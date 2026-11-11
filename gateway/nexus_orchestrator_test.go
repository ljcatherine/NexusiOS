package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const orchestratorTestToken = "orchestrator-only-upstream-bearer-987654321"

func orchestratorTestGateway(t *testing.T, service *httptest.Server, scopes map[string]bool) *Gateway {
	t.Helper()
	g := testGateway(service, map[string]map[string]bool{"owner-subject": scopes})
	g.cfg.WorkspaceGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	g.cfg.ModelStatePath = filepath.Join(t.TempDir(), "model-state", "pending-switch.json")
	g.cfg.RequestsPerMinute = 100
	g.orchestrator = newNexusOrchestratorProxy(orchestratorTestToken)
	g.orchestrator.endpoint = service.URL // in-memory loopback fixture, never configured from user input
	return g
}

func TestNativeModelMetadataSurvivesScopedGatewayProxy(t *testing.T) {
	body := `{"models":[{"id":"0123456789abcdef","label":"misleading-Q4","drive":"internal","fits":true,"current":false,"file_size_bytes":8589934592,"architecture":"qwen35","quantization_type":18},{"id":"fedcba9876543210","label":"unknown","drive":"usb","fits":false,"current":false,"file_size_bytes":null,"architecture":null,"quantization_type":null}]}`
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/nexus/models" || r.Header.Get("Authorization") != "Bearer "+orchestratorTestToken {
			t.Error("model metadata did not use the scoped private route and service credential")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Cf-Access-Jwt-Assertion") != "" {
			t.Error("public caller credentials leaked to model metadata service")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusModelRead: true})
	response := requestOrchestrator(g, "GET", "/v1/nexus/models", "")
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != body {
		t.Fatalf("typed model metadata/unknowns changed in proxy: %d %s", response.Code, response.Body.String())
	}
}

func TestPendingModelSwitchSurvivesGatewayRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-state", "pending.json")
	if err := writePendingModelSwitch(path, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	pending, err := readPendingModelSwitch(path)
	if err != nil || pending != "0123456789abcdef" {
		t.Fatalf("journal did not survive restart: target=%q err=%v", pending, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("journal must have owner-only permissions, mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := os.Chmod(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writePendingModelSwitch(path, "fedcba9876543210"); err == nil {
		t.Fatal("journal accepted a group-accessible state directory")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer service.Close()
	previous := testGateway(service, map[string]map[string]bool{"owner-subject": {permissionChat: true}})
	previous.cfg.ModelStatePath = path
	previous.modelPending, err = readPendingModelSwitch(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewGateway(previous.cfg, previous.verifier)
	response := httptest.NewRecorder()
	allowed := restarted.beginInference(response)
	if allowed || response.Code != http.StatusServiceUnavailable {
		t.Fatalf("gateway restart must keep inference blocked: allowed=%v status=%d", allowed, response.Code)
	}
}

func requestOrchestrator(g *Gateway, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer valid-token")
	r.Header.Set("Cookie", "CF_Authorization=secret-cookie")
	r.Header.Set("Cf-Access-Jwt-Assertion", "never-forwarded")
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	r.Header.Set("X-Nexus-Principal", strings.Repeat("b", 64))
	if method == "POST" && strings.Contains(path, "agent-runs") {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	return w
}

func TestNexusOrchestratorRequiresDistinctScopeAndToken(t *testing.T) {
	calls := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"workspaces":[],"unavailable_hosts":[]}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionChat: true, permissionModels: true})
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 403 {
		t.Fatalf("normal AI grants must not authorize orchestration, got %d", got)
	}
	g.cfg.SubjectPermissions["owner-subject"][permissionNexusWorkspaceRead] = true
	r := httptest.NewRequest("GET", "/v1/nexus/workspaces", nil)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	if w.Code != 401 || calls != 0 {
		t.Fatalf("unauthenticated request reached upstream: %d (%d calls)", w.Code, calls)
	}
	g.orchestrator = nil
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 503 {
		t.Fatalf("missing dedicated orchestrator token must fail with 503: %d", got)
	}
	for _, value := range []string{"", strings.Repeat("a", 31), strings.Repeat("x", 257), strings.Repeat("a", 32) + "\n", "Bearer header pasted here"} {
		if validOrchestratorToken(value) {
			t.Fatalf("invalid orchestrator token format accepted")
		}
	}
	if !validOrchestratorToken(orchestratorTestToken) {
		t.Fatal("dedicated token fixture unexpectedly rejected")
	}
	policy, err := parseSubjectPermissions(`{"owner-subject":["nexus.orchestrate"]}`)
	if err != nil || !policy["owner-subject"][permissionOrchestrate] {
		t.Fatalf("new policy grant rejected: %v", err)
	}
}

func TestNexusOrchestratorSeparatesCapabilitiesBeforeUpstream(t *testing.T) {
	calls := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/v1/nexus/agent-runs/active" {
			_, _ = io.WriteString(w, `{"active":0}`)
			return
		}
		if r.Method == http.MethodGet && orchestratorRunPath.MatchString(r.URL.Path) {
			if strings.HasSuffix(r.URL.Path, strings.Repeat("2", 32)) {
				_, _ = io.WriteString(w, `{"result":{"response":"private answer"}}`)
			} else {
				workspace := strings.HasSuffix(r.URL.Path, strings.Repeat("1", 32))
				_, _ = io.WriteString(w, `{"workspace_required":`+strconv.FormatBool(workspace)+`,"workspace_identity":{"host":"debian","id":"code"},"result":{"response":"private answer"}}`)
			}
			return
		}
		if r.Method == http.MethodPost && (orchestratorCancelRunPath.MatchString(r.URL.Path) || orchestratorCancelSubagentPath.MatchString(r.URL.Path)) {
			_, _ = io.WriteString(w, `{"id":"0123456789abcdef0123456789abcdef","status":"completed","result":{"response":"private answer"}}`)
			return
		}
		if r.URL.Path == "/v1/nexus/workspaces" {
			io.WriteString(w, `{"workspaces":[]}`)
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer service.Close()

	cases := []struct {
		name, method, path, body string
		scopes                   map[string]bool
		status                   int
		reachesUpstream          bool
	}{
		{"orchestration cannot read models", "GET", "/v1/nexus/models", "", map[string]bool{permissionOrchestrate: true}, 403, false},
		{"model read", "GET", "/v1/nexus/models", "", map[string]bool{permissionNexusModelRead: true}, 200, true},
		{"model read cannot switch", "POST", "/v1/nexus/models/unload", "", map[string]bool{permissionNexusModelRead: true}, 403, false},
		{"model control", "POST", "/v1/nexus/models/unload", "", map[string]bool{permissionNexusModelControl: true}, 202, true},
		{"orchestration cannot browse", "GET", "/v1/nexus/workspaces", "", map[string]bool{permissionOrchestrate: true}, 403, false},
		{"orchestration cannot search workspace", "POST", "/v1/nexus/workspaces/debian/code/tasks", `{"operation":"inventory"}`, map[string]bool{permissionOrchestrate: true}, 403, false},
		{"workspace read", "GET", "/v1/nexus/workspaces", "", map[string]bool{permissionNexusWorkspaceRead: true}, 200, true},
		{"task needs inference", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi"}`, map[string]bool{permissionOrchestrate: true}, 403, false},
		{"general task", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi"}`, map[string]bool{permissionOrchestrate: true, permissionChat: true}, 202, true},
		{"null workspace", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi","workspace":null}`, map[string]bool{permissionOrchestrate: true, permissionChat: true}, 202, true},
		{"workspace task needs read", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi","workspace":{"host":"debian"}}`, map[string]bool{permissionOrchestrate: true, permissionChat: true}, 403, false},
		{"escaped workspace key needs read", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi","worksp\u0061ce":{"host":"debian"}}`, map[string]bool{permissionOrchestrate: true, permissionChat: true}, 403, false},
		{"duplicate workspace rejected", "POST", "/v1/nexus/agent-runs", `{"workspace":{"host":"debian"},"worksp\u0061ce":null}`, map[string]bool{permissionOrchestrate: true, permissionChat: true}, 400, false},
		{"workspace task with read", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi","workspace":{"host":"debian","workspace_id":"code"}}`, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true}, 202, true},
		{"chat cannot create task", "POST", "/v1/nexus/agent-runs", `{"prompt":"hi"}`, map[string]bool{permissionChat: true}, 403, false},
		{"result needs inference access", "GET", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", "", map[string]bool{permissionOrchestrate: true}, 403, false},
		{"general result with inference access", "GET", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", "", map[string]bool{permissionOrchestrate: true, permissionChat: true}, 200, true},
		{"workspace result needs workspace access", "GET", "/v1/nexus/agent-runs/11111111111111111111111111111111", "", map[string]bool{permissionOrchestrate: true, permissionChat: true}, 403, true},
		{"workspace result with access", "GET", "/v1/nexus/agent-runs/11111111111111111111111111111111", "", map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true}, 200, true},
		{"missing workspace metadata fails closed", "GET", "/v1/nexus/agent-runs/22222222222222222222222222222222", "", map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true}, 502, true},
		{"cancel does not need inference access", "POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel", "", map[string]bool{permissionOrchestrate: true}, 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			g := orchestratorTestGateway(t, service, tc.scopes)
			response := requestOrchestrator(g, tc.method, tc.path, tc.body)
			if response.Code != tc.status || (calls > 0) != tc.reachesUpstream {
				t.Fatalf("status=%d calls=%d want status=%d upstream=%t", response.Code, calls, tc.status, tc.reachesUpstream)
			}
			if (tc.status != 200 || strings.HasSuffix(tc.path, "/cancel")) && strings.Contains(response.Body.String(), "private answer") {
				t.Fatal("restricted result appeared in response")
			}
		})
	}
	policy, err := parseSubjectPermissions(`{"owner-subject":["nexus.orchestrate","nexus.workspace.read","nexus.model.read","nexus.model.control","ai.chat"]}`)
	if err != nil || !policy["owner-subject"][permissionNexusModelControl] || !policy["owner-subject"][permissionNexusWorkspaceRead] {
		t.Fatalf("separated scope configuration rejected: %v", err)
	}
}

func TestWorkspaceGrantsRestrictDiscoveryRequestsAndResults(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/nexus/agent-runs/active":
			io.WriteString(w, `{"active":0}`)
		case r.URL.Path == "/v1/nexus/workspaces":
			io.WriteString(w, `{"workspaces":[{"host":"debian","id":"code","name":"Allowed"},{"host":"nixos","id":"private","name":"Private"}],"unavailable_hosts":[]}`)
		case r.URL.Path == "/v1/nexus/workspaces/nixos":
			io.WriteString(w, `{"host":"nixos","workspaces":[{"id":"private","name":"Private"}]}`)
		case r.Method == "GET" && orchestratorRunPath.MatchString(r.URL.Path):
			if strings.HasSuffix(r.URL.Path, strings.Repeat("1", 32)) {
				io.WriteString(w, `{"workspace_required":true,"workspace_identity":{"host":"nixos","id":"private"},"result":{"response":"secret"}}`)
			} else if strings.HasSuffix(r.URL.Path, strings.Repeat("2", 32)) {
				io.WriteString(w, `{"workspace_required":true,"result":{"response":"secret"}}`)
			} else {
				io.WriteString(w, `{"workspace_required":true,"workspace_identity":{"host":"debian","id":"code"},"result":{"response":"allowed"}}`)
			}
		default:
			if r.Method == "POST" {
				w.WriteHeader(http.StatusAccepted)
			}
			io.WriteString(w, `{}`)
		}
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true})
	grants, err := parseWorkspaceGrants(`{"owner-subject":["debian:code"]}`)
	if err != nil {
		t.Fatal(err)
	}
	g.cfg.WorkspaceGrants = grants
	for _, tc := range []struct {
		method, path, body string
		status             int
		absent             string
	}{
		{"GET", "/v1/nexus/workspaces", "", 200, "Private"},
		{"GET", "/v1/nexus/workspaces/nixos", "", 200, "Private"},
		{"GET", "/v1/nexus/workspaces/nixos/private/files", "", 403, ""},
		{"GET", "/v1/nexus/workspaces/debian/code/files", "", 200, ""},
		{"POST", "/v1/nexus/agent-runs", `{"prompt":"x","workspace":{"host":"nixos","workspace_id":"private","path":""}}`, 403, ""},
		{"POST", "/v1/nexus/agent-runs", `{"prompt":"x","workspace":{"host":"debian","host":"nixos","workspace_id":"code"}}`, 403, ""},
		{"POST", "/v1/nexus/agent-runs", `{"prompt":"x","workspace":{"host":"debian","workspace_id":"code","path":""}}`, 202, ""},
		{"GET", "/v1/nexus/agent-runs/11111111111111111111111111111111", "", 403, "secret"},
		{"GET", "/v1/nexus/agent-runs/22222222222222222222222222222222", "", 403, "secret"},
		{"GET", "/v1/nexus/agent-runs/00000000000000000000000000000000", "", 200, ""},
	} {
		response := requestOrchestrator(g, tc.method, tc.path, tc.body)
		if response.Code != tc.status || (tc.absent != "" && strings.Contains(response.Body.String(), tc.absent)) {
			t.Fatalf("%s %s: status %d body %s", tc.method, tc.path, response.Code, response.Body.String())
		}
	}
	for _, raw := range []string{`{"a":["nixos:../bad"]}`, `{"a":["debian:code","debian:code"]}`, `{"a":null}`, `{"a":[],"a":[]}`} {
		if _, err := parseWorkspaceGrants(raw); err == nil {
			t.Fatalf("accepted invalid grant policy %s", raw)
		}
	}
	g.cfg.WorkspaceGrants = nil
	if response := requestOrchestrator(g, "GET", "/v1/nexus/workspaces/debian/code/files", ""); response.Code != 403 {
		t.Fatalf("missing policy must deny workspace access: %d", response.Code)
	}
	if response := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", ""); response.Code != 200 || strings.Contains(response.Body.String(), "Allowed") {
		t.Fatalf("missing policy must hide workspace discovery: %d %s", response.Code, response.Body.String())
	}
}

func TestInternalRunAuthorizationChecksCurrentPolicy(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true})
	g.cfg.OrchestratorBearerToken = orchestratorTestToken
	digest := sha256.Sum256([]byte("owner-subject"))
	body := `{"principal":"` + hex.EncodeToString(digest[:]) + `","workspace":{"host":"debian","id":"code"}}`
	call := func(token, address, payload string) int {
		r := httptest.NewRequest("POST", "/internal/nexus/authorize-run", strings.NewReader(payload))
		r.RemoteAddr = address
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if code := call(orchestratorTestToken, "127.0.0.1:1234", body); code != 204 {
		t.Fatalf("authorized check: %d", code)
	}
	if code := call("incorrect", "127.0.0.1:1234", body); code != 403 {
		t.Fatalf("bad token: %d", code)
	}
	if code := call(orchestratorTestToken, "192.0.2.1:1234", body); code != 403 {
		t.Fatalf("non-loopback: %d", code)
	}
	if code := call(orchestratorTestToken, "127.0.0.1:1234", `{"principal":"`+hex.EncodeToString(digest[:])+`","workspace":null,"workspace":null}`); code != 400 {
		t.Fatalf("duplicate workspace: %d", code)
	}
	delete(g.cfg.WorkspaceGrants["owner-subject"], "debian:code")
	if code := call(orchestratorTestToken, "127.0.0.1:1234", body); code != 403 {
		t.Fatalf("revoked root: %d", code)
	}
	g.cfg.SubjectPermissions["owner-subject"][permissionChat] = false
	if code := call(orchestratorTestToken, "127.0.0.1:1234", `{"principal":"`+hex.EncodeToString(digest[:])+`","workspace":null}`); code != 403 {
		t.Fatalf("revoked inference: %d", code)
	}
}

func TestNexusOrchestratorPreservesRunRecoveryStatusesOnly(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nexus/agent-runs/active" {
			_, _ = io.WriteString(w, `{"active":0}`)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/nexus/agent-runs" {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true})
	if got := requestOrchestrator(g, "GET", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", "").Code; got != 404 {
		t.Fatalf("missing saved run should remain 404: %d", got)
	}
	if got := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", `{"prompt":"hi"}`).Code; got != 410 {
		t.Fatalf("expired submission should remain 410: %d", got)
	}
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 502 {
		t.Fatalf("unrelated upstream 404 should remain masked: %d", got)
	}
}

func TestNexusOrchestratorTypedApprovalCheckpointMetadata(t *testing.T) {
	var upstream atomic.Value
	original := `{"id":"0123456789abcdef0123456789abcdef","status":"waiting_for_approval","workspace_required":true,"workspace_identity":{"host":"debian","id":"code"},"approval_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approval_kind":"command"}`
	upstream.Store(original)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, upstream.Load().(string))
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{
		permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true,
	})
	path := "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, replacement, old string
		status                 int
	}{
		{"owned command checkpoint", "", "", 200},
		{"owned patch checkpoint", `"approval_kind":"patch"`, `"approval_kind":"command"`, 200},
		{"unknown kind denied", `"approval_kind":"shell"`, `"approval_kind":"command"`, 502},
		{"wrong review ID denied", `"approval_id":"abc"`, `"approval_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 502},
		{"nonwaiting kind denied", `"status":"completed"`, `"status":"waiting_for_approval"`, 502},
		{"nonworkspace kind denied", `"workspace_required":false`, `"workspace_required":true`, 502},
		{"missing kind backward compatible", `"approval_kind":null`, `"approval_kind":"command"`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.old != "" {
				upstream.Store(strings.Replace(original, tc.old, tc.replacement, 1))
			} else {
				upstream.Store(original)
			}
			result := requestOrchestrator(g, "GET", path, "")
			if result.Code != tc.status {
				t.Fatalf("typed review metadata status=%d want=%d; response=%s", result.Code, tc.status, result.Body.String())
			}
		})
	}
}

func TestNexusOrchestratorExactRoutesRewriteAndNoCredentialLeak(t *testing.T) {
	seen := map[string]string{}
	ownerDigest := sha256.Sum256([]byte("owner-subject"))
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path] = r.Header.Get("Authorization")
		if strings.HasPrefix(r.URL.Path, "/v1/nexus/agent-runs") && r.URL.Path != "/v1/nexus/agent-runs/active" &&
			r.Header.Get("X-Nexus-Principal") != hex.EncodeToString(ownerDigest[:]) {
			t.Error("private upstream did not receive the verified principal digest")
		}
		for _, key := range []string{"Cookie", "Cf-Access-Jwt-Assertion", "X-Forwarded-Host", "Origin"} {
			if got := r.Header.Get(key); got != "" {
				t.Errorf("private upstream received caller-controlled %s header", key)
			}
		}
		if r.URL.RawQuery != "" || strings.Contains(r.Host, "attacker") {
			t.Error("untrusted destination/query reached upstream")
		}
		w.Header().Set("Set-Cookie", "secret=bad")
		w.Header().Set("Location", "https://evil.example")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "/models/") || r.URL.Path == "/v1/nexus/agent-runs") {
			w.WriteHeader(http.StatusAccepted)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		if r.URL.Path == "/v1/nexus/agent-runs/active" {
			_, _ = io.WriteString(w, `{"active":0}`)
		} else if r.URL.Path == "/v1/nexus/agent-runs" && r.Method == http.MethodPost {
			_, _ = io.WriteString(w, `{"id":"0123456789abcdef0123456789abcdef","status":"queued"}`)
		} else if r.Method == http.MethodGet && orchestratorRunPath.MatchString(r.URL.Path) {
			_, _ = io.WriteString(w, `{"state":"ready","workspace_required":false}`)
		} else if r.URL.Path == "/v1/nexus/status" {
			_, _ = io.WriteString(w, `{"state":"no_model","ready":false}`)
		} else if r.URL.Path == "/v1/nexus/workspaces" {
			_, _ = io.WriteString(w, `{"workspaces":[]}`)
		} else {
			_, _ = io.WriteString(w, `{"state":"ready"}`)
		}
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true, permissionNexusModelRead: true, permissionNexusModelControl: true})
	for _, tc := range []struct {
		method, path, upstreamPath, body string
		status                           int
	}{
		{"GET", "/v1/nexus/workspaces", "/v1/nexus/workspaces", "", 200},
		{"GET", "/v1/nexus/agent-runs", "/v1/nexus/agent-runs", "", 200},
		{"GET", "/v1/nexus/agent-runs/active", "/v1/nexus/agent-runs/active", "", 200},
		{"POST", "/v1/nexus/agent-runs", "/v1/nexus/agent-runs", `{"prompt":"hello"}`, 202},
		{"GET", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef", "", 200},
		{"POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/cancel", "", 200},
		{"POST", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/subagents/abcdef0123456789abcdef0123456789/cancel", "/v1/nexus/agent-runs/0123456789abcdef0123456789abcdef/subagents/abcdef0123456789abcdef0123456789/cancel", "", 200},
		{"GET", "/v1/nexus/models", "/v1/nexus/models", "", 200},
		{"GET", "/v1/nexus/status", "/v1/nexus/status", "", 200},
		{"GET", "/v1/nexus/models/status", "/v1/nexus/status", "", 200},
		{"POST", "/v1/nexus/models/unload", "/v1/nexus/models/unload", "", 202},
		{"POST", "/v1/nexus/models/0123456789abcdef/load", "/v1/nexus/models/0123456789abcdef/load", "", 202},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if tc.path == "/v1/nexus/models/0123456789abcdef/load" {
				if got := requestOrchestrator(g, "GET", "/v1/nexus/status", "").Code; got != 200 {
					t.Fatalf("unload status: %d", got)
				}
			}
			response := requestOrchestrator(g, tc.method, tc.path, tc.body)
			if response.Code != tc.status {
				t.Fatalf("got HTTP %d, want %d; body=%s", response.Code, tc.status, response.Body.String())
			}
			if got := seen[tc.method+" "+tc.upstreamPath]; got != "Bearer "+orchestratorTestToken {
				t.Fatalf("upstream used wrong bearer token")
			}
			if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("untrusted upstream headers escaped proxy")
			}
		})
	}
	before := len(seen)
	for _, path := range []string{"/v1/nexus/models/0123456789abcdeZ/load",
		"/v1/nexus/models/0123456789abcdef/LOAD", "/v1/nexus/models/0123456789abcdef/load?x=1",
		"/v1/nexus/models/unload/extra", "/v1/nexus/workspaces?token=bad"} {
		if code := requestOrchestrator(g, "POST", path, "").Code; code == 200 || code == 202 {
			t.Errorf("unexpected valid request %q: %d", path, code)
		}
	}
	if len(seen) != before {
		t.Fatal("invalid route reached orchestrator")
	}
}

func TestNexusWorkspaceRoutesPreserveOnlySafeRelativePath(t *testing.T) {
	var seen []string
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer "+orchestratorTestToken {
			t.Error("workspace upstream did not receive dedicated bridge token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"host":"debian","workspace_id":"code","path":"src/a b.swift","text":"ok","size_bytes":2}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusWorkspaceRead: true})
	response := requestOrchestrator(g, "GET", "/v1/nexus/workspaces/debian/code/context?path=src%2Fa%20b.swift", "")
	if response.Code != 200 || len(seen) != 1 || seen[0] != "/v1/nexus/workspaces/debian/code/context?path=src%2Fa+b.swift" {
		t.Fatalf("workspace path not safely forwarded: status=%d upstream=%v body=%s", response.Code, seen, response.Body.String())
	}
	for _, path := range []string{
		"/v1/nexus/workspaces/debian/code/files?path=../secret",
		"/v1/nexus/workspaces/debian/code/files?path=src%2F..%2Fsecret",
		"/v1/nexus/workspaces/debian/code/files?path=src%2F%2Fsecret",
		"/v1/nexus/workspaces/debian/code/files?path=src&path=other",
		"/v1/nexus/workspaces/debian/code/files?other=1",
	} {
		if code := requestOrchestrator(g, "GET", path, "").Code; code < 400 {
			t.Errorf("unsafe query accepted (%s): %d", path, code)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("invalid workspace query reached upstream: %v", seen)
	}
}

func TestNexusOrchestratorBoundsRedirectAndDisabledNativeStatus(t *testing.T) {
	called := 0
	status := 503
	responseBody := `{"error":"native controller not configured"}`
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if status == 302 {
			w.Header().Set("Location", "https://evil.test/credential")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true, permissionNexusModelRead: true})
	for _, path := range []string{"/v1/nexus/models", "/v1/nexus/status", "/v1/nexus/models/status"} {
		if response := requestOrchestrator(g, "GET", path, ""); response.Code != 503 ||
			strings.Contains(response.Body.String(), "native controller") {
			t.Fatalf("disabled native control must show generic 503, got %d %q", response.Code, response.Body.String())
		}
	}
	status = 302
	if response := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", ""); response.Code != 502 {
		t.Fatalf("upstream redirects must fail closed: %d", response.Code)
	}
	before := called
	for _, body := range []string{strings.Repeat("a", maxOrchestratorRequestBytes+1),
		`{"prompt":"x"} extra`, "[]"} {
		if response := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", body); response.Code < 400 {
			t.Fatalf("invalid/oversized request accepted: %d", response.Code)
		}
	}
	if called != before {
		t.Fatal("invalid agent run reached upstream")
	}
	status = 200
	large := strings.Repeat("a", maxOrchestratorResponseBytes)
	responseBody = `{"result":"` + large + `"}`
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 502 {
		t.Fatalf("oversized response accepted: %d", got)
	}
}

func TestNexusOrchestratorAuditNeverLogsTokenOrRequestedModelID(t *testing.T) {
	var output bytes.Buffer
	prior := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(prior) })
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusModelControl: true})
	response := requestOrchestrator(g, "POST", "/v1/nexus/models/0123456789abcdef/load", "")
	logs := output.String()
	if response.Code != 503 || !strings.Contains(logs, "permission=nexus.model.control") ||
		strings.Contains(logs, orchestratorTestToken) || strings.Contains(logs, "valid-token") ||
		strings.Contains(logs, "0123456789abcdef") || !strings.Contains(logs, "/v1/nexus/models/{id}/load") {
		t.Fatalf("audit redaction/disabled control failed: code=%d logs=%q", response.Code, logs)
	}
}

func TestNexusOrchestratorSubjectRateLimitAndChunkedBodyCap(t *testing.T) {
	calls := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"workspaces":[]}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true})
	g.cfg.RequestsPerMinute = 1
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 200 {
		t.Fatalf("first request failed: %d", got)
	}
	if got := requestOrchestrator(g, "GET", "/v1/nexus/workspaces", "").Code; got != 429 || calls != 1 {
		t.Fatalf("rate limit not applied to orchestrator scope: status=%d upstreamCalls=%d", got, calls)
	}
	g.cfg.RequestsPerMinute = 10
	g.mu.Lock()
	g.counters = make(map[string]requestCounter)
	g.mu.Unlock()
	req := httptest.NewRequest("POST", "/v1/nexus/agent-runs", strings.NewReader(
		strings.Repeat("x", maxOrchestratorRequestBytes+1)))
	req.ContentLength = -1 // simulated chunked transfer with no declared size
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	g.Handler().ServeHTTP(resp, req)
	if resp.Code != 413 || calls != 1 {
		t.Fatalf("chunked oversized request must not reach upstream: status=%d calls=%d", resp.Code, calls)
	}
}

func TestGatewayBlocksInferenceUntilRequestedModelIsReady(t *testing.T) {
	state := `{"state":"ready","ready":true,"model_id":"fedcba9876543210"}`
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nexus/agent-runs/active" {
			_, _ = io.WriteString(w, `{"active":0}`)
			return
		}
		if r.URL.Path == "/v1/nexus/status" {
			_, _ = io.WriteString(w, state)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"switching"}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusModelRead: true, permissionNexusModelControl: true})
	g.aiLifecycle.Lock() // simulate an active streamed chat or agent run
	if got := requestOrchestrator(g, "POST", "/v1/nexus/models/0123456789abcdef/load", "").Code; got != 503 {
		t.Fatalf("switch during inference: %d", got)
	}
	g.aiLifecycle.Unlock()
	if got := requestOrchestrator(g, "POST", "/v1/nexus/models/0123456789abcdef/load", "").Code; got != 202 {
		t.Fatalf("switch request: %d", got)
	}
	if got := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", `{"prompt":"hello"}`).Code; got != 503 {
		t.Fatalf("agent during switch: %d", got)
	}
	requestOrchestrator(g, "GET", "/v1/nexus/status", "")
	if got := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", `{"prompt":"hello"}`).Code; got != 503 {
		t.Fatalf("old ready model cleared pending switch: %d", got)
	}
	state = `{"state":"ready","ready":true,"model_id":"0123456789abcdef"}`
	requestOrchestrator(g, "GET", "/v1/nexus/status", "")
	if got := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", `{"prompt":"hello"}`).Code; got != 202 {
		t.Fatalf("confirmed model did not restore inference: %d", got)
	}
}

func TestGatewayFailsClosedWhileOrchestratorUsesInference(t *testing.T) {
	active := 1
	calls := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/nexus/agent-runs/active" {
			t.Errorf("unexpected orchestrator route: %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"active":`+strconv.Itoa(active)+`}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionChat: true})
	w := httptest.NewRecorder()
	if g.beginInference(w) || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("active task must block another inference: status=%d", w.Code)
	}
	active = 0
	w = httptest.NewRecorder()
	if !g.beginInference(w) {
		t.Fatalf("idle orchestrator should allow inference: status=%d", w.Code)
	}
	g.aiLifecycle.Unlock()
	active = -1
	w = httptest.NewRecorder()
	if g.beginInference(w) || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid active count must fail closed: status=%d", w.Code)
	}
	if calls != 3 {
		t.Fatalf("expected three state checks, got %d", calls)
	}
}

func TestModelRefreshReconcilesSwitchWithoutManagementPolling(t *testing.T) {
	const target = "0123456789abcdef"
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/nexus/status":
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+orchestratorTestToken {
				t.Error("readiness must use a private authenticated GET")
			}
			io.WriteString(w, `{"state":"ready","ready":true,"model_id":"0123456789abcdef"}`)
		case "/v1/models":
			io.WriteString(w, `{"data":[{"id":"new-model"}]}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionModels: true})
	g.cfg.AllowUpstreamModels = true
	g.modelPending = target
	if err := writePendingModelSwitch(g.cfg.ModelStatePath, target); err != nil {
		t.Fatal(err)
	}
	response := requestOrchestrator(g, "GET", "/v1/models", "")
	if response.Code != 200 {
		t.Fatalf("model refresh failed: %d", response.Code)
	}
	if g.modelPending != "" {
		t.Fatal("model refresh left a confirmed switch stuck")
	}
	if _, err := os.Stat(g.cfg.ModelStatePath); !os.IsNotExist(err) {
		t.Fatal("confirmed journal not cleared")
	}
}

func TestInferenceReconcilesOnlyTrustedExactReadiness(t *testing.T) {
	for _, tc := range []struct {
		name, target, body string
		code               int
		allowed, corrupt   bool
	}{
		{"ready", "0123456789abcdef", `{"state":"ready","ready":true,"model_id":"0123456789abcdef"}`, 200, true, false},
		{"wrong-model", "0123456789abcdef", `{"state":"ready","ready":true,"model_id":"fedcba9876543210"}`, 200, false, false},
		{"loading", "0123456789abcdef", `{"state":"loading","ready":false,"model_id":"0123456789abcdef"}`, 200, false, false},
		{"unavailable", "0123456789abcdef", `{}`, 503, false, false},
		{"redirect", "0123456789abcdef", `{}`, 302, false, false},
		{"duplicate", "0123456789abcdef", `{"state":"ready","ready":false,"ready":true,"model_id":"0123456789abcdef"}`, 200, false, false},
		{"oversized", "0123456789abcdef", strings.Repeat("x", 16*1024+1), 200, false, false},
		{"corrupt-journal", "0123456789abcdef", `{"state":"ready","ready":true,"model_id":"0123456789abcdef"}`, 200, false, true},
		{"unloaded", "unload", `{"state":"no_model","ready":false}`, 200, true, false},
		{"missing-readiness", "unload", `{"state":"no_model"}`, 200, false, false},
		{"null-readiness", "unload", `{"state":"no_model","ready":null}`, 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("reconciliation must never replay an action")
				}
				if r.URL.Path == "/v1/nexus/agent-runs/active" {
					io.WriteString(w, `{"active":0}`)
					return
				}
				if r.URL.Path != "/v1/nexus/status" || r.Header.Get("Authorization") != "Bearer "+orchestratorTestToken {
					t.Error("invalid readiness probe")
				}
				reads++
				w.WriteHeader(tc.code)
				io.WriteString(w, tc.body)
			}))
			defer service.Close()
			g := orchestratorTestGateway(t, service, map[string]bool{permissionChat: true})
			g.modelPending = tc.target
			if err := writePendingModelSwitch(g.cfg.ModelStatePath, tc.target); err != nil {
				t.Fatal(err)
			}
			if tc.corrupt {
				g.modelStateErr = io.ErrUnexpectedEOF
			}
			w := httptest.NewRecorder()
			allowed := g.beginInference(w)
			if allowed {
				g.aiLifecycle.Unlock()
			}
			if allowed != tc.allowed {
				t.Fatalf("inference allowed=%v, want=%v", allowed, tc.allowed)
			}
			if !allowed {
				if g.modelPending != tc.target {
					t.Fatal("unconfirmed pending state was lost")
				}
				if _, err := os.Stat(g.cfg.ModelStatePath); err != nil {
					t.Fatal("unconfirmed journal was removed")
				}
			}
			if tc.corrupt && reads != 0 {
				t.Fatal("corrupt state must not be automatically recovered")
			}
		})
	}
}

func TestModelRefreshDuringSwitchDoesNotQueryUnreadyInference(t *testing.T) {
	statusCode := 503
	modelCalls := 0
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nexus/status" {
			w.WriteHeader(statusCode)
			io.WriteString(w, `{"state":"ready","ready":true,"model_id":"0123456789abcdef"}`)
			return
		}
		if r.URL.Path == "/v1/models" {
			modelCalls++
			io.WriteString(w, `{"data":[{"id":"new-model"}]}`)
			return
		}
		t.Errorf("unexpected route %s", r.URL.Path)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionModels: true})
	g.cfg.AllowUpstreamModels = true
	g.modelPending = "0123456789abcdef"
	if err := writePendingModelSwitch(g.cfg.ModelStatePath, g.modelPending); err != nil {
		t.Fatal(err)
	}
	response := requestOrchestrator(g, "GET", "/v1/models", "")
	if response.Code != 200 || strings.TrimSpace(response.Body.String()) != `{"data":[]}` || modelCalls != 0 {
		t.Fatalf("startup refresh must report no ready models without querying inference: %d %s calls=%d", response.Code, response.Body, modelCalls)
	}
	if g.modelPending == "" {
		t.Fatal("startup lost switch lease")
	}
	statusCode = 200
	response = requestOrchestrator(g, "GET", "/v1/models", "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), "new-model") || modelCalls != 1 || g.modelPending != "" {
		t.Fatalf("ready refresh failed: %d %s calls=%d pending=%q", response.Code, response.Body, modelCalls, g.modelPending)
	}
}
