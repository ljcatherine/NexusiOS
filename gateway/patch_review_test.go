package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const patchReviewTestToken = "review-only-private-credential-0123456789"
const patchScope = "/v1/nexus/workspaces/debian/code/patches"

func TestPatchReviewSeparatesPermissionsCredentialsAndPrincipal(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		review := r.Method == "GET" || strings.HasSuffix(r.URL.Path, "/decision")
		expected := orchestratorTestToken
		if review {
			expected = patchReviewTestToken
		}
		if r.Header.Get("Authorization") != "Bearer "+expected {
			t.Error("incorrect private credential")
		}
		principal := sha256.Sum256([]byte("owner-subject"))
		if r.Header.Get("X-Nexus-Principal") != hex.EncodeToString(principal[:]) || r.Header.Get("Cookie") != "" {
			t.Error("verified principal or cookie isolation failed")
		}
		if r.Method == "POST" && r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing JSON content type")
		}
		if r.Method == "GET" && r.URL.Path == patchScope {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":false,"patches":[]}`)
		} else {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":false,"patch":{"proposal":{"host":"debian","workspace_id":"code"}}}`)
		}
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusWorkspaceRead: true, permissionNexusPatchPropose: true})
	g.orchestrator.reviewToken = patchReviewTestToken
	if response := requestPatchReview(g, "POST", patchScope, `{"path":"main.py","replacement":"x","submission_id":"`+strings.Repeat("a", 32)+`"}`); response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	before := calls.Load()
	for _, method := range []string{"GET", "POST"} {
		path, body := patchScope, ""
		if method == "POST" {
			path += "/" + strings.Repeat("a", 32) + "/decision"
			body = `{"digest":"` + strings.Repeat("b", 64) + `","decision":"approve"}`
		}
		if response := requestPatchReview(g, method, path, body); response.Code != 403 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	if calls.Load() != before {
		t.Fatal("proposer reached private review API")
	}
	delete(g.cfg.SubjectPermissions["owner-subject"], permissionNexusPatchPropose)
	g.cfg.SubjectPermissions["owner-subject"][permissionNexusApprovalReview] = true
	if response := requestPatchReview(g, "GET", patchScope, ""); response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	if response := requestPatchReview(g, "POST", patchScope, `{}`); response.Code != 403 {
		t.Fatal("reviewer could propose", response.Code)
	}
	r := httptest.NewRequest("POST", patchScope+"/"+strings.Repeat("a", 32)+"/decision", strings.NewReader(`{"digest":"`+strings.Repeat("b", 64)+`","decision":"reject"}`))
	r.Header.Set("Authorization", "Bearer valid-token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Nexus-Principal", strings.Repeat("c", 64))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before = calls.Load()
	g.cfg.WorkspaceGrants = nil
	if response := requestPatchReview(g, "GET", patchScope, ""); response.Code != 403 {
		t.Fatal("root grant bypass", response.Code)
	}
	if calls.Load() != before {
		t.Fatal("denied root reached upstream")
	}
}

func TestPatchReviewFailsClosedOnConfigurationScopeAndBounds(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"host":"nixos","workspace_id":"code","execution_enabled":false,"patches":[]}`)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusWorkspaceRead: true, permissionNexusApprovalReview: true, permissionNexusPatchPropose: true})
	for _, token := range []string{"", orchestratorTestToken} {
		g.orchestrator.reviewToken = token
		if response := requestPatchReview(g, "GET", patchScope, ""); response.Code != 503 {
			t.Fatal("unsafe review token accepted", response.Code)
		}
	}
	g.orchestrator.reviewToken = patchReviewTestToken
	if response := requestPatchReview(g, "GET", patchScope, ""); response.Code != 502 {
		t.Fatal("wrong response workspace accepted", response.Code)
	}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"digest":"x","digest":"y"}`, 400},
		{`{"replacement":"` + strings.Repeat("x", 512<<10) + `"}`, 413},
	} {
		if response := requestPatchReview(g, "POST", patchScope, tc.body); response.Code != tc.status {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	if _, err := parseSubjectPermissions(`{"owner-subject":["nexus.workspace.propose","nexus.approvals.review"]}`); err != nil {
		t.Fatal(err)
	}
}

func requestPatchReview(g *Gateway, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer valid-token")
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, r)
	return w
}

func TestManualPatchActionsRequireReviewAndExplicitWriteRoot(t *testing.T) {
	var calls atomic.Int32
	var upstreamStatus atomic.Int32
	executionEnvelope := true
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+patchReviewTestToken {
			t.Error("manual action did not use the separate human-review credential")
		}
		if status := upstreamStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			io.WriteString(w, `{"error":"private policy details"}`)
			return
		}
		if executionEnvelope {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":true,"patch":{"proposal":{"host":"debian","workspace_id":"code"}}}`)
		} else {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":false,"patch":{"proposal":{"host":"debian","workspace_id":"code"}}}`)
		}
	}))
	defer service.Close()
	permissions := map[string]bool{permissionNexusWorkspaceRead: true, permissionNexusPatchPropose: true}
	g := orchestratorTestGateway(t, service, permissions)
	g.orchestrator.reviewToken = patchReviewTestToken
	body := `{"digest":"` + strings.Repeat("b", 64) + `"}`
	for _, action := range []string{"apply", "reconcile"} {
		path := patchScope + "/" + strings.Repeat("a", 32) + "/" + action
		delete(permissions, permissionNexusApprovalReview)
		delete(permissions, permissionNexusWorkspaceWrite)
		g.cfg.WorkspaceWriteGrants = nil
		before := calls.Load()
		if response := requestPatchReview(g, "POST", path, body); response.Code != 403 {
			t.Fatal(response.Code)
		}
		permissions[permissionNexusApprovalReview] = true
		if response := requestPatchReview(g, "POST", path, body); response.Code != 403 {
			t.Fatal(response.Code)
		}
		permissions[permissionNexusWorkspaceWrite] = true
		if response := requestPatchReview(g, "POST", path, body); response.Code != 403 {
			t.Fatal(response.Code)
		}
		if calls.Load() != before {
			t.Fatal("denied write reached the private service")
		}
		g.cfg.WorkspaceWriteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
		if response := requestPatchReview(g, "POST", path, body); response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		if response := requestPatchReview(g, "GET", path, ""); response.Code != 404 {
			t.Fatal("GET executed an action", response.Code)
		}
		executionEnvelope = false
		if response := requestPatchReview(g, "POST", path, body); response.Code != 502 {
			t.Fatal("incorrect execution envelope accepted", response.Code)
		}
		executionEnvelope = true
		upstreamStatus.Store(403)
		if response := requestPatchReview(g, "POST", path, body); response.Code != 403 || strings.Contains(response.Body.String(), "private policy details") {
			t.Fatal("revoked write was not returned safely", response.Code)
		}
		upstreamStatus.Store(0)
	}
}
