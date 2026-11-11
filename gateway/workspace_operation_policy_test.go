package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkspaceOperationPolicyNeedsExplicitWriteScopeAndRoot(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	scopes := map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true, permissionNexusPatchPropose: true}
	g := orchestratorTestGateway(t, upstream, scopes)
	g.cfg.OrchestratorBearerToken = orchestratorTestToken
	hash := sha256.Sum256([]byte("owner-subject"))
	principal := hex.EncodeToString(hash[:])
	check := func(operation, root, peer, credential string) int {
		r := httptest.NewRequest("POST", "/internal/nexus/authorize-workspace-operation", strings.NewReader(
			`{"principal":"`+principal+`","workspace":{"host":"debian","id":"`+root+`"},"operation":"`+operation+`"}`))
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if status := check("propose", "code", "127.0.0.1:1234", orchestratorTestToken); status != 204 {
		t.Fatal(status)
	}
	if status := check("apply", "code", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("implicit write", status)
	}
	scopes[permissionNexusWorkspaceWrite] = true
	if status := check("apply", "code", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("missing write-root policy", status)
	}
	g.cfg.WorkspaceWriteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	if status := check("apply", "code", "127.0.0.1:1234", orchestratorTestToken); status != 204 {
		t.Fatal(status)
	}
	if status := check("apply", "other", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("root bypass", status)
	}
	if status := check("apply", "code", "192.0.2.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("nonloopback caller", status)
	}
	if status := check("apply", "code", "127.0.0.1:1234", "wrong"); status != 403 {
		t.Fatal("wrong credential", status)
	}
	if status := check("shell", "code", "127.0.0.1:1234", orchestratorTestToken); status != 400 {
		t.Fatal("unknown operation", status)
	}
	if status := check("execute", "code", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("write implicitly allowed execution", status)
	}
	scopes[permissionNexusWorkspaceExecute] = true
	if status := check("execute", "code", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("missing independent execute-root grant", status)
	}
	g.cfg.WorkspaceExecuteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	if status := check("execute", "code", "127.0.0.1:1234", orchestratorTestToken); status != 204 {
		t.Fatal("explicit execute denied", status)
	}
	delete(scopes, permissionNexusWorkspaceWrite)
	g.cfg.WorkspaceWriteGrants = nil
	if status := check("execute", "code", "127.0.0.1:1234", orchestratorTestToken); status != 204 {
		t.Fatal("execution incorrectly required write permission", status)
	}
	if status := check("execute", "other", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("execute-root bypass", status)
	}
	scopes[permissionNexusWorkspaceWrite] = true
	g.cfg.WorkspaceWriteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	delete(scopes, permissionNexusWorkspaceRead)
	if status := check("apply", "code", "127.0.0.1:1234", orchestratorTestToken); status != 403 {
		t.Fatal("write without read grant", status)
	}
}

func TestAgentProposalFlagCannotBypassProposerPermission(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nexus/agent-runs/active" {
			w.Write([]byte(`{"active":0}`))
			return
		}
		w.WriteHeader(202)
		w.Write([]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"queued"}`))
	}))
	defer upstream.Close()
	scopes := map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true}
	g := orchestratorTestGateway(t, upstream, scopes)
	body := `{"prompt":"edit","workspace":{"host":"debian","workspace_id":"code","path":""},"allow_proposals":true}`
	if response := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", body); response.Code != 403 {
		t.Fatal(response.Code, response.Body.String())
	}
	scopes[permissionNexusPatchPropose] = true
	if response := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", body); response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	for _, value := range []string{`null`, `"true"`, `[]`, `{}`} {
		malformed := strings.Replace(body, `"allow_proposals":true`, `"allow_proposals":`+value, 1)
		if response := requestOrchestrator(g, "POST", "/v1/nexus/agent-runs", malformed); response.Code != 400 {
			t.Fatal("malformed flag accepted", response.Code)
		}
	}
}
