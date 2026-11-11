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

const commandReviewScope = "/v1/nexus/workspaces/debian/code/commands"

func TestCommandReviewNeedsIndependentExecuteAndHumanScopes(t *testing.T) {
	var calls atomic.Int32
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+patchReviewTestToken || r.Header.Get("Cookie") != "" ||
			r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Nexus-Principal") != func() string { digest := sha256.Sum256([]byte("owner-subject")); return hex.EncodeToString(digest[:]) }() {
			t.Error("private command review ingress used wrong credentials or leaked caller identity")
		}
		if r.Method == "GET" && r.URL.Path == commandReviewScope {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":false,"commands":[]}`)
			return
		}
		if r.Method == "GET" && r.URL.Path == commandReviewScope+"/profiles" {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","workspace_generation":"`+strings.Repeat("c", 64)+`","execution_enabled":false,"profiles":[{"id":"probe","version":"`+strings.Repeat("d", 64)+`","invocation":{"executable":"/bin/true","arguments":[],"limits":{"timeout_ms":1000,"memory_bytes":16777216,"address_space_bytes":16777216,"processes":1,"cpu_seconds":1,"scratch_bytes":4096,"output_bytes":1024}}}]}`)
			return
		}
		execute := strings.HasSuffix(r.URL.Path, "/execute") || strings.HasSuffix(r.URL.Path, "/reconcile") || strings.HasSuffix(r.URL.Path, "/cancel")
		if execute {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":true,"command":{"proposal":{"host":"debian","workspace_id":"code"}}}`)
		} else {
			io.WriteString(w, `{"host":"debian","workspace_id":"code","execution_enabled":false,"command":{"proposal":{"host":"debian","workspace_id":"code"}}}`)
		}
	}))
	defer service.Close()
	permissions := map[string]bool{permissionNexusWorkspaceRead: true, permissionOrchestrate: true, permissionChat: true, permissionNexusApprovalReview: true}
	g := orchestratorTestGateway(t, service, permissions)
	g.orchestrator.reviewToken = patchReviewTestToken
	request := func(method, path, body string) int { return requestPatchReview(g, method, path, body).Code }
	assertDenied := func(label string) {
		t.Helper()
		before := calls.Load()
		if got := request("GET", commandReviewScope, ""); got != 403 || calls.Load() != before {
			t.Fatalf("%s reached protected command review: HTTP %d upstream %d->%d", label, got, before, calls.Load())
		}
	}
	assertDenied("no execute scope or root")
	permissions[permissionNexusWorkspaceExecute] = true
	assertDenied("no execute root")
	g.cfg.WorkspaceExecuteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	if got := request("GET", commandReviewScope, ""); got != 200 {
		t.Fatalf("approved owner unable to view commands: %d", got)
	}
	if got := request("GET", commandReviewScope+"/profiles", ""); got != 200 {
		t.Fatalf("fixed-profile inventory unavailable: %d", got)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"POST", commandReviewScope, `{"profile_id":"probe","submission_id":"` + strings.Repeat("a", 32) + `"}`},
		{"GET", commandReviewScope + "/" + strings.Repeat("a", 32), ""},
		{"POST", commandReviewScope + "/" + strings.Repeat("a", 32) + "/decision", `{"digest":"` + strings.Repeat("b", 64) + `","decision":"approve"}`},
		{"POST", commandReviewScope + "/" + strings.Repeat("a", 32) + "/execute", `{"digest":"` + strings.Repeat("b", 64) + `"}`},
		{"POST", commandReviewScope + "/" + strings.Repeat("a", 32) + "/reconcile", `{"digest":"` + strings.Repeat("b", 64) + `"}`},
		{"POST", commandReviewScope + "/" + strings.Repeat("a", 32) + "/cancel", `{"digest":"` + strings.Repeat("b", 64) + `"}`},
	} {
		if got := request(tc.method, tc.path, tc.body); got != 200 {
			t.Fatalf("protected method %s %s: HTTP %d", tc.method, tc.path, got)
		}
	}
	delete(permissions, permissionNexusApprovalReview)
	assertDenied("revoked human review scope")
	permissions[permissionNexusApprovalReview] = true
	delete(permissions, permissionChat)
	assertDenied("revoked chat scope")
	permissions[permissionChat] = true
	delete(permissions, permissionOrchestrate)
	assertDenied("revoked orchestrate scope")
	permissions[permissionOrchestrate] = true
	delete(permissions, permissionNexusWorkspaceExecute)
	assertDenied("revoked execute scope")
	permissions[permissionNexusWorkspaceExecute] = true
	g.cfg.WorkspaceGrants = nil
	assertDenied("revoked read root")
}

func TestCommandReviewFailClosedOnPayloadIdentityAndHostResponse(t *testing.T) {
	response := `{"host":"debian","workspace_id":"code","execution_enabled":false,"commands":[]}`
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, response)
	}))
	defer service.Close()
	g := orchestratorTestGateway(t, service, map[string]bool{permissionNexusWorkspaceRead: true, permissionOrchestrate: true,
		permissionChat: true, permissionNexusApprovalReview: true, permissionNexusWorkspaceExecute: true})
	g.orchestrator.reviewToken = patchReviewTestToken
	g.cfg.WorkspaceExecuteGrants = map[string]map[string]bool{"owner-subject": {"debian:code": true}}
	check := func(method, path, body string, status int) {
		t.Helper()
		w := requestPatchReview(g, method, path, body)
		if w.Code != status {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, status, w.Body.String())
		}
	}
	check("POST", commandReviewScope, `{"profile_id":"tests","profile_id":"evil"}`, 400)
	check("POST", commandReviewScope, strings.Repeat("x", 4097), 413)
	check("GET", commandReviewScope+"?x=1", "", 404)
	check("GET", commandReviewScope+"/not-an-id", "", 404)
	check("GET", commandReviewScope+"/"+strings.Repeat("a", 32)+"/execute", "", 404)
	check("GET", commandReviewScope+"/"+strings.Repeat("a", 32)+"/cancel", "", 404)
	check("POST", commandReviewScope+"/profiles", `{}`, 404)
	check("POST", commandReviewScope+"/"+strings.Repeat("a", 32), `{}`, 404)
	g.orchestrator.reviewToken = orchestratorTestToken
	check("GET", commandReviewScope, "", 503)
	g.orchestrator.reviewToken = patchReviewTestToken
	response = `{"host":"nixos","workspace_id":"code","execution_enabled":false,"commands":[]}`
	check("GET", commandReviewScope, "", 502)
	response = `{"host":"debian","workspace_id":"code","execution_enabled":true,"commands":[]}`
	check("GET", commandReviewScope, "", 502)
	response = `{"host":"debian","workspace_id":"code","workspace_generation":"` + strings.Repeat("c", 64) + `","execution_enabled":false,"profiles":[{"id":"../unsafe","version":"` + strings.Repeat("d", 64) + `","invocation":{}}]}`
	check("GET", commandReviewScope+"/profiles", "", 502)
}
