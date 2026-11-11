package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Real gateway and Python HTTP/SQLite service; workspace reads use a fixture.
func TestGatewayPythonPatchReviewBoundary(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for cross-service review fixture")
	}
	root, err := filepath.Abs("../agent-orchestrator")
	if err != nil {
		t.Fatal(err)
	}
	const script = `
import sys, threading
sys.path.insert(0, sys.argv[1])
from test_server import FakeController, api
controller = FakeController()
controller.token = sys.argv[2]
controller.review_token = sys.argv[3]
service = api.Service(('127.0.0.1', 0), controller, state_dir=sys.argv[4])
threading.Thread(target=service.serve_forever, daemon=True).start()
print(service.server_port, flush=True)
try:
    sys.stdin.read()
finally:
    service.shutdown()
    service.server_close()
`
	cmd := exec.Command(python, "-c", script, root, orchestratorTestToken, patchReviewTestToken, filepath.Join(t.TempDir(), "runs"))
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Python review fixture failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("Python review fixture did not stop")
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(output).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	var port string
	select {
	case port = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("Python review startup timed out")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 {
		t.Fatal("Python review fixture unavailable")
	}
	placeholder := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer placeholder.Close()
	g := orchestratorTestGateway(t, placeholder, map[string]bool{permissionNexusWorkspaceRead: true, permissionNexusPatchPropose: true, permissionNexusApprovalReview: true})
	g.orchestrator.endpoint = "http://127.0.0.1:" + port
	g.orchestrator.reviewToken = patchReviewTestToken
	body := `{"path":"src/main.py","replacement":"print(7)","submission_id":"` + strings.Repeat("e", 32) + `"}`
	created := requestPatchReview(g, "POST", patchScope, body)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var envelope struct {
		Patch struct{ ID, Digest, Status string }
	}
	if err := json.Unmarshal(created.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	id, digest := envelope.Patch.ID, envelope.Patch.Digest
	if len(id) != 32 || len(digest) != 64 {
		t.Fatal("missing immutable proposal identity")
	}
	for _, route := range []string{patchScope, patchScope + "/" + id} {
		response := requestPatchReview(g, "GET", route, "")
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	decision := `{"digest":"` + digest + `","decision":"approve"}`
	response := requestPatchReview(g, "POST", patchScope+"/"+id+"/decision", decision)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"status":"approved"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	if replay := requestPatchReview(g, "POST", patchScope+"/"+id+"/decision", decision); replay.Code != 409 {
		t.Fatal("review replay accepted", replay.Code)
	}
	if retry := requestPatchReview(g, "POST", patchScope, body); retry.Code != 200 || !strings.Contains(retry.Body.String(), id) {
		t.Fatal("retry changed identity", retry.Code)
	}
	g.orchestrator.reviewToken = "wrong-private-review-credential-0123456789"
	if denied := requestPatchReview(g, "GET", patchScope, ""); denied.Code != 502 {
		t.Fatal("invalid private review credential accepted", denied.Code)
	}
	request, _ := http.NewRequest("GET", g.orchestrator.endpoint+patchScope, nil)
	request.Header.Set("Authorization", "Bearer "+orchestratorTestToken)
	request.Header.Set("X-Nexus-Principal", strings.Repeat("a", 64))
	result, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, result.Body)
	result.Body.Close()
	if result.StatusCode != 401 {
		t.Fatal("agent credential reached review", result.StatusCode)
	}
}
