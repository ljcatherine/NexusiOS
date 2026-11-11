package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real Python policy client against the real Go handler over
// loopback and the real streaming client against a local PS5 protocol fixture.
func TestPythonSchedulerStopsAfterGatewayWorkspaceRevocation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the cross-service fixture")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	scopes := map[string]bool{permissionOrchestrate: true, permissionChat: true, permissionNexusWorkspaceRead: true}
	allowed := orchestratorTestGateway(t, upstream, scopes)
	allowed.cfg.OrchestratorBearerToken = orchestratorTestToken
	denied := orchestratorTestGateway(t, upstream, scopes)
	denied.cfg.OrchestratorBearerToken = orchestratorTestToken
	denied.cfg.WorkspaceGrants = map[string]map[string]bool{}
	var active atomic.Pointer[Gateway]
	active.Store(allowed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Load().Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../agent-orchestrator")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("owner-subject"))
	const script = `
import os, sys, tempfile, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
sys.path.insert(0, sys.argv[1])
from server import Controller
from run_jobs import RunJobs
class Backend(BaseHTTPRequestHandler):
    cancelled = threading.Event()
    stream_id = None
    delete_id = None
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        Backend.stream_id = self.headers.get('X-Conversation-Id')
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.end_headers()
        self.wfile.write(b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n')
        self.wfile.flush()
        print('started', flush=True)
        Backend.cancelled.wait(timeout=10)
    def do_DELETE(self):
        Backend.delete_id = parse_qs(urlsplit(self.path).query).get('conv_id', [None])[0]
        Backend.cancelled.set()
        self.send_response(204)
        self.end_headers()
    def log_message(self, *_args):
        pass
backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
backend_thread.start()
class Fixture(Controller):
    def run(self, payload, *, progress, cancelled, child_cancelled):
        self.llm([{'role':'user','content':'fixture'}], cancelled=cancelled)
        return {'response':'unexpected'}
controller = Fixture({'NEXUS_ORCHESTRATOR_TOKEN': os.environ['FIXTURE_TOKEN'],
                      'NEXUS_PS5_CHAT_URL': f'http://127.0.0.1:{backend.server_port}/v1',
                      'NEXUS_PS5_MODEL_ID': 'fixture',
                      'NEXUS_GATEWAY_POLICY_PORT': os.environ['FIXTURE_PORT']})
with tempfile.TemporaryDirectory() as root:
    os.chmod(root, 0o700)
    jobs = RunJobs(controller, root)
    try:
        record = jobs.submit({'prompt':'task','workspace':{'host':'debian','workspace_id':'code','path':''}},
                             owner=os.environ['FIXTURE_OWNER'])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status = jobs.store.get(record['id'])
            if status['status'] in ('completed','cancelled','failed'):
                assert status['status'] == 'failed' and status['phase'] == 'authorization revoked', status
                assert status['result'] is None
                assert Backend.cancelled.wait(timeout=2)
                assert Backend.stream_id and Backend.delete_id == Backend.stream_id
                assert jobs.store.inference_quarantined()
                break
            time.sleep(0.02)
        else:
            raise RuntimeError('task did not stop')
    finally:
        jobs.close()
        Backend.cancelled.set()
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=2)
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", script, root)
	cmd.Env = append(os.Environ(), "FIXTURE_TOKEN="+orchestratorTestToken,
		"FIXTURE_PORT="+port, "FIXTURE_OWNER="+hex.EncodeToString(digest[:]))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "started" {
		_ = cmd.Wait()
		t.Fatalf("scheduler did not start: %s", stderr.String())
	}
	active.Store(denied)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("scheduler did not stop on revocation: %v: %s", err, stderr.String())
	}
}
