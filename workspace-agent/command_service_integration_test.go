package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Unlike the earlier dispatcher fixture, this test uses the application's
// actual routes, initialization, private command state and authenticated
// handler stack. Only the review and gateway policy decisions are fixtures.
// The executed program is a single administrator-fixed, isolated read probe.
func TestCommandServiceRegisteredRoutesActualPythonDispatchRecovery(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is required for cross-service integration")
	}
	const script = `read -r line < /workspace/safe.txt; printf 'signed:%s' "$line"`
	_, _, workspacePath := commandTestRunner(t, script) // Verify usable real sandbox before configuring service.
	probe := commandTestConfig(t, script)
	p := probe.Profiles[0]
	readKey := "fixture-command-read-" + strings.Repeat("r", 40)
	executeKey := "fixture-command-execute-" + strings.Repeat("e", 40)
	cfg := config{
		Host:                 "nixos",
		Listen:               "127.0.0.1:8896",
		Token:                readKey,
		CommandExecutorToken: executeKey,
		Roots:                []rootConfig{{ID: "code", Name: "Isolated read-only test", Path: workspacePath, CommandProfiles: []string{"probe"}}},
		CommandProfiles: []commandProfilePolicy{{
			ID: p.ID, Executable: p.Executable, Arguments: nil,
		}},
	}
	// Copy the immutable administrator-side invocation from the actual runner,
	// not a client-supplied command or arguments.
	cfg.CommandProfiles[0] = commandProfilePolicy{
		ID: p.ID, Executable: p.Executable, Arguments: append([]string(nil), p.Args...),
		Files: append([]string(nil), p.Files...), RuntimePaths: append([]string(nil), p.RuntimePaths...),
		Limits: commandProfileLimits{TimeoutMS: p.Timeout.Milliseconds(), MemoryBytes: p.MemoryBytes,
			AddressSpaceBytes: p.AddressSpaceBytes, Processes: p.Processes,
			CPUSeconds: p.CPUSeconds, ScratchBytes: p.ScratchBytes, OutputBytes: p.OutputBytes},
	}
	cfg.SandboxPath, cfg.LimitPath = probe.SandboxPath, probe.LimitPath
	cfg.ScopePath, cfg.ControlPath = probe.ScopePath, probe.ControlPath
	cfg.CommandStateDir = privateAdmissionTestDirectory(t)
	cfg.CommandSnapshotDir = privateAdmissionTestDirectory(t)
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("actual configured command-service startup: %v", err)
	}
	defer s.close()
	if len(s.roots["code"].generation) != 64 {
		t.Fatal("opt-in read-only root did not receive persistent generation")
	}
	actual := s.handler()
	var prepared, sent, reconciled atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/commands/prepare") {
			record := httptest.NewRecorder()
			actual.ServeHTTP(record, r)
			if record.Code == http.StatusOK && prepared.Add(1) == 1 {
				// Trusted source changes after capture, before approval/dispatch.
				if err := os.WriteFile(filepath.Join(workspacePath, "safe.txt"), []byte("changed after capture\n"), 0600); err != nil {
					t.Errorf("edit fixture: %v", err)
				}
			}
			copyRecordedResponse(w, record)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/commands/execute") {
			sent.Add(1)
			record := httptest.NewRecorder()
			actual.ServeHTTP(record, r)
			if record.Code == http.StatusOK {
				// Lose the *transport reply* after the real host's durable receipt.
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					conn.Close()
					return
				}
			}
			copyRecordedResponse(w, record)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/commands/receipts/") {
			reconciled.Add(1)
		}
		actual.ServeHTTP(w, r)
	}))
	defer fixture.Close()
	data, err := json.Marshal(map[string]any{"base": fixture.URL + "/v1", "read_key": readKey, "execute_key": executeKey})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), python, "-c", `import json,sys,time,tempfile,uuid,os
from server import Controller
from run_jobs import RunStore
from command_approvals import CommandApprovals
from command_dispatch import CommandDispatcher,CommandDispatchUnavailable

fixture=json.load(sys.stdin)
owner='b'*64
base=fixture['base']
controller=Controller({'NEXUS_ORCHESTRATOR_TOKEN':'fixture-orchestrator-'+('o'*32),
 'NEXUS_PS5_CHAT_URL':'http://127.0.0.1:8081/v1','NEXUS_PS5_MODEL_ID':'fixture',
 'NEXUS_NIXOS_WORKSPACE_URL':base,'NEXUS_NIXOS_WORKSPACE_TOKEN':fixture['read_key'],
 'NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN':fixture['execute_key']})
controller.authorize_workspace_operation=lambda principal,workspace,operation: principal==owner and operation=='execute'
roots=controller.list_workspace('nixos')['workspaces']
assert len(roots)==1 and roots[0]['read_only'] is True
assert 'run_command' in roots[0]['capabilities'] and len(roots[0]['generation'])==64
with tempfile.TemporaryDirectory() as directory:
 os.chmod(directory,0o700)
 runs=RunStore(directory); approvals=CommandApprovals(runs)
 dispatch=CommandDispatcher(controller,approvals)
 submission_id=uuid.uuid4().hex
 item=dispatch.prepare_proposal(owner,'nixos','code','probe',submission_id)
 assert item['status']=='pending'
 assert item['proposal']['workspace_generation']==roots[0]['generation']
 assert dispatch.prepare_proposal(owner,'nixos','code','probe',submission_id)==item
 assert approvals.review(owner,item['id'],item['digest'],'approve')
 try:
  dispatch.execute(owner,item['id'],item['digest'])
  raise AssertionError('lost host reply should require reconciliation')
 except CommandDispatchUnavailable: pass
 original=approvals.get_execution(owner,item['id'],item['digest'])
 assert original['phase']=='uncertain'
 runs.close(); runs=RunStore(directory); approvals=CommandApprovals(runs)
 dispatch=CommandDispatcher(controller,approvals)
 finished=dispatch.reconcile(owner,item['id'],item['digest'])
 assert finished['phase']=='completed'
 assert finished['operation_id']==original['operation_id']
 assert finished['receipt']['result']['stdout']=='signed:fixture text'
 assert finished['receipt']['result']['exit_code']==0
 assert dispatch.execute(owner,item['id'],item['digest'])==finished
 runs.close()
`)
	cmd.Dir = "../agent-orchestrator"
	cmd.Stdin = strings.NewReader(string(data))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, python, "-c", string(cmd.Args[2]))
	cmd.Dir = "../agent-orchestrator"
	cmd.Stdin = strings.NewReader(string(data))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real registered host routes + Python parent dispatch: %v %s", err, output)
	}
	if prepared.Load() != 1 || sent.Load() != 1 || reconciled.Load() != 1 {
		t.Fatalf("unexpected host requests: prepared=%d executed=%d reconciled=%d", prepared.Load(), sent.Load(), reconciled.Load())
	}
	if got, err := os.ReadFile(filepath.Join(workspacePath, "safe.txt")); err != nil || string(got) != "changed after capture\n" {
		t.Fatal("captured execution unexpectedly overwrote mutable host source", err)
	}
}

func copyRecordedResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}

// Acceptance through the *registered and authenticated* service routes, rather
// than a direct runner method call: a distinct executor token requests cancel
// while a real scope is executing. A missing/mutated bearer or request cannot
// stop another operation. Terminal receipts remain replay-safe after cancel.
func TestCommandServiceActualHTTPInFlightCancelAndReceipt(t *testing.T) {
	const script = `while :; do :; done`
	_, _, path := commandTestRunner(t, script)
	profile := commandTestConfig(t, script)
	p := profile.Profiles[0]
	readKey := "fixture-command-read-" + strings.Repeat("r", 40)
	execKey := "fixture-command-execute-" + strings.Repeat("e", 40)
	cfg := config{
		Host: "nixos", Listen: "127.0.0.1:8896", Token: readKey,
		CommandExecutorToken: execKey,
		Roots: []rootConfig{{ID: "code", Name: "Isolated read-only test", Path: path,
			CommandProfiles: []string{"probe"}}},
		CommandProfiles: []commandProfilePolicy{{
			ID: p.ID, Executable: p.Executable, Arguments: append([]string(nil), p.Args...),
			Files: append([]string(nil), p.Files...), RuntimePaths: append([]string(nil), p.RuntimePaths...),
			Limits: commandProfileLimits{TimeoutMS: p.Timeout.Milliseconds(), MemoryBytes: p.MemoryBytes,
				AddressSpaceBytes: p.AddressSpaceBytes, Processes: p.Processes, CPUSeconds: p.CPUSeconds,
				ScratchBytes: p.ScratchBytes, OutputBytes: p.OutputBytes},
		}},
		SandboxPath: profile.SandboxPath, LimitPath: profile.LimitPath,
		ScopePath: profile.ScopePath, ControlPath: profile.ControlPath,
		CommandStateDir:    privateAdmissionTestDirectory(t),
		CommandSnapshotDir: privateAdmissionTestDirectory(t),
	}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("start actual registered command routes: %v", err)
	}
	defer s.close()
	server := httptest.NewServer(s.handler())
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	type response struct {
		status int
		body   []byte
	}
	call := func(method, route, token string, payload any) response {
		t.Helper()
		var reader io.Reader
		if payload != nil {
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(data)
		}
		request, err := http.NewRequest(method, server.URL+route, reader)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if payload != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		result, err := client.Do(request)
		if err != nil {
			t.Fatalf("HTTP request %s: %v", route, err)
		}
		defer result.Body.Close()
		contents, err := io.ReadAll(io.LimitReader(result.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response{result.StatusCode, contents}
	}
	owner := strings.Repeat("b", 64)
	snapshotID := strings.Repeat("a", 32)
	expires := time.Now().Add(100 * time.Second).Unix()
	pathBase := "/v1/workspaces/code/commands"
	prep := call("POST", pathBase+"/prepare", readKey, map[string]any{
		"host": "nixos", "workspace_id": "code", "owner": owner, "profile_id": "probe",
		"snapshot_id": snapshotID, "expires_at": expires})
	if prep.status != 200 {
		t.Fatalf("prepare HTTP %d %s", prep.status, prep.body)
	}
	var snapshot struct {
		Snapshot commandPreparation `json:"snapshot"`
	}
	if err := json.Unmarshal(prep.body, &snapshot); err != nil {
		t.Fatal(err)
	}
	m := snapshot.Snapshot
	payload := commandRequest{Host: "nixos", WorkspaceID: "code", Generation: m.Generation,
		Owner: owner, ApprovalID: strings.Repeat("c", 32), Digest: strings.Repeat("d", 64),
		OperationID: strings.Repeat("e", 32), SnapshotID: m.ID, ProfileID: m.ProfileID,
		ProfileVersion: m.Profile, InputDigest: m.InputDigest, ExpiresAt: m.ExpiresAt}
	payload.Proof = payload.sign(execKey)
	operationRoute := pathBase + "/receipts/" + payload.OperationID
	if got := call("POST", operationRoute+"/cancel", readKey, payload); got.status != 401 {
		t.Fatalf("read token cancelled operation: %d", got.status)
	}
	if got := call("POST", operationRoute+"/cancel", execKey, payload); got.status != 409 {
		t.Fatalf("unknown unclaimed operation cancellation was not refused: %d", got.status)
	}
	finished := make(chan response, 1)
	go func() {
		finished <- call("POST", pathBase+"/execute", execKey, payload)
	}()
	deadline := time.Now().Add(time.Second * 3)
	for {
		s.commands.activeMu.Lock()
		active := s.commands.activeCommands[payload.OperationID] != nil
		s.commands.activeMu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP execution never entered active command state")
		}
		time.Sleep(8 * time.Millisecond)
	}
	mutated := payload
	mutated.Owner = strings.Repeat("f", 64)
	mutated.Proof = mutated.sign(execKey)
	if got := call("POST", operationRoute+"/cancel", execKey, mutated); got.status != 409 {
		t.Fatalf("different signed owner cancelled existing operation: %d", got.status)
	}
	mutated = payload
	mutated.Proof = strings.Repeat("0", 64)
	if got := call("POST", operationRoute+"/cancel", execKey, mutated); got.status != 400 {
		t.Fatalf("invalid HMAC cancelled operation: %d", got.status)
	}
	cancelled := call("POST", operationRoute+"/cancel", execKey, payload)
	if cancelled.status != 200 {
		t.Fatalf("cancel HTTP %d %s", cancelled.status, cancelled.body)
	}
	var cancelAck struct {
		OperationID string `json:"operation_id"`
		Cancelled   bool   `json:"cancel_requested"`
		Status      string `json:"receipt_status"`
	}
	if err := json.Unmarshal(cancelled.body, &cancelAck); err != nil || !cancelAck.Cancelled || cancelAck.OperationID != payload.OperationID || cancelAck.Status != "claimed" {
		t.Fatalf("invalid HTTP cancellation acknowledgment: %+v %v", cancelAck, err)
	}
	select {
	case result := <-finished:
		var receipt commandReceipt
		if err := json.Unmarshal(result.body, &receipt); err != nil || result.status != 200 || receipt.Result == nil || !receipt.Result.Cancelled || receipt.Status != "completed" {
			t.Fatalf("terminal HTTP receipt: %d %+v %v", result.status, receipt, err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("real HTTP cancellation never completed")
	}
	late := call("POST", operationRoute+"/cancel", execKey, payload)
	if late.status != 200 {
		t.Fatalf("late cancellation: HTTP %d", late.status)
	}
	if got := call("POST", pathBase+"/execute", execKey, payload); got.status != 200 || s.commandJournal.count != 2 {
		t.Fatalf("command was replayed after cancellation: HTTP %d journal_count=%d", got.status, s.commandJournal.count)
	}
}
