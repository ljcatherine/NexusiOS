package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// Local test-only routes exercise the real Python dispatcher and confined Go
// executor. Human review/current policy are fixture decisions, not live grants.
func TestCommandActualPythonDispatchLostReplyAndReceiptRecovery(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-service command fixture requires Python 3")
	}
	runner, root, _ := commandTestRunner(t, `read -r line < /workspace/safe.txt; printf 'signed:%s' "$line"`)
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	owner := strings.Repeat("b", 64)
	store, err := openCommandSnapshots(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if err := store.Save(context.Background(), "nixos", owner, prepared); err != nil {
		t.Fatal(err)
	}
	journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	p := runner.profiles["probe"]
	invocation := map[string]any{"executable": p.Executable, "arguments": p.Args, "limits": map[string]any{
		"timeout_ms": p.Timeout.Milliseconds(), "memory_bytes": p.MemoryBytes, "address_space_bytes": p.AddressSpaceBytes,
		"processes": p.Processes, "cpu_seconds": p.CPUSeconds, "scratch_bytes": p.ScratchBytes, "output_bytes": p.OutputBytes}}
	key := "fixture-only-command-signature-" + strings.Repeat("x", 32)
	readKey := "fixture-only-read-" + strings.Repeat("r", 32)
	var executed, reconciled atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			if r.Header.Get("Authorization") != "Bearer "+readKey {
				w.WriteHeader(401)
				return
			}
			if r.URL.Path == "/v1/workspaces" {
				json.NewEncoder(w).Encode(map[string]any{"host": "nixos", "workspaces": []any{map[string]any{"id": "code", "name": "Fixture", "read_only": true, "generation": root.generation, "capabilities": []string{"run_command"}}}})
				return
			}
			if r.URL.Path == "/v1/workspaces/code/commands/profiles" {
				json.NewEncoder(w).Encode(map[string]any{"host": "nixos", "workspace_id": "code", "profiles": []any{map[string]any{"id": "probe", "version": prepared.Metadata().Profile, "invocation": invocation}}})
				return
			}
		}
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			return
		}
		var request commandRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		var receipt commandReceipt
		var actionErr error
		if r.URL.Path == "/v1/workspaces/code/commands/execute" {
			executed.Add(1)
			loaded, loadErr := store.Load(r.Context(), "nixos", owner, request.SnapshotID)
			if loadErr != nil {
				w.WriteHeader(409)
				return
			}
			defer loaded.Close()
			receipt, actionErr = runner.ExecuteRecorded(r.Context(), journal, key, "nixos", root, loaded, request)
			if actionErr == nil {
				// The host durably completed, but the parent receives no HTTP receipt.
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
		} else if r.URL.Path == "/v1/workspaces/code/commands/receipts/"+request.OperationID+"/reconcile" {
			reconciled.Add(1)
			receipt, actionErr = runner.ReconcileRecorded(r.Context(), journal, key, "nixos", request)
		} else {
			w.WriteHeader(404)
			return
		}
		if actionErr != nil {
			w.WriteHeader(409)
			return
		}
		json.NewEncoder(w).Encode(receipt)
	}))
	defer server.Close()
	data, err := json.Marshal(map[string]any{"base": server.URL + "/v1", "owner": owner, "read_key": readKey, "key": key, "metadata": prepared.Metadata(), "invocation": invocation})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `import json,sys,tempfile,os
from server import Controller
from run_jobs import RunStore
from command_approvals import CommandApprovals
from command_dispatch import CommandDispatcher,CommandDispatchUnavailable
record=json.load(sys.stdin)
controller=Controller({'NEXUS_ORCHESTRATOR_TOKEN':'fixture-orchestrator-'+('o'*32),'NEXUS_PS5_CHAT_URL':'http://127.0.0.1:8081/v1','NEXUS_PS5_MODEL_ID':'fixture','NEXUS_NIXOS_WORKSPACE_URL':record['base'],'NEXUS_NIXOS_WORKSPACE_TOKEN':record['read_key'],'NEXUS_NIXOS_COMMAND_EXECUTOR_TOKEN':record['key']})
controller.authorize_workspace_operation=lambda owner,workspace,operation: owner==record['owner'] and operation=='execute'
proposal={'kind':'command','host':'nixos',**record['metadata'],'invocation':record['invocation']}
with tempfile.TemporaryDirectory() as directory:
 os.chmod(directory,0o700)
 runs=RunStore(directory);approvals=CommandApprovals(runs)
 item=approvals.propose(record['owner'],proposal,'a'*32)
 assert approvals.review(record['owner'],item['id'],item['digest'],'approve')
 dispatcher=CommandDispatcher(controller,approvals)
 try:
  dispatcher.execute(record['owner'],item['id'],item['digest'])
  raise AssertionError('host receipt should have been lost')
 except CommandDispatchUnavailable: pass
 saved=approvals.get_execution(record['owner'],item['id'],item['digest'])
 assert saved['phase']=='uncertain'
 runs.close();runs=RunStore(directory);approvals=CommandApprovals(runs);dispatcher=CommandDispatcher(controller,approvals)
 finished=dispatcher.reconcile(record['owner'],item['id'],item['digest'])
 assert finished['phase']=='completed' and finished['receipt']['result']['stdout']=='signed:fixture text'
 assert finished['operation_id']==saved['operation_id']
 assert dispatcher.execute(record['owner'],item['id'],item['digest'])==finished
 runs.close()
`)
	cmd.Dir = "../agent-orchestrator"
	cmd.Stdin = strings.NewReader(string(data))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real command dispatch fixture: %v %s", err, output)
	}
	if executed.Load() != 1 || reconciled.Load() != 1 {
		t.Fatal("unexpected dispatch/reconcile count", executed.Load(), reconciled.Load())
	}
}
