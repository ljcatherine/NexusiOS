package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestCommandReviewManifestMatchesPythonForUnicodeAndEscapes(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-service review fixture requires Python 3")
	}
	inputs, digest, err := commandInputManifest([]storedCommandInput{
		{Path: "src/a&<\u2028.py", Data: []byte("first")},
		{Path: "src/é.py", Data: []byte("second")},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(struct {
		Inputs []commandInput `json:"inputs"`
		Digest string         `json:"digest"`
	}{inputs, digest})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `import json,sys
from command_approvals import manifest_digest
record=json.load(sys.stdin)
assert manifest_digest(record['inputs'])==record['digest'], 'Go/Python input digest mismatch'
`)
	cmd.Dir = "../agent-orchestrator"
	cmd.Stdin = strings.NewReader(string(data))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("command review interop: %v %s", err, output)
	}
}

func TestCommandDispatchSignatureMatchesPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-service signature fixture requires Python 3")
	}
	p := commandRequest{Host: "nixos", WorkspaceID: "code", Generation: strings.Repeat("a", 64), Owner: strings.Repeat("b", 64), ApprovalID: strings.Repeat("c", 32), Digest: strings.Repeat("d", 64), OperationID: strings.Repeat("e", 32), SnapshotID: strings.Repeat("f", 32), ProfileID: "tests", ProfileVersion: strings.Repeat("1", 64), InputDigest: strings.Repeat("2", 64), ExpiresAt: 1794000000}
	key := "fixture-only-command-signing-not-a-real-credential"
	p.Proof = p.sign(key)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `import json,sys
from command_dispatch import command_proof
payload=json.load(sys.stdin)
assert command_proof(payload,'fixture-only-command-signing-not-a-real-credential')==payload['proof']
`)
	cmd.Dir = "../agent-orchestrator"
	cmd.Stdin = strings.NewReader(string(data))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go/Python command signature mismatch: %v %s", err, output)
	}
}
