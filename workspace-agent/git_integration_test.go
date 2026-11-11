package main

import (
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPythonControllerReadsRealSandboxedGitBridge(t *testing.T) {
	h, _ := gitFixture(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("cross-service fixture requires Python 3")
	}
	modulePath, err := filepath.Abs("../agent-orchestrator")
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(h.handler)
	defer service.Close()
	script := `import os
from server import Controller
c = Controller({
    'NEXUS_ORCHESTRATOR_TOKEN': 'o' * 40,
    'NEXUS_PS5_CHAT_URL': 'http://127.0.0.1:8081/v1',
    'NEXUS_PS5_MODEL_ID': 'unused-fixture',
    'NEXUS_NIXOS_WORKSPACE_URL': os.environ['TEST_WORKSPACE_URL'],
    'NEXUS_NIXOS_WORKSPACE_TOKEN': os.environ['TEST_WORKSPACE_TOKEN'],
})
roots = c.list_workspace('nixos')['workspaces']
assert roots[0]['read_only'] is True
assert 'git_status' in roots[0]['capabilities']
status = c.workspace_task('nixos', 'code', {'operation': 'git_status', 'path': ''})
assert [item['path'] for item in status['git']['changes']] == ['README.md']
diff = c.workspace_task('nixos', 'code', {'operation': 'git_diff', 'path': 'README.md'})
assert '+changed' in diff['git']['diff']
print('real bridge/controller Git inspection passed')
`
	cmd := exec.Command(python, "-c", script)
	cmd.Env = []string{"PYTHONPATH=" + modulePath, "PATH=/nonexistent", "TEST_WORKSPACE_URL=" + service.URL + "/v1", "TEST_WORKSPACE_TOKEN=" + testToken}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-service fixture: %v: %s", err, output)
	}
}
