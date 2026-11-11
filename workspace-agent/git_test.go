package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitFixture(t *testing.T) (testHarness, *gitInspector) {
	t.Helper()
	h := setup(t)
	paths := make([]string, 3)
	for i, item := range []struct{ env, name string }{
		{"NEXUS_TEST_GIT_EXECUTABLE", "git"}, {"NEXUS_TEST_BWRAP_EXECUTABLE", "bwrap"}, {"NEXUS_TEST_PRLIMIT_EXECUTABLE", "prlimit"},
	} {
		paths[i] = os.Getenv(item.env)
		if paths[i] == "" {
			var err error
			paths[i], err = exec.LookPath(item.name)
			if err != nil {
				t.Skip("sandbox integration requires Git, bubblewrap >= 0.12 and prlimit")
			}
		}
	}
	g, err := newGitInspector(config{GitPath: paths[0], SandboxPath: paths[1], LimitPath: paths[2]})
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(g.git, args...)
		cmd.Dir = h.root
		cmd.Env = []string{"PATH=/nonexistent", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture Git: %v: %s", err, output)
		}
	}
	run("init", "-q")
	run("add", "--", "README.md", ".env", "credentials.json")
	run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
	for _, name := range []string{"README.md", ".env", "credentials.json"} {
		if err := os.WriteFile(filepath.Join(h.root, name), []byte("changed\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// None of these repository-controlled commands may run, including clean
	// filters (which --no-ext-diff/--no-textconv alone would not disable).
	run("config", "core.fsmonitor", "missing-helper")
	run("config", "diff.external", "missing-helper")
	run("config", "filter.trap.clean", "missing-helper")
	run("config", "filter.trap.required", "true")
	if err := os.WriteFile(filepath.Join(h.root, ".gitattributes"), []byte("*.md filter=trap\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.server.git = g
	h.server.roots["code"].config.GitRead = true
	return h, g
}

func TestGitInspectionIsOptIn(t *testing.T) {
	h := setup(t)
	for _, operation := range []string{"git_status", "git_diff", "git_diff_staged"} {
		body := `{"host":"nixos","workspace_id":"code","operation":"` + operation + `","path":"README.md"}`
		if response := request(h, "POST", "/v1/subagents/tasks", testToken, body); response.Code != 403 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
}

func TestSandboxedGitStatusDiffAndSecretFiltering(t *testing.T) {
	h, _ := gitFixture(t)
	for _, operation := range []string{"git_status", "git_diff", "git_diff_staged"} {
		path := "README.md"
		if operation == "git_status" {
			path = ""
		}
		body := `{"host":"nixos","workspace_id":"code","operation":"` + operation + `","path":"` + path + `"}`
		response := request(h, "POST", "/v1/subagents/tasks", testToken, body)
		if response.Code != 200 {
			t.Fatalf("%s: %d %s", operation, response.Code, response.Body.String())
		}
		var result taskResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Git == nil || strings.Contains(response.Body.String(), h.root) || strings.Contains(response.Body.String(), "credentials.json") || strings.Contains(response.Body.String(), ".env") {
			t.Fatal(response.Body.String())
		}
		if operation == "git_status" && (len(result.Git.Changes) != 1 || result.Git.Changes[0].Path != "README.md") {
			t.Fatal(result.Git)
		}
		if operation == "git_diff" && (!strings.Contains(result.Git.Diff, "+changed") || !strings.Contains(result.Git.Diff, "-Welcome to Nexus")) {
			t.Fatal(result.Git)
		}
		if operation == "git_diff_staged" && result.Git.Diff != "" {
			t.Fatal("unstaged changes leaked into staged diff")
		}
	}
	for _, path := range []string{".env", "credentials.json", "../outside.txt", "linked.txt", "external/outside.txt", ""} {
		body, _ := json.Marshal(map[string]string{"host": "nixos", "workspace_id": "code", "operation": "git_diff", "path": path})
		if response := request(h, "POST", "/v1/subagents/tasks", testToken, string(body)); response.Code == 200 {
			t.Fatal("unsafe diff accepted", path)
		}
	}
}

func TestGitComparisonsStayLiteralAndSeparateIndexFromWorktree(t *testing.T) {
	h, g := gitFixture(t)
	root := h.server.roots["code"]
	git := exec.Command(g.git, "-c", "core.fsmonitor=false", "-c", "filter.trap.required=false", "-c", "filter.trap.clean=", "add", "--", "README.md")
	git.Dir = h.root
	git.Env = []string{"HOME=/nonexistent", "PATH=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if output, err := git.CombinedOutput(); err != nil {
		t.Fatalf("stage fixture: %v %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(h.root, "README.md"), []byte("after staging\n"), 0600); err != nil {
		t.Fatal(err)
	}
	staged, err := g.inspect(context.Background(), root, "git_diff_staged", "README.md")
	if err != nil || !strings.Contains(staged.Diff, "+changed") || strings.Contains(staged.Diff, "after staging") {
		t.Fatal("incorrect staged comparison", staged, err)
	}
	working, err := g.inspect(context.Background(), root, "git_diff", "README.md")
	if err != nil || !strings.Contains(working.Diff, "+after staging") || strings.Contains(working.Diff, "Welcome to Nexus") {
		t.Fatal("incorrect worktree comparison", working, err)
	}
	literal, err := g.inspect(context.Background(), root, "git_diff", ":(glob)*.md")
	if err != nil || literal.Diff != "" {
		t.Fatal("Git pathspec expanded", literal, err)
	}
	if err := os.Rename(filepath.Join(h.root, ".git"), filepath.Join(h.root, ".git.original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h.root, ".git.original"), filepath.Join(h.root, ".git")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.inspect(context.Background(), root, "git_status", ""); !errors.Is(err, errForbidden) {
		t.Fatal("symlinked Git metadata accepted", err)
	}
}

func TestGitSandboxDeniesWritesOutsideReadsAndHostNetwork(t *testing.T) {
	h, g := gitFixture(t)
	// The alias override here is a test probe, never API-controlled.
	// Execute a fixture helper through Git to observe the real
	// isolation policy, with all normal production paths still fixed/readonly.
	outside := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(outside, []byte("OUTSIDE_PRIVATE"), 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(h.root, "probe.sh")
	shellPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("isolation probe requires Bash's TCP builtin")
	}
	shell, err := filepath.EvalSymlinks(shellPath)
	if err != nil {
		t.Fatal(err)
	}
	hostServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer hostServer.Close()
	port := hostServer.Listener.Addr().(*net.TCPAddr).Port
	script := "#!" + shell + "\necho DENIED\nif echo write > /workspace/unwanted.txt; then echo WRITE_ALLOWED; fi\nif test -r '" + outside + "'; then echo OUTSIDE_VISIBLE; fi\n" +
		fmt.Sprintf("if (echo probe > /dev/tcp/127.0.0.1/%d) 2>/dev/null; then echo NETWORK_ALLOWED; fi\n", port)
	if err := os.WriteFile(probe, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	output, err := g.run(context.Background(), h.server.roots["code"], []string{"-c", "alias.probe=!/workspace/probe.sh", "probe"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "DENIED") || strings.Contains(string(output), "WRITE_ALLOWED") || strings.Contains(string(output), "OUTSIDE_VISIBLE") || strings.Contains(string(output), "NETWORK_ALLOWED") {
		t.Fatal(string(output))
	}
	if _, err := os.Stat(filepath.Join(h.root, "unwanted.txt")); !os.IsNotExist(err) {
		t.Fatal("workspace was writable")
	}
}

func TestGitSandboxBoundsOutputAndCancellation(t *testing.T) {
	h, g := gitFixture(t)
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(h.root, "probe.sh")
	if err := os.WriteFile(probe, []byte("#!"+shell+"\nwhile :; do echo '"+strings.Repeat("x", 1000)+"'; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := g.run(ctx, h.server.roots["code"], []string{"-c", "alias.probe=!/workspace/probe.sh", "probe"}); !errors.Is(err, errTooLarge) {
		t.Fatal("output limit not enforced", err)
	}
	if err := os.WriteFile(probe, []byte("#!"+shell+"\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancelAgain := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelAgain()
	started := time.Now()
	if _, err := g.run(ctx, h.server.roots["code"], []string{"-c", "alias.probe=!/workspace/probe.sh", "probe"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline not enforced", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancellation did not terminate promptly")
	}
}
