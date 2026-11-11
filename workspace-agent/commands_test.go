package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const commandTestBwrap = "/nix/store/3hqwbwxij9lxhyrf2amsm2xg24xszmmx-bubblewrap-0.12.0/bin/bwrap"
const commandTestPrlimit = "/run/current-system/sw/bin/prlimit"

func commandTestRoot(t *testing.T) (*workspace, string) {
	t.Helper()
	path := t.TempDir()
	fd, err := openConfiguredRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return &workspace{fd: fd, config: rootConfig{ID: "code"}, generation: strings.Repeat("a", 64)}, path
}

func TestCommandSnapshotPolicy(t *testing.T) {
	root, path := commandTestRoot(t)
	put := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(path, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put("safe.txt", "only approved text\n")
	put(".env", "hidden")
	put("credentials.json", "protected")
	put("binary.txt", "\x00bad")
	put("hard.txt", "private")
	if err := os.Link(filepath.Join(path, "hard.txt"), filepath.Join(path, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(path, "safe.txt"), filepath.Join(path, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", "credentials.json", "binary.txt", "hard.txt", "alias.txt", "linked.txt", "missing.txt", "../safe.txt", "/safe.txt", "gitconfig", "etc/safe.txt"} {
		t.Run(name, func(t *testing.T) {
			if _, err := commandReadFile(context.Background(), root, name); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	files, _, _, err := captureCommandInputs(context.Background(), root, []string{"safe.txt"})
	if err != nil || len(files) != 1 || string(files[0].Data) != "only approved text\n" {
		t.Fatal("captured input", files, err)
	}
	put("safe.txt", "changed original")
	if string(files[0].Data) != "only approved text\n" {
		t.Fatal("snapshot references original")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := captureCommandInputs(ctx, root, []string{"safe.txt"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	put("large.txt", strings.Repeat("x", maxReadBytes+1))
	if _, err := commandReadFile(context.Background(), root, "large.txt"); err == nil {
		t.Fatal("large file accepted")
	}
	paths := []string{}
	for i := 0; i < 17; i++ {
		name := string(rune('a'+i)) + ".txt"
		put(name, strings.Repeat("x", maxReadBytes))
		paths = append(paths, name)
	}
	if _, _, _, err := captureCommandInputs(context.Background(), root, paths); !errors.Is(err, errTooLarge) {
		t.Fatal("snapshot total:", err)
	}
}

func commandTestConfig(t *testing.T, script string) commandRunnerConfig {
	t.Helper()
	// Debian supplies /usr/bin, while NixOS keeps systemd in an immutable
	// store path. Resolve the test-only trusted binaries through PATH rather
	// than silently skipping the entire real sandbox suite on NixOS.
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("user systemd-run is unavailable")
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		t.Skip("user systemctl is unavailable")
	}
	for _, path := range []string{commandTestBwrap, commandTestPrlimit, systemdRun, systemctl} {
		if _, err := trustedProgram(path); err != nil {
			t.Skipf("actual sandbox unavailable: trusted executable %s: %v", path, err)
		}
	}
	shell, err := trustedProgram("/bin/sh")
	if err != nil {
		t.Skipf("actual sandbox requires trusted /bin/sh: %v", err)
	}
	nix, err := exec.LookPath("nix-store")
	if err != nil {
		t.Skip("actual sandbox runtime closure unavailable: nix-store not installed")
	}
	closure, err := exec.Command(nix, "-qR", strings.Split(shell, "/bin/")[0], strings.Split(func() string { p, _ := trustedProgram(commandTestPrlimit); return p }(), "/bin/")[0]).CombinedOutput()
	if err != nil {
		t.Skipf("cannot resolve trusted shell runtime closure: %v: %s", err, closure)
	}
	return commandRunnerConfig{Enabled: true, SandboxPath: commandTestBwrap, LimitPath: commandTestPrlimit,
		ScopePath: systemdRun, ControlPath: systemctl,
		Profiles: []commandProfile{{ID: "probe", Executable: shell, Args: []string{"--noprofile", "--norc", "-c", script}, RuntimePaths: strings.Fields(string(closure)), Files: []string{"safe.txt"}, Timeout: 2 * time.Second, MemoryBytes: 128 << 20, Processes: 16, CPUSeconds: 2, ScratchBytes: 1 << 20, OutputBytes: 4096}}}
}

func commandTestRunner(t *testing.T, script string) (*commandRunner, *workspace, string) {
	t.Helper()
	cfg := commandTestConfig(t, script)
	root, path := commandTestRoot(t)
	if err := os.WriteFile(filepath.Join(path, "safe.txt"), []byte("fixture text\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Only this tiny fixed probe may skip for unsupported kernel/user namespaces.
	probe := cfg
	probe.Profiles = append([]commandProfile(nil), cfg.Profiles...)
	probe.Profiles[0].Args = []string{"--noprofile", "--norc", "-c", "printf sandbox-ready"}
	runner, err := newCommandRunner(probe)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), root, "probe")
	if err != nil || result.ExitCode != 0 || result.Stdout != "sandbox-ready" {
		t.Skipf("actual sandbox launch unavailable: error=%v exit=%d stderr=%q", err, result.ExitCode, result.Stderr)
	}
	runner, err = newCommandRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return runner, root, path
}

func TestCommandProfilesFailClosed(t *testing.T) {
	if _, err := newCommandRunner(commandRunnerConfig{}); !errors.Is(err, errForbidden) {
		t.Fatal(err)
	}
	root, _ := commandTestRoot(t)
	var absent *commandRunner
	if _, err := absent.Run(context.Background(), root, "probe"); !errors.Is(err, errForbidden) {
		t.Fatal(err)
	}
	cfg := commandTestConfig(t, "exit 0")
	for _, change := range []func(*commandRunnerConfig){
		func(c *commandRunnerConfig) { c.Profiles[0].ID = "../shell" },
		func(c *commandRunnerConfig) { c.Profiles[0].Executable = "sh" },
		func(c *commandRunnerConfig) { c.Profiles[0].RuntimePaths = []string{"/nix/store"} },
		func(c *commandRunnerConfig) { c.Profiles[0].Files = []string{".git/config"} },
		func(c *commandRunnerConfig) { c.Profiles[0].Timeout = 0 },
		func(c *commandRunnerConfig) { c.Profiles[0].OutputBytes = commandOutputBytes + 1 },
		func(c *commandRunnerConfig) { c.Profiles[0].Args = []string{string([]byte{0xff})} },
		func(c *commandRunnerConfig) { c.ScopePath = "/bin/true" },
		func(c *commandRunnerConfig) { c.Profiles[0].AddressSpaceBytes = 32 << 30 },
		func(c *commandRunnerConfig) { c.Profiles = append(c.Profiles, c.Profiles[0]) },
	} {
		copy := cfg
		copy.Profiles = append([]commandProfile(nil), cfg.Profiles...)
		change(&copy)
		if _, err := newCommandRunner(copy); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	runner, err := newCommandRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), root, "probe; exit 0"); !errors.Is(err, errForbidden) {
		t.Fatal(err)
	}
	cfg.Profiles[0].Args[0] = "mutated"
	if runner.profiles["probe"].Args[0] == "mutated" {
		t.Fatal("mutable policy")
	}
}

func TestCommandActualIsolation(t *testing.T) {
	script := `set -eu
read -r line < /workspace/safe.txt
[ "$line" = 'fixture text' ]
for p in /etc/passwd /home /run /proc /sys /workspace/.env /workspace/credentials.json /workspace/.git /workspace/linked.txt /workspace/alias.txt; do
 [ ! -e "$p" ] || exit 20
done
[ -z "${NEXUS_COMMAND_TEST_SECRET+x}" ]
[ "$HOME" = /nonexistent ]
[ "$PATH" = /nonexistent ]
[ "$(ulimit -u)" = 16 ]
[ "$(ulimit -n)" = 64 ]
[ "$(ulimit -v)" = 8388608 ]
[ "$(ulimit -t)" = 2 ]
if ( printf changed > /workspace/safe.txt ) 2>/tmp/mutation-error; then exit 21; fi
if ( printf new > /workspace/new.txt ) 2>/tmp/mutation-error; then exit 22; fi
if ( printf leak > /dev/tcp/1.1.1.1/443 ) 2>/tmp/network-error; then exit 23; fi
if ( read -t 0.1 -r line <&3 ) 2>/tmp/fd-error; then exit 25; fi
printf scratch > /tmp/result
printf isolated
printf diagnostic >&2
exit 7`
	runner, root, path := commandTestRunner(t, script)
	t.Setenv("NEXUS_COMMAND_TEST_SECRET", "must-not-inherit")
	for _, name := range []string{".env", "credentials.json"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	runner.profiles["probe"] = func() commandProfile {
		p := runner.profiles["probe"]
		p.Args[3] = "[ ! -e '" + outside + "' ] || exit 24\n" + p.Args[3]
		return p
	}()
	result, err := runner.Run(context.Background(), root, "probe")
	if err != nil || result.ExitCode != 7 || result.Stdout != "isolated" || result.Stderr != "diagnostic" {
		t.Fatalf("%+v %v", result, err)
	}
	data, _ := os.ReadFile(filepath.Join(path, "safe.txt"))
	if string(data) != "fixture text\n" {
		t.Fatal("original mutated")
	}
	if _, err := os.Stat(filepath.Join(path, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("original file created")
	}
}

func TestCommandActualLimits(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		cancel       bool
	}{
		{"output", `while :; do printf '01234567890123456789'; printf '01234567890123456789' >&2; done`, false},
		{"timeout", `while :; do :; done`, false},
		{"cancel", `(while :; do :; done) & wait`, true},
		{"scratch", `set -e; x=xxxxxxxxxxxxxxxx; for ((i=0;i<12;i++)); do x=$x$x; done; for ((i=0;i<32;i++)); do printf '%s' "$x"; done > /tmp/large`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner, root, _ := commandTestRunner(t, tc.script)
			p := runner.profiles["probe"]
			p.Timeout = 250 * time.Millisecond
			if tc.name == "scratch" {
				p.Timeout = time.Second
			}
			runner.profiles["probe"] = p
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				time.AfterFunc(80*time.Millisecond, cancel)
			}
			start := time.Now()
			result, err := runner.Run(ctx, root, "probe")
			if time.Since(start) > 2*time.Second {
				t.Fatal("termination exceeded bound")
			}
			switch tc.name {
			case "output":
				if !errors.Is(err, errTooLarge) || !result.Truncated || len(result.Stdout)+len(result.Stderr) != p.OutputBytes {
					t.Fatalf("output lengths=%d/%d result=%+v err=%v", len(result.Stdout), len(result.Stderr), result, err)
				}
			case "timeout":
				if !errors.Is(err, context.DeadlineExceeded) || !result.TimedOut {
					t.Fatalf("%+v %v", result, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || !result.Cancelled {
					t.Fatalf("%+v %v", result, err)
				}
			case "scratch":
				if err != nil || result.TimedOut || result.ExitCode == 0 {
					t.Fatalf("scratch limit not enforced: %+v %v", result, err)
				}
			}
		})
	}
}

// A bind mount in a separate mount namespace proves same-device mount rejection
// without modifying any host mount or repository. The child only reads fixtures.
func TestCommandMountBoundary(t *testing.T) {
	if rootPath := os.Getenv("NEXUS_COMMAND_MOUNT_FIXTURE"); rootPath != "" {
		fd, err := openConfiguredRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fd)
		if _, err := commandReadFile(context.Background(), &workspace{fd: fd}, "mounted.txt"); !errors.Is(err, errForbidden) {
			t.Fatal("bind mount accepted:", err)
		}
		return
	}
	if _, err := trustedProgram(commandTestBwrap); err != nil {
		t.Skipf("bind-mount fixture requires trusted bubblewrap: %v", err)
	}
	root, path := commandTestRoot(t)
	_ = root
	for _, name := range []string{"mounted.txt", "source.txt"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/", "--ro-bind", filepath.Join(path, "source.txt"), filepath.Join(path, "mounted.txt"), "--", binary, "-test.run=^TestCommandMountBoundary$", "-test.v"}
	cmd := exec.Command(commandTestBwrap, args...)
	cmd.Env = append(os.Environ(), "NEXUS_COMMAND_MOUNT_FIXTURE="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "bwrap:") {
			t.Skipf("bind-mount namespace unavailable: %s", out)
		}
		t.Fatalf("bind-mount fixture: %v: %s", err, out)
	}
}

func TestCommandSharedOutputCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &commandOutput{remaining: 13, cancel: cancel}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(stderr bool) {
			defer wg.Done()
			_, _ = (commandStream{output: out, stderr: stderr}).Write([]byte("1234567"))
		}(i%2 == 0)
	}
	wg.Wait()
	if !out.exceeded || out.stdout.Len()+out.stderr.Len() != 13 || ctx.Err() != context.Canceled {
		t.Fatal("shared output cap/cancellation failed")
	}
}
