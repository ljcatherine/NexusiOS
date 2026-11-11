package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommandScopeHelperRefusesProjectCodeOutsideVerifiedScope(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-run")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--nexus-command-scope-v1", "nexus-command-"+strings.Repeat("a", 32)+".scope",
		"134217728", "16", "/bin/sh", "-c", "touch '"+marker+"'")
	cmd.Env = commandScopeEnvironment()
	data, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || !strings.Contains(string(data), "aggregate command isolation unavailable") {
		t.Fatalf("unverified scope executed: %v %s", err, data)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("project code ran before cgroup verification")
	}
}

func TestCommandActualAggregateMemoryAndDescendantCleanup(t *testing.T) {
	// Four fixed workers exceed the shared 128 MiB budget while each remains
	// below its independent virtual-address cap. This is not a fork bomb.
	runner, root, _ := commandTestRunner(t, `for child in 1 2 3 4; do
 ( x=xxxxxxxxxxxxxxxx; for ((i=0;i<22;i++)); do x=$x$x; done; while :; do :; done ) &
done
wait`)
	// Retain the failed unit for its authoritative Result. Polling memory.events
	// races --collect: a group OOM can kill every task and remove the cgroup
	// before the observer reaches it. All launch/isolation arguments stay equal.
	unit, err := commandScopeUnit()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, action := range []string{"stop", "reset-failed"} {
			cmd := exec.CommandContext(ctx, runner.control, "--user", action, unit)
			cmd.Env = commandScopeEnvironment()
			_ = cmd.Run()
		}
	}
	t.Cleanup(cleanup)
	p := runner.profiles["probe"]
	inputs, _, _, err := captureCommandInputs(context.Background(), root, p.Files)
	if err != nil {
		t.Fatal(err)
	}
	inputFiles, inputArgs, err := anonymousCommandInputs(context.Background(), inputs, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCommandInputs(inputFiles)
	args := runner.commandScopeArgs(unit, p, inputArgs)
	retained := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--collect" {
			retained = append(retained, arg)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runner.scope, retained...)
	cmd.ExtraFiles = inputFiles
	cmd.Env = commandScopeEnvironment()
	data, runErr := cmd.CombinedOutput()
	if ctx.Err() != nil || runErr == nil {
		t.Fatalf("aggregate workload did not fail within limits: %v %s", runErr, data)
	}
	show := exec.CommandContext(ctx, runner.control, "--user", "show", unit, "--property=Result", "--value")
	show.Env = commandScopeEnvironment()
	result, err := show.Output()
	if err != nil || strings.TrimSpace(string(result)) != "oom-kill" {
		t.Fatalf("aggregate memory enforcement: result=%q error=%v workload=%v %s", result, err, runErr, data)
	}
	cleanup()
	if !runner.commandScopesClear(context.Background()) {
		t.Fatal("descendants/scope not confirmed stopped")
	}
}

func TestCommandAlreadyCancelledNeverStartsProjectCode(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf must-not-run")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runner.Run(ctx, root, "probe")
	if !errors.Is(err, context.Canceled) || !result.Cancelled || result.Stdout != "" {
		t.Fatalf("cancelled admission: %+v %v", result, err)
	}
}

func TestCommandScopeHelperRefusesMismatchedKernelBudgets(t *testing.T) {
	cfg := commandTestConfig(t, "exit 0")
	scope, err := trustedProgram(cfg.ScopePath)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []string{"memory", "pids", "cpu"} {
		t.Run(mismatch, func(t *testing.T) {
			unit, err := commandScopeUnit()
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "must-not-run")
			memory, pids, quota := "134217728", "16", "100%"
			if mismatch == "memory" {
				memory = "67108864"
			}
			if mismatch == "pids" {
				pids = "12"
			}
			if mismatch == "cpu" {
				quota = "200%"
			}
			cmd := exec.Command(scope, "--user", "--scope", "--quiet", "--collect", "--no-ask-password",
				"--unit="+unit, "--property=MemoryMax="+memory, "--property=MemorySwapMax=0",
				"--property=TasksMax="+pids, "--property=CPUQuota="+quota, "--property=RuntimeMaxSec=2",
				binary, "--nexus-command-scope-v1", unit, "134217728", "16", "/bin/sh", "-c", "touch '"+marker+"'")
			cmd.Env = commandScopeEnvironment()
			data, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(data), "aggregate command isolation unavailable") {
				t.Fatalf("mismatched scope accepted: %v %s", err, data)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("project code ran under incorrect limits")
			}
		})
	}
}
