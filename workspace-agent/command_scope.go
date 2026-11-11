package main

// No project code runs until this fixed helper has verified its actual kernel
// cgroup. The user manager is trusted infrastructure, never an agent tool.
import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var commandScopeName = regexp.MustCompile(`^nexus-command-[0-9a-f]{32}\.scope$`)

func commandScopeUnit() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "nexus-command-" + hex.EncodeToString(nonce[:]) + ".scope", nil
}

func commandScopeEnvironment() []string {
	runtime := fmt.Sprintf("/run/user/%d", os.Getuid())
	return []string{"LC_ALL=C", "PATH=/nonexistent", "HOME=/nonexistent", "GOMAXPROCS=2",
		"XDG_RUNTIME_DIR=" + runtime, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus"}
}

func (r *commandRunner) commandScopeArgs(unit string, p commandProfile, inputArgs []string) []string {
	args := []string{"--user", "--scope", "--quiet", "--collect", "--no-ask-password", "--expand-environment=no",
		"--unit=" + unit, fmt.Sprintf("--property=MemoryMax=%d", p.MemoryBytes),
		"--property=MemorySwapMax=0", fmt.Sprintf("--property=TasksMax=%d", p.Processes),
		fmt.Sprintf("--property=RuntimeMaxSec=%.6f", p.Timeout.Seconds()), "--property=CPUQuota=100%",
		// Pin the running agent inode, not a mutable installation path.
		fmt.Sprintf("/proc/%d/exe", os.Getpid()), "--nexus-command-scope-v1", unit,
		strconv.FormatUint(p.MemoryBytes, 10), strconv.FormatUint(p.Processes, 10), r.limit}
	return append(args, r.sandboxArgs(p, inputArgs)...)
}

func (r *commandRunner) commandScopesClear(ctx context.Context) bool {
	check, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(check, r.control, "--user", "list-units", "--all", "--no-pager", "--no-legend", "nexus-command-*.scope")
	cmd.Env = commandScopeEnvironment()
	output := &commandOutput{remaining: 4096, cancel: cancel}
	cmd.Stdout = commandStream{output: output}
	cmd.WaitDelay = 250 * time.Millisecond
	err := cmd.Run()
	return err == nil && !output.exceeded && strings.TrimSpace(output.stdout.String()) == ""
}

func (r *commandRunner) stopCommandScope(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.control, "--user", "--no-ask-password", "stop", unit)
	cmd.Env = commandScopeEnvironment()
	_ = cmd.Run() // a completed --collect scope is already absent
	return r.commandScopesClear(context.Background())
}

func commandScopeVerified(unit string, memory, processes uint64) bool {
	if !commandScopeName.MatchString(unit) || memory < 16<<20 || memory > 512<<20 || processes < 1 || processes > 32 {
		return false
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, "0::/") || strings.Contains(line, "\n") {
		return false
	}
	path := strings.TrimPrefix(line, "0::")
	if filepath.Clean(path) != path || filepath.Base(path) != unit {
		return false
	}
	root := "/sys/fs/cgroup" + path
	for file, value := range map[string]string{"memory.max": strconv.FormatUint(memory, 10),
		"memory.swap.max": "0", "pids.max": strconv.FormatUint(processes, 10)} {
		actual, err := os.ReadFile(filepath.Join(root, file))
		if err != nil || strings.TrimSpace(string(actual)) != value {
			return false
		}
	}
	quota, err := os.ReadFile(filepath.Join(root, "cpu.max"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(quota))
	if len(fields) != 2 {
		return false
	}
	q, e1 := strconv.ParseUint(fields[0], 10, 64)
	period, e2 := strconv.ParseUint(fields[1], 10, 64)
	return e1 == nil && e2 == nil && q > 0 && period > 0 && q <= period
}

func init() {
	if len(os.Args) < 2 || os.Args[1] != "--nexus-command-scope-v1" {
		return
	}
	if len(os.Args) < 7 {
		os.Exit(125)
	}
	memory, e1 := strconv.ParseUint(os.Args[3], 10, 64)
	processes, e2 := strconv.ParseUint(os.Args[4], 10, 64)
	if e1 != nil || e2 != nil || !commandScopeVerified(os.Args[2], memory, processes) {
		_, _ = os.Stderr.WriteString("aggregate command isolation unavailable\n")
		os.Exit(125)
	}
	// No ambient bus/environment or descriptor enters the project namespace.
	if syscall.Exec(os.Args[5], os.Args[5:], []string{"LC_ALL=C", "PATH=/nonexistent"}) != nil {
		os.Exit(125)
	}
}
