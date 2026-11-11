package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeCapsulesRefuseUntrustedRootsAndCancellation(t *testing.T) {
	for _, path := range []string{"/", "relative", t.TempDir()} {
		if capsule, err := openCommandRuntime(context.Background(), path); err == nil {
			capsule.root.Close()
			t.Fatal("untrusted runtime accepted", path)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if path := os.Getenv("NEXUS_COMMAND_RUNTIME_FIXTURE"); path != "" {
		_, err := openCommandRuntime(ctx, path)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled runtime validation", err)
		}
	}
}

func TestActualRuntimeCapsuleIsVerifiedAndMountedAsGuestRoot(t *testing.T) {
	path := os.Getenv("NEXUS_COMMAND_RUNTIME_FIXTURE")
	if path == "" {
		t.Skip("requires the immutable command-runtime.nix fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capsule, err := openCommandRuntime(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	digest := capsule.digest
	if !capsule.executable("/bin/bash") || !capsule.executable("/usr/bin/prlimit") || capsule.executable("/../bin/bash") || capsule.executable("/bin/missing") {
		capsule.root.Close()
		t.Fatal("invalid guest executable boundary")
	}
	capsule.root.Close()
	cfg := commandTestConfig(t, "exit 0")
	p := cfg.Profiles[0]
	p.Executable = "/bin/bash"
	p.RuntimePaths = nil
	p.RuntimeRoot = path
	p.RuntimeDigest = digest
	p.RuntimeLimitPath = "/usr/bin/prlimit"
	p.Timeout = 5 * time.Second
	p.Args = []string{"--noprofile", "--norc", "-c", `set -eu
read -r line < /workspace/safe.txt
[ "$line" = 'capsule input' ]
[ ! -e /etc/passwd ]
[ ! -e /home ]
[ ! -e /proc ]
[ ! -e /run ]
descriptor_error=$( { read -r value <&3; } 2>&1 ) || :
case "$descriptor_error" in *"Bad file descriptor"*) ;; *) exit 23 ;; esac
descriptor_error=$( { read -r value <&4; } 2>&1 ) || :
case "$descriptor_error" in *"Bad file descriptor"*) ;; *) exit 24 ;; esac
if printf mutation > /workspace/safe.txt 2>/tmp/denied; then exit 19; fi
printf artifact > /tmp/result
printf capsule-ok`}
	cfg.Profiles = []commandProfile{p}
	runner, err := newCommandRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root, source := commandTestRoot(t)
	if err := os.WriteFile(filepath.Join(source, "safe.txt"), []byte("capsule input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), root, "probe")
	if err != nil || result.ExitCode != 0 || result.Stdout != "capsule-ok" {
		t.Fatalf("guest capsule: %+v %v", result, err)
	}
	actual, _ := os.ReadFile(filepath.Join(source, "safe.txt"))
	if string(actual) != "capsule input\n" {
		t.Fatal("original input mutated")
	}
	p.RuntimeDigest = strings.Repeat("0", 64)
	cfg.Profiles = []commandProfile{p}
	if _, err := newCommandRunner(cfg); err == nil {
		t.Fatal("incorrect runtime digest accepted")
	}
	p.RuntimeDigest = digest
	p.Executable = "/bin/../bin/bash"
	cfg.Profiles = []commandProfile{p}
	if _, err := newCommandRunner(cfg); err == nil {
		t.Fatal("unclean guest path accepted")
	}
}
