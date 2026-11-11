package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandAnonymousInputProcessHelper(t *testing.T) {
	if os.Getenv("NEXUS_TEST_ANONYMOUS_INPUT") != "hold" {
		return
	}
	files, _, err := anonymousCommandInputs(context.Background(), []storedCommandInput{{Path: "input.txt", Data: []byte("private captured bytes")}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCommandInputs(files)
	var st syscall.Stat_t
	if syscall.Fstat(int(files[0].Fd()), &st) != nil || st.Nlink != 0 {
		t.Fatal("named input")
	}
	fmt.Println("anonymous-input-held")
	var input [1]byte
	_, _ = os.Stdin.Read(input[:])
}

func TestCommandAnonymousInputHandlesDisappearOnProcessDeath(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestCommandAnonymousInputProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "NEXUS_TEST_ANONYMOUS_INPUT=hold")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "anonymous-input-held"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("anonymous child did not start")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child handshake timeout")
	}
	processFDs := fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid)
	entries, err := os.ReadDir(processFDs)
	if err != nil {
		t.Fatal(err)
	}
	unnamed := false
	for _, entry := range entries {
		target, _ := os.Readlink(filepath.Join(processFDs, entry.Name()))
		unnamed = unnamed || strings.Contains(target, commandAdmissionDirectory()) && strings.HasSuffix(target, " (deleted)")
	}
	if !unnamed {
		t.Fatal("anonymous input not held by child")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, err := os.Stat(processFDs); !os.IsNotExist(err) {
		t.Fatal("dead process retained input descriptors", err)
	}
}

func TestCommandInputsAreUnnamedReadonlyAndClosedOnCancel(t *testing.T) {
	inputs := []storedCommandInput{{Path: "nested/input.txt", Data: []byte("anonymous bytes\n")}}
	files, args, err := anonymousCommandInputs(context.Background(), inputs, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCommandInputs(files)
	if len(files) != 1 || !strings.Contains(strings.Join(args, " "), "--file 3 /workspace/nested/input.txt") {
		t.Fatal("input mount contract", args)
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(files[0].Fd()), &st) != nil || st.Nlink != 0 {
		t.Fatal("input has a persistent directory entry")
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, files[0].Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		t.Fatal("input descriptor is writable")
	}
	data, err := io.ReadAll(files[0])
	if err != nil || string(data) != "anonymous bytes\n" {
		t.Fatal("input bytes", string(data), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if leaked, _, err := anonymousCommandInputs(ctx, inputs, 3); err == nil || len(leaked) != 0 {
		closeCommandInputs(leaked)
		t.Fatal("cancelled anonymous inputs accepted")
	}
}

func TestCommandActualMaximumAnonymousInputsAndDescriptorClosure(t *testing.T) {
	script := `set -eu
[ "$(ulimit -n)" = 64 ]
read -r first < /workspace/inputs/f000.txt
read -r last < /workspace/inputs/f127.txt
[ "$first" = input-0 ] && [ "$last" = input-127 ]
for ((fd=3;fd<132;fd++)); do
  descriptor_error=$( { read -r value <&$fd; } 2>&1 ) || :
  case "$descriptor_error" in *"Bad file descriptor"*) ;; *) exit 24 ;; esac
done
if printf mutation > /workspace/inputs/f000.txt 2>/tmp/denied; then exit 25; fi
if printf extra > /workspace/extra.txt 2>/tmp/denied; then exit 26; fi
printf all-inputs-closed`
	cfg := commandTestConfig(t, script)
	cfg.Profiles[0].Timeout = 5 * time.Second
	cfg.Profiles[0].Files = nil
	root, source := commandTestRoot(t)
	if err := os.Mkdir(filepath.Join(source, "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < commandSnapshotFiles; i++ {
		name := fmt.Sprintf("inputs/f%03d.txt", i)
		cfg.Profiles[0].Files = append(cfg.Profiles[0].Files, name)
		if err := os.WriteFile(filepath.Join(source, name), []byte(fmt.Sprintf("input-%d\n", i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := newCommandRunner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), root, "probe")
	if err != nil || result.ExitCode != 0 || result.Stdout != "all-inputs-closed" {
		t.Fatalf("maximum anonymous inputs: %+v %v", result, err)
	}
}
