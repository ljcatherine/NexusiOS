package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privateAdmissionTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestCommandAdmissionProcessHelper(t *testing.T) {
	mode := os.Getenv("NEXUS_TEST_ADMISSION_MODE")
	if mode == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	file, err := acquireCommandAdmission(ctx, os.Getenv("NEXUS_TEST_ADMISSION_DIRECTORY"))
	if mode == "blocked" {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("independent process entered occupied admission: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if mode == "hold" {
		fmt.Println("admission-held")
		// Parent deliberately kills this process to verify kernel crash release.
		var input [1]byte
		_, _ = os.Stdin.Read(input[:])
	}
}

func admissionProcess(t *testing.T, directory, mode string) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestCommandAdmissionProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "NEXUS_TEST_ADMISSION_MODE="+mode, "NEXUS_TEST_ADMISSION_DIRECTORY="+directory)
	return cmd
}

func TestCommandAdmissionCrossProcessAndCrashRelease(t *testing.T) {
	directory := privateAdmissionTestDirectory(t)
	file, err := acquireCommandAdmission(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	blocked := admissionProcess(t, directory, "blocked")
	if data, err := blocked.CombinedOutput(); err != nil {
		t.Fatalf("cross-process contention: %v %s", err, data)
	}
	file.Close()
	acquire := admissionProcess(t, directory, "acquire")
	if data, err := acquire.CombinedOutput(); err != nil {
		t.Fatalf("lock was not reusable: %v %s", err, data)
	}
	holder := admissionProcess(t, directory, "hold")
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "admission-held"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not acquire lock")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child admission handshake timed out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if unexpected, err := acquireCommandAdmission(ctx, directory); !errors.Is(err, context.DeadlineExceeded) {
		if unexpected != nil {
			unexpected.Close()
		}
		t.Fatalf("child lock was ignored: %v", err)
	}
	if err := holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = holder.Wait()
	recovered, err := acquireCommandAdmission(context.Background(), directory)
	if err != nil {
		t.Fatal("crashed process left admission locked", err)
	}
	recovered.Close()
	info, err := os.Stat(filepath.Join(directory, commandAdmissionFile))
	if err != nil || info.Size() != 0 || info.Mode() != 0600 {
		t.Fatal("lock identity/permissions not preserved", info, err)
	}
}

func TestCommandAdmissionRejectsUnsafeObjects(t *testing.T) {
	for _, shape := range []string{"symlink", "hardlink", "fifo", "directory", "public", "contents", "public-parent"} {
		t.Run(shape, func(t *testing.T) {
			directory := privateAdmissionTestDirectory(t)
			path := filepath.Join(directory, commandAdmissionFile)
			var err error
			switch shape {
			case "symlink":
				err = os.Symlink("missing", path)
			case "hardlink":
				err = os.WriteFile(path, nil, 0600)
				if err == nil {
					err = os.Link(path, filepath.Join(directory, "alias"))
				}
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "public":
				err = os.WriteFile(path, nil, 0644)
			case "contents":
				err = os.WriteFile(path, []byte("must not truncate"), 0600)
			case "public-parent":
				err = os.Chmod(directory, 0755)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			file, err := acquireCommandAdmission(ctx, directory)
			if file != nil {
				file.Close()
			}
			if !errors.Is(err, errCommandUnavailable) {
				t.Fatal("unsafe admission was not refused", err)
			}
			if shape == "contents" {
				data, _ := os.ReadFile(path)
				if string(data) != "must not truncate" {
					t.Fatal("existing lock data was truncated")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	directory := privateAdmissionTestDirectory(t)
	if _, err := acquireCommandAdmission(ctx, directory); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled admission", err)
	}
	if _, err := os.Stat(filepath.Join(directory, commandAdmissionFile)); !os.IsNotExist(err) {
		t.Fatal("already-cancelled admission created a file")
	}
}

func TestCommandActualAdmissionWaitCannotRunProjectCode(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf project-ran")
	file, err := acquireCommandAdmission(context.Background(), commandAdmissionDirectory())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := runner.Run(ctx, root, "probe")
	if !errors.Is(err, context.DeadlineExceeded) || result.Stdout != "" || result.ExitCode != -1 {
		t.Fatalf("occupied admission ran project code: %+v %v", result, err)
	}
	file.Close()
	result, err = runner.Run(context.Background(), root, "probe")
	if err != nil || result.ExitCode != 0 || !strings.Contains(result.Stdout, "project-ran") {
		t.Fatalf("released admission failed: %+v %v", result, err)
	}
}
