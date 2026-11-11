package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCommandActualRunsCapturedInputsAndCannotRepeat(t *testing.T) {
	runner, root, source := commandTestRunner(t, "read -r line < /workspace/safe.txt; printf '%s' \"$line\"")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	metadata := prepared.Metadata()
	hash := sha256.Sum256([]byte("fixture text\n"))
	if len(metadata.ID) != 32 || !hex64.MatchString(metadata.Profile) || !hex64.MatchString(metadata.InputDigest) ||
		metadata.WorkspaceID != "code" || metadata.Generation != root.generation || len(metadata.Inputs) != 1 ||
		metadata.Inputs[0].SHA256 != hex.EncodeToString(hash[:]) || metadata.Inputs[0].Size != 13 ||
		metadata.ExpiresAt <= time.Now().Unix() || metadata.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		t.Fatalf("captured metadata invalid: %+v", metadata)
	}
	metadata.Inputs[0].Path = "mutated-client-copy"
	if prepared.Metadata().Inputs[0].Path != "safe.txt" {
		t.Fatal("metadata aliases private manifest")
	}
	if err := os.WriteFile(filepath.Join(source, "safe.txt"), []byte("changed after review\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunPrepared(context.Background(), root, prepared)
	if err != nil || result.ExitCode != 0 || result.Stdout != "fixture text" ||
		result.SnapshotID != metadata.ID || result.InputDigest != metadata.InputDigest ||
		result.ProfileVersion != metadata.Profile || result.WorkspaceGeneration != root.generation {
		t.Fatalf("job did not run/report exact captured inputs: %+v %v", result, err)
	}
	if _, err := runner.RunPrepared(context.Background(), root, prepared); !errors.Is(err, errForbidden) {
		t.Fatal("prepared command executed twice", err)
	}
	current, _ := os.ReadFile(filepath.Join(source, "safe.txt"))
	if string(current) != "changed after review\n" {
		t.Fatal("execution changed current source")
	}
}

func TestCommandPreparedRefusesChangedBindingsAndBytes(t *testing.T) {
	for _, change := range []string{"generation", "identity", "profile", "expiry", "bytes", "path", "missing"} {
		t.Run(change, func(t *testing.T) {
			runner, root, _ := commandTestRunner(t, "printf must-not-run")
			prepared, err := runner.Prepare(context.Background(), root, "probe")
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			switch change {
			case "generation":
				root.generation = strings.Repeat("b", 64)
			case "identity":
				root, _ = commandTestRoot(t)
			case "profile":
				p := runner.profiles["probe"]
				p.OutputBytes++
				runner.profiles["probe"] = p
			case "expiry":
				prepared.metadata.ExpiresAt = time.Now().Unix()
			case "bytes":
				prepared.files[0].Data = []byte("tampered\n")
			case "path":
				prepared.files[0].Path = "../escape"
			case "missing":
				prepared.Close()
			}
			result, err := runner.RunPrepared(context.Background(), root, prepared)
			if err == nil || result.ExitCode != -1 || result.Stdout != "" {
				t.Fatalf("changed binding ran: %+v %v", result, err)
			}
		})
	}
}

func TestCommandPreparationRequiresGenerationAndHonorsCancellation(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "exit 0")
	root.generation = ""
	if _, err := runner.Prepare(context.Background(), root, "probe"); !errors.Is(err, errForbidden) {
		t.Fatal("unversioned root accepted", err)
	}
	root.generation = strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Prepare(ctx, root, "probe"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled capture", err)
	}
}

func TestCommandActualPreparedConcurrentAttemptIsSingleUse(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf once")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	type outcome struct {
		result commandResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := runner.RunPrepared(context.Background(), root, prepared)
			outcomes <- outcome{result, err}
		}()
	}
	workers.Wait()
	close(outcomes)
	succeeded, refused := 0, 0
	for outcome := range outcomes {
		if outcome.err == nil && outcome.result.ExitCode == 0 && outcome.result.Stdout == "once" {
			succeeded++
		} else if errors.Is(outcome.err, errForbidden) && outcome.result.ExitCode == -1 && outcome.result.Stdout == "" {
			refused++
		} else {
			t.Fatalf("unexpected concurrent result: %+v", outcome)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("attempts: executed=%d refused=%d", succeeded, refused)
	}
}
