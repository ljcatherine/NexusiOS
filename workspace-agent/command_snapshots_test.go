package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommandActualPersistentSnapshotUsesCapturedBytesAfterReopen(t *testing.T) {
	runner, root, source := commandTestRunner(t, `read -r line < /workspace/safe.txt; printf '%s' "$line"`)
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	metadata := prepared.Metadata()
	p := commandRequestFixture(prepared)
	directory := privateAdmissionTestDirectory(t)
	store, err := openCommandSnapshots(directory)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openCommandSnapshots(directory); err == nil {
		second.close()
		t.Fatal("second snapshot writer allowed")
	}
	if err := store.Save(context.Background(), p.Host, p.Owner, prepared); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), p.Host, p.Owner, prepared); err != nil {
		t.Fatal("exact save retry", err)
	}
	prepared.Close()
	store.close()
	if err := os.WriteFile(filepath.Join(source, "safe.txt"), []byte("new working tree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err = openCommandSnapshots(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if bad, err := store.Load(context.Background(), p.Host, strings.Repeat("f", 64), metadata.ID); !errors.Is(err, errForbidden) {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("owner isolation", err)
	}
	if bad, err := store.Load(context.Background(), "debian", p.Owner, metadata.ID); !errors.Is(err, errForbidden) {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("host isolation", err)
	}
	restored, err := store.Load(context.Background(), p.Host, p.Owner, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	receipt, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, p.Host, root, restored, p)
	if err != nil || receipt.Result == nil || receipt.Result.ExitCode != 0 || receipt.Result.Stdout != "fixture text" {
		t.Fatalf("restored execution: %+v %v", receipt, err)
	}
	again, err := store.Load(context.Background(), p.Host, p.Owner, metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	receipt, err = runner.ExecuteRecorded(context.Background(), journal, commandTestToken, p.Host, root, again, p)
	if err != nil || again.consumed.Load() || receipt.Result == nil || receipt.Result.Stdout != "fixture text" {
		t.Fatal("loading bypassed consumption", receipt, err)
	}
	count, err := store.cleanup(context.Background(), time.Now().Add(6*time.Minute).Unix())
	if err != nil || count != 0 {
		t.Fatal("expiry cleanup", count, err)
	}
	if _, found, err := journal.lookup(p); err != nil || !found {
		t.Fatal("snapshot cleanup erased consumption", err)
	}
}

func TestCommandPersistentSnapshotCapacityAndCancellation(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "exit 0")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	store, err := openCommandSnapshots(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	owner := strings.Repeat("b", 64)
	for index := 0; index < maxStoredCommandSnapshots; index++ {
		prepared.metadata.ID = strings.Repeat(string(rune('a'+index)), 32)
		// IDs remain hexadecimal: a-f and digits for the final two entries.
		if index >= 6 {
			prepared.metadata.ID = strings.Repeat(string(rune('0'+index-6)), 32)
		}
		if err := store.Save(context.Background(), "nixos", owner, prepared); err != nil {
			t.Fatal("capacity fill", index, err)
		}
	}
	prepared.metadata.ID = strings.Repeat("2", 32)
	if err := store.Save(context.Background(), "nixos", owner, prepared); !errors.Is(err, errTooLarge) {
		t.Fatal("unbounded snapshots", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Load(ctx, "nixos", owner, prepared.metadata.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled load", err)
	}
	if err := store.Save(ctx, "nixos", owner, prepared); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled save", err)
	}
}

func TestCommandSnapshotPublicationCrashBoundaries(t *testing.T) {
	for _, boundary := range []string{"before_write", "before_publish", "after_publish", "after_directory_sync"} {
		t.Run(boundary, func(t *testing.T) {
			runner, root, _ := commandTestRunner(t, "exit 0")
			prepared, err := runner.Prepare(context.Background(), root, "probe")
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			directory := privateAdmissionTestDirectory(t)
			store, err := openCommandSnapshots(directory)
			if err != nil {
				t.Fatal(err)
			}
			store.fault = func(point string) error {
				if point == boundary {
					return errors.New("injected publication interruption")
				}
				return nil
			}
			owner := strings.Repeat("b", 64)
			if err := store.Save(context.Background(), "nixos", owner, prepared); !errors.Is(err, errCommandSnapshots) {
				t.Fatal("publication fault", err)
			}
			if _, err := store.Load(context.Background(), "nixos", owner, prepared.Metadata().ID); !errors.Is(err, errCommandSnapshots) {
				t.Fatal("ambiguous live handle resumed", err)
			}
			store.close()
			store, err = openCommandSnapshots(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			loaded, err := store.Load(context.Background(), "nixos", owner, prepared.Metadata().ID)
			if boundary == "before_write" || boundary == "before_publish" {
				if err == nil {
					loaded.Close()
					t.Fatal("unpublished stage became visible")
				}
			} else {
				if err != nil {
					t.Fatal("published record lost", err)
				}
				loaded.Close()
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".pending") {
					t.Fatal("unpublished staging residue")
				}
			}
		})
	}
}

func TestCommandSnapshotsRejectDamagedAndUnsafeRecords(t *testing.T) {
	for _, damage := range []string{"checksum", "path", "public", "symlink", "unknown"} {
		t.Run(damage, func(t *testing.T) {
			runner, root, _ := commandTestRunner(t, "exit 0")
			prepared, err := runner.Prepare(context.Background(), root, "probe")
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			directory := privateAdmissionTestDirectory(t)
			store, err := openCommandSnapshots(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(context.Background(), "nixos", strings.Repeat("b", 64), prepared); err != nil {
				t.Fatal(err)
			}
			store.close()
			path := filepath.Join(directory, prepared.Metadata().ID+".json")
			switch damage {
			case "checksum":
				data, _ := os.ReadFile(path)
				data = []byte(strings.Replace(string(data), "nixos", "debian", 1))
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "path":
				data, _ := os.ReadFile(path)
				var record storedCommandSnapshot
				if err := json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				record.Files[0].Path = "../escape"
				record.Metadata.Inputs[0].Path = "../escape"
				manifest, _ := json.Marshal(record.Metadata.Inputs)
				record.Metadata.InputDigest = hashText("nexus.command.inputs.v1\x00" + string(manifest))
				record.Checksum = record.checksum()
				data, _ = json.Marshal(record)
				if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(directory, "unrecognized"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := openCommandSnapshots(directory); err == nil {
				reopened.close()
				t.Fatal("unsafe snapshot state reopened")
			}
			if damage == "unknown" {
				data, _ := os.ReadFile(filepath.Join(directory, "unrecognized"))
				if string(data) != "preserve" {
					t.Fatal("unknown state deleted")
				}
			}
		})
	}
}
