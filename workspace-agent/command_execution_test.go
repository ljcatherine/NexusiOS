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

const commandTestToken = "command-executor-fixture-not-a-real-credential"

func commandRequestFixture(prepared *preparedCommand) commandRequest {
	m := prepared.Metadata()
	p := commandRequest{Host: "nixos", WorkspaceID: m.WorkspaceID, Generation: m.Generation, Owner: strings.Repeat("b", 64), ApprovalID: strings.Repeat("c", 32), Digest: strings.Repeat("d", 64), OperationID: strings.Repeat("e", 32), SnapshotID: m.ID, ProfileID: m.ProfileID, ProfileVersion: m.Profile, InputDigest: m.InputDigest, ExpiresAt: m.ExpiresAt}
	p.Proof = p.sign(commandTestToken)
	return p
}

func TestCommandActualRecordedReceiptSurvivesRestartWithoutReplay(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf recorded")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	directory := privateAdmissionTestDirectory(t)
	journal, err := openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openCommandJournal(directory); err == nil {
		second.close()
		t.Fatal("second journal writer allowed")
	}
	p := commandRequestFixture(prepared)
	receipt, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p)
	if err != nil || receipt.Status != "completed" || receipt.Result == nil || receipt.Result.ExitCode != 0 || receipt.Result.Stdout != "recorded" {
		t.Fatalf("execution: %+v %v", receipt, err)
	}
	receipt.Result.Stdout = "mutated reader"
	journal.close()
	journal, err = openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	prepared.Close() // No snapshot remains that could accidentally launch again.
	receipt, err = runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, nil, p)
	if err != nil || receipt.Result == nil || receipt.Result.Stdout != "recorded" || journal.count != 2 {
		t.Fatalf("lost-reply recovery: %+v %v", receipt, err)
	}
	changed := p
	changed.OperationID = strings.Repeat("f", 32)
	changed.Proof = changed.sign(commandTestToken)
	if _, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, nil, changed); !errors.Is(err, errCommandConflict) {
		t.Fatal("approval reuse", err)
	}
	changed = p
	changed.ApprovalID = strings.Repeat("f", 32)
	changed.Proof = changed.sign(commandTestToken)
	if _, _, err := journal.lookup(changed); !errors.Is(err, errCommandConflict) {
		t.Fatal("operation/snapshot reuse", err)
	}
	changed = p
	changed.Owner = strings.Repeat("f", 64)
	if _, err := runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", changed); !errors.Is(err, errCommandBinding) {
		t.Fatal("unsigned owner change", err)
	}
}

func TestCommandRecordedRemoteCancelRequiresSignedOriginalAndReturnsTerminalReceipt(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "while :; do :; done")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	p := commandRequestFixture(prepared)
	completed := make(chan commandReceipt, 1)
	failed := make(chan error, 1)
	go func() {
		receipt, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p)
		completed <- receipt
		failed <- err
	}()
	defer func() {
		runner.activeMu.Lock()
		if cancel := runner.activeCommands[p.OperationID]; cancel != nil {
			cancel()
		}
		runner.activeMu.Unlock()
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runner.activeMu.Lock()
		ready := runner.activeCommands[p.OperationID] != nil
		runner.activeMu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recorded operation never entered active cancellation window")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, tc := range []struct {
		name string
		edit func(*commandRequest)
	}{
		{"wrong owner", func(value *commandRequest) { value.Owner = strings.Repeat("f", 64) }},
		{"wrong approval", func(value *commandRequest) { value.ApprovalID = strings.Repeat("f", 32) }},
		{"wrong operation", func(value *commandRequest) { value.OperationID = strings.Repeat("f", 32) }},
		{"bad proof", func(value *commandRequest) { value.Proof = strings.Repeat("0", 64) }},
	} {
		changed := p
		tc.edit(&changed)
		if _, requested, err := runner.CancelRecorded(journal, commandTestToken, "nixos", changed); err == nil || requested {
			t.Fatalf("%s cancelled signed operation: %v", tc.name, err)
		}
	}
	if _, requested, err := (&commandRunner{}).CancelRecorded(journal, commandTestToken, "nixos", p); err == nil || requested {
		t.Fatal("another process without active command cancelled operation", err)
	}
	if receipt, requested, err := runner.CancelRecorded(journal, commandTestToken, "nixos", p); err != nil || !requested || receipt.Status != "claimed" {
		t.Fatalf("owner cancellation did not find claimed operation: %+v requested=%v err=%v", receipt, requested, err)
	}
	select {
	case receipt := <-completed:
		if err := <-failed; err != nil || receipt.Status != "completed" || receipt.Result == nil || !receipt.Result.Cancelled || receipt.Result.TimedOut {
			t.Fatalf("cancelled result should be a bounded real terminal receipt: %+v %v", receipt, err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("remote cancellation failed to stop the bounded command")
	}
	if receipt, requested, err := runner.CancelRecorded(journal, commandTestToken, "nixos", p); err != nil || requested || receipt.Result == nil || !receipt.Result.Cancelled {
		t.Fatalf("late repeat must not execute/cancel anything: %+v requested=%v err=%v", receipt, requested, err)
	}
	if receipt, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, nil, p); err != nil || !receipt.Result.Cancelled || journal.count != 2 {
		t.Fatalf("cancelled operation was replayed: %+v %v", receipt, err)
	}
}

func TestCommandRecordedUnfinishedClaimOnlyReconcilesAsInterrupted(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf must-not-run")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	p := commandRequestFixture(prepared)
	directory := privateAdmissionTestDirectory(t)
	journal, err := openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, dispatch, err := journal.claim(p); err != nil || !dispatch {
		t.Fatal("claim", dispatch, err)
	}
	journal.close()
	journal, err = openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	receipt, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p)
	if err != nil || receipt.Status != "claimed" || prepared.consumed.Load() {
		t.Fatal("unfinished claim replayed", receipt, err)
	}
	receipt, err = runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", p)
	if err != nil || receipt.Status != "interrupted" || receipt.Result != nil || receipt.Failure != "exit_unknown" {
		t.Fatal("unknown exit invented", receipt, err)
	}
	if _, dispatch, err := journal.claim(p); err != nil || dispatch {
		t.Fatal("interrupted operation replayed", dispatch, err)
	}
}

func TestCommandJournalDurabilityFailureCannotExecuteOrReplay(t *testing.T) {
	for _, boundary := range []string{"before_append", "before_fsync", "after_fsync"} {
		t.Run(boundary, func(t *testing.T) {
			runner, root, _ := commandTestRunner(t, "printf must-not-run")
			prepared, err := runner.Prepare(context.Background(), root, "probe")
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
			if err != nil {
				t.Fatal(err)
			}
			defer journal.close()
			journal.fault = func(point string) error {
				if point == boundary {
					return errors.New("injected")
				}
				return nil
			}
			p := commandRequestFixture(prepared)
			if _, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p); !errors.Is(err, errCommandJournal) || prepared.consumed.Load() {
				t.Fatal("code ran before durable claim", err)
			}
			journal.fault = nil
			if _, _, err := journal.claim(p); !errors.Is(err, errCommandJournal) {
				t.Fatal("poisoned ledger resumed", err)
			}
		})
	}
}

func TestCommandJournalRejectsTornAndAlteredRecords(t *testing.T) {
	for _, corruption := range []string{"torn", "checksum", "permissions"} {
		t.Run(corruption, func(t *testing.T) {
			directory := privateAdmissionTestDirectory(t)
			journal, err := openCommandJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			m := commandPreparation{ID: strings.Repeat("a", 32), WorkspaceID: "code", Generation: strings.Repeat("a", 64), ProfileID: "probe", Profile: strings.Repeat("a", 64), InputDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute).Unix()}
			p := commandRequestFixture(&preparedCommand{metadata: m})
			if _, _, err := journal.claim(p); err != nil {
				t.Fatal(err)
			}
			journal.close()
			path := filepath.Join(directory, "commands.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "torn":
				data = data[:len(data)-1]
			case "checksum":
				data = []byte(strings.Replace(string(data), "claimed", "CLAIMED", 1))
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if corruption != "permissions" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := openCommandJournal(directory); err == nil {
				reopened.close()
				t.Fatal("unsafe ledger reopened")
			}
		})
	}
}

func TestCommandActualRecordedCancellationAndReconcileCannotRaceLaunch(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "while :; do :; done")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	p := commandRequestFixture(prepared)
	claimed := make(chan struct{})
	permit := make(chan struct{})
	journal.fault = func(boundary string) error {
		if boundary == "after_fsync" {
			select {
			case <-claimed:
			default:
				close(claimed)
				<-permit
			}
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		receipt commandReceipt
		err     error
	}
	finished := make(chan outcome, 1)
	go func() {
		receipt, err := runner.ExecuteRecorded(ctx, journal, commandTestToken, "nixos", root, prepared, p)
		finished <- outcome{receipt, err}
	}()
	select {
	case <-claimed:
	case <-time.After(3 * time.Second):
		close(permit)
		t.Fatal("claim did not persist")
	}
	// Another executor's reconciliation must wait through the durable claim /
	// pre-launch gap, not turn it terminal while code can still start afterward.
	reconciled := make(chan outcome, 1)
	go func() {
		receipt, err := runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", p)
		reconciled <- outcome{receipt, err}
	}()
	cancel()
	close(permit)
	select {
	case result := <-finished:
		if result.err != nil || result.receipt.Status != "completed" || result.receipt.Result == nil || !result.receipt.Result.Cancelled || result.receipt.Result.Stdout != "" {
			t.Fatalf("cancelled recorded operation: %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled execution did not finish")
	}
	select {
	case result := <-reconciled:
		if result.err != nil || result.receipt.Status != "completed" || result.receipt.Result == nil || !result.receipt.Result.Cancelled {
			t.Fatalf("reconcile raced launch: %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reconciliation did not finish")
	}
}

func TestCommandJournalLostTerminalReceiptReconcilesWithoutReplay(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf ran-once")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	directory := privateAdmissionTestDirectory(t)
	journal, err := openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	journal.fault = func(boundary string) error {
		if boundary == "after_fsync" {
			writes++
			if writes == 2 {
				return errors.New("lost terminal acknowledgement")
			}
		}
		return nil
	}
	p := commandRequestFixture(prepared)
	if _, err := runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p); !errors.Is(err, errCommandJournal) {
		t.Fatal("terminal fault", err)
	}
	journal.close()
	journal, err = openCommandJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	receipt, err := runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", p)
	if err != nil || receipt.Status != "completed" || receipt.Result == nil || receipt.Result.Stdout != "ran-once" || journal.count != 2 {
		t.Fatal("terminal receipt not recovered", receipt, err)
	}
}

func TestCommandReconcileMissingDeliveryWaitsForLeaseAndNeverExecutes(t *testing.T) {
	runner, root, _ := commandTestRunner(t, "printf must-not-run")
	prepared, err := runner.Prepare(context.Background(), root, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	journal, err := openCommandJournal(privateAdmissionTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.close()
	p := commandRequestFixture(prepared)
	if _, err := runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", p); !errors.Is(err, errCommandUncertain) || journal.count != 0 {
		t.Fatal("fresh delivery cancelled", err, journal.count)
	}
	p.ExpiresAt = time.Now().Unix() - 1
	p.Proof = p.sign(commandTestToken)
	receipt, err := runner.ReconcileRecorded(context.Background(), journal, commandTestToken, "nixos", p)
	if err != nil || receipt.Status != "interrupted" || receipt.Result != nil || journal.count != 2 {
		t.Fatal("missing expired delivery not resolved", receipt, err)
	}
	receipt, err = runner.ExecuteRecorded(context.Background(), journal, commandTestToken, "nixos", root, prepared, p)
	if err != nil || receipt.Status != "interrupted" || prepared.consumed.Load() {
		t.Fatal("reconciled operation ran", receipt, err)
	}
}
