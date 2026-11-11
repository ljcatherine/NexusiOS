package main

// Internal authenticated-dispatch contract only, not a review or shell API.
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

var errCommandBinding = errors.New("invalid command execution binding")
var errCommandConflict = errors.New("command identifiers already consumed")
var errCommandUncertain = errors.New("command receipt unresolved; reconcile without replay")

type commandRequest struct {
	Host           string `json:"host"`
	WorkspaceID    string `json:"workspace_id"`
	Generation     string `json:"workspace_generation"`
	Owner          string `json:"owner"`
	ApprovalID     string `json:"approval_id"`
	Digest         string `json:"digest"`
	OperationID    string `json:"operation_id"`
	SnapshotID     string `json:"snapshot_id"`
	ProfileID      string `json:"profile_id"`
	ProfileVersion string `json:"profile_version"`
	InputDigest    string `json:"input_digest"`
	ExpiresAt      int64  `json:"expires_at"`
	Proof          string `json:"proof,omitempty"`
}

func (p commandRequest) binding() []byte {
	data := []byte("nexus.workspace.command.v1\x00")
	for _, value := range []string{p.Host, p.WorkspaceID, p.Generation, p.Owner, p.ApprovalID, p.Digest, p.OperationID, p.SnapshotID, p.ProfileID, p.ProfileVersion, p.InputDigest, strconv.FormatInt(p.ExpiresAt, 10)} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		data = append(data, length[:]...)
		data = append(data, value...)
	}
	return data
}

func (p commandRequest) validate() error {
	if !identifier.MatchString(p.Host) || !identifier.MatchString(p.WorkspaceID) || !identifier.MatchString(p.ProfileID) ||
		!hex64.MatchString(p.Generation) || !hex64.MatchString(p.Owner) || !hex64.MatchString(p.Digest) ||
		!hex64.MatchString(p.ProfileVersion) || !hex64.MatchString(p.InputDigest) || !hex32.MatchString(p.ApprovalID) ||
		!hex32.MatchString(p.OperationID) || !hex32.MatchString(p.SnapshotID) || p.ExpiresAt <= 0 {
		return errCommandBinding
	}
	return nil
}

func (p commandRequest) requestDigest() string { return hashText(string(p.binding())) }
func (p commandRequest) sign(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(p.binding())
	return hex.EncodeToString(mac.Sum(nil))
}
func (p commandRequest) verifySignature(token string) error {
	if !validExecutorToken(token) || p.validate() != nil || !hex64.MatchString(p.Proof) || !hmac.Equal([]byte(p.Proof), []byte(p.sign(token))) {
		return errCommandBinding
	}
	return nil
}

type commandReceipt struct {
	Request commandRequest `json:"request"` // Proof is always removed before storage.
	Status  string         `json:"status"`
	Result  *commandResult `json:"result,omitempty"`
	Failure string         `json:"failure,omitempty"`
}

// HMAC only authenticates the trusted signer. That signer must separately verify
// a human decision, current execute grants and atomically consume the approval.
func (r *commandRunner) ExecuteRecorded(ctx context.Context, journal *commandJournal, token, host string, root *workspace, prepared *preparedCommand, p commandRequest) (commandReceipt, error) {
	if r == nil || journal == nil || root == nil || p.Host != host || p.WorkspaceID != root.config.ID || p.Generation != root.generation || p.verifySignature(token) != nil {
		return commandReceipt{}, errCommandBinding
	}
	if receipt, found, err := journal.lookup(p); found || err != nil {
		return receipt, err
	}
	if prepared == nil || p.ExpiresAt <= time.Now().Unix() || p.ExpiresAt > time.Now().Unix()+300 {
		return commandReceipt{}, errCommandBinding
	}
	m := prepared.Metadata()
	if p.SnapshotID != m.ID || p.ProfileID != m.ProfileID || p.ProfileVersion != m.Profile || p.InputDigest != m.InputDigest || p.ExpiresAt > m.ExpiresAt {
		return commandReceipt{}, errCommandBinding
	}
	profile, ok := r.profiles[p.ProfileID]
	if !ok || !r.preparedMatches(root, prepared, profile) {
		return commandReceipt{}, errCommandBinding
	}
	ctx, cancel := context.WithTimeout(ctx, profile.Timeout)
	defer cancel()
	ctx, cancelLease := context.WithDeadline(ctx, time.Unix(p.ExpiresAt, 0))
	defer cancelLease()
	admission, err := acquireCommandAdmission(ctx, commandAdmissionDirectory())
	if err != nil {
		return commandReceipt{}, err
	}
	defer admission.Close()
	if p.ExpiresAt <= time.Now().Unix() || !r.preparedMatches(root, prepared, profile) {
		return commandReceipt{}, errCommandBinding
	}
	receipt, dispatch, err := journal.claim(p)
	if err != nil || !dispatch {
		return receipt, err
	}
	// Register only after the journal's durable signed claim. A cancellation
	// request is authorized against that claim before reaching this map, and
	// cannot affect an unrelated process or change the approved input binding.
	activeContext, activeCancel := context.WithCancel(ctx)
	r.activeMu.Lock()
	if r.activeCommands == nil {
		r.activeCommands = make(map[string]context.CancelFunc)
	}
	r.activeCommands[p.OperationID] = activeCancel
	r.activeMu.Unlock()
	defer func() {
		r.activeMu.Lock()
		delete(r.activeCommands, p.OperationID)
		r.activeMu.Unlock()
		activeCancel()
	}()
	result, runErr := r.runPrepared(activeContext, root, prepared, "nexus-command-"+p.OperationID+".scope", true)
	failure := ""
	if runErr != nil {
		failure = "execution_failed"
	} // Never persist internal paths/errors.
	if r.quarantined.Load() {
		// Unknown cleanup cannot be recorded as a safely completed job.
		return receipt, errCommandUncertain
	}
	return journal.finish(p, "completed", &result, failure)
}

// CancelRecorded requests cancellation of *only* a currently running,
// already-durably-claimed signed operation. It never creates a new claim,
// replays code, or declares success. The original execution thread retains
// responsibility for supervisor cleanup and the terminal receipt. On restart
// the active map is empty: the caller must reconcile the original host claim.
func (r *commandRunner) CancelRecorded(journal *commandJournal, token, host string, p commandRequest) (commandReceipt, bool, error) {
	if r == nil || journal == nil || p.Host != host || p.verifySignature(token) != nil {
		return commandReceipt{}, false, errCommandBinding
	}
	receipt, found, err := journal.lookup(p)
	if err != nil {
		return commandReceipt{}, false, err
	}
	if !found {
		return commandReceipt{}, false, errCommandUncertain
	}
	if receipt.Status != "claimed" {
		return receipt, false, nil
	}
	r.activeMu.Lock()
	cancel := r.activeCommands[p.OperationID]
	if cancel != nil {
		cancel()
	}
	r.activeMu.Unlock()
	if cancel == nil {
		return receipt, false, errCommandUncertain
	}
	return receipt, true, nil
}

// Explicit receipt reconciliation never launches or implicitly cancels code.
// A pending job with no remaining scopes has an unknown exit, not a success.
func (r *commandRunner) ReconcileRecorded(ctx context.Context, journal *commandJournal, token, host string, p commandRequest) (commandReceipt, error) {
	if r == nil || journal == nil || p.Host != host || p.verifySignature(token) != nil {
		return commandReceipt{}, errCommandBinding
	}
	receipt, found, err := journal.lookup(p)
	if err != nil {
		return receipt, err
	}
	if !found && p.ExpiresAt > time.Now().Unix() {
		return commandReceipt{}, errCommandUncertain
	}
	if found && receipt.Status != "claimed" {
		return receipt, nil
	}
	lock, err := acquireCommandAdmission(ctx, commandAdmissionDirectory())
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	// Execution holds admission from durable claim through terminal receipt.
	// Re-read after acquiring it so reconciliation cannot race a pending launch.
	receipt, found, err = journal.lookup(p)
	if err != nil {
		return receipt, err
	}
	if found && receipt.Status != "claimed" {
		return receipt, nil
	}
	if !r.commandScopesClear(ctx) {
		return receipt, errCommandUncertain
	}
	if !found {
		// An expired signed request that never arrived must also become terminal
		// without replay. A fresh missing request stays pending, not cancelled.
		if p.ExpiresAt > time.Now().Unix() {
			return commandReceipt{}, errCommandUncertain
		}
		if _, _, err := journal.claim(p); err != nil {
			return commandReceipt{}, err
		}
	}
	return journal.finish(p, "interrupted", nil, "exit_unknown")
}
