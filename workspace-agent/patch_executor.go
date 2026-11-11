package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Not connected to HTTP until generation-bound approvals and dispatcher policy
// are wired. A dedicated private root with no unmanaged writers is mandatory.
type patchExecutor struct {
	sandbox, limit string
	mu             sync.Mutex
	// Tests use an independently built static copy rather than a race-instrumented
	// test binary. Production opens its running executable through /proc/self/exe.
	helperPath string
	fault      func(string) error
}

func newPatchExecutor(sandbox, limit string) (*patchExecutor, error) {
	b, e1 := trustedProgram(sandbox)
	l, e2 := trustedProgram(limit)
	if e1 != nil || e2 != nil {
		return nil, errCommandUnavailable
	}
	return &patchExecutor{sandbox: b, limit: l, helperPath: "/proc/self/exe"}, nil
}

func (e *patchExecutor) start(ctx context.Context, root *workspace, p patchRequest, recoverStage *patchStageIdentity) (*exec.Cmd, *json.Decoder, io.WriteCloser, error) {
	rootFD, err := syscall.Dup(root.fd)
	if err != nil {
		return nil, nil, nil, errForbidden
	}
	rootFile := os.NewFile(uintptr(rootFD), "managed-workspace")
	helper, err := os.Open(e.helperPath)
	if err != nil {
		rootFile.Close()
		return nil, nil, nil, errForbidden
	}
	var stat syscall.Stat_t
	if syscall.Fstat(int(helper.Fd()), &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0022 != 0 {
		rootFile.Close()
		helper.Close()
		return nil, nil, nil, errForbidden
	}
	args := []string{"--as=4294967296", "--cpu=5", "--nofile=64", "--fsize=65536", "--core=0", "--", e.sandbox,
		"--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"}
	// Fixed read-only runtime policy for the trusted Go helper, never project code.
	for _, runtime := range []string{"/nix/store", "/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		if st, err := os.Stat(runtime); err == nil && st.IsDir() {
			args = append(args, "--ro-bind", runtime, runtime)
		}
	}
	args = append(args, "--ro-bind-fd", "4", "/executor", "--bind-fd", "3", "/workspace", "--proc", "/proc", "--dev", "/dev",
		"--chdir", "/workspace", "--remount-ro", "/", "--setenv", "HOME", "/nonexistent", "--setenv", "PATH", "/nonexistent",
		"--setenv", "GOMEMLIMIT", "67108864", "--", "/executor", "--nexus-patch-helper-v1")
	cmd := exec.CommandContext(ctx, e.limit, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/nonexistent"}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{rootFile, helper}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	input, err := cmd.StdinPipe()
	if err != nil {
		rootFile.Close()
		helper.Close()
		return nil, nil, nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		rootFile.Close()
		helper.Close()
		return nil, nil, nil, err
	}
	var rootStat syscall.Stat_t
	if syscall.Fstat(root.fd, &rootStat) != nil {
		input.Close()
		rootFile.Close()
		helper.Close()
		return nil, nil, nil, errForbidden
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		rootFile.Close()
		helper.Close()
		return nil, nil, nil, err
	}
	rootFile.Close()
	helper.Close()
	// HMAC proof and executor credential are never passed to the helper.
	p.Proof = ""
	request := patchHelperRequest{Request: p, Root: patchRootAnchor{Device: uint64(rootStat.Dev), Inode: rootStat.Ino}, Recover: recoverStage}
	if err = json.NewEncoder(input).Encode(request); err != nil {
		input.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, nil, nil, err
	}
	decoder := json.NewDecoder(io.LimitReader(output, 16<<10))
	decoder.DisallowUnknownFields()
	return cmd, decoder, input, nil
}

func (e *patchExecutor) at(name string) error {
	if e.fault != nil {
		return e.fault(name)
	}
	return nil
}

func (e *patchExecutor) execute(ctx context.Context, root *workspace, p patchRequest, journal *patchJournal, authorize func() bool) (patchReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || root == nil || !root.config.ManagedWrite || !root.config.ExclusiveWriter || journal == nil || authorize == nil || !authorize() || p.validate() != nil || p.ExpiresAt <= time.Now().Unix() {
		return patchReceipt{}, errForbidden
	}
	if syscall.Flock(root.fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return patchReceipt{}, errForbidden
	}
	defer syscall.Flock(root.fd, syscall.LOCK_UN)
	// Strict file preflight runs before consumption; the child repeats it inside
	// confinement. Existing roots remain ineligible through the public route.
	if _, err := root.inspectPatchFile(p.Path); err != nil {
		return patchReceipt{}, err
	}
	receipt, dispatch, err := journal.reserve(p)
	if err != nil || !dispatch {
		return receipt, err
	}
	if err = e.at("after_reserve"); err != nil {
		return patchReceipt{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd, decoder, input, err := e.start(runCtx, root, p, nil)
	if err != nil {
		return journal.finishWithoutWrite(p, "failed")
	}
	defer func() { input.Close(); cancel(); _ = cmd.Wait() }()
	var first patchHelperReply
	if decoder.Decode(&first) != nil {
		return patchReceipt{}, errPatchUncertain
	}
	if first.Phase == "conflict" && first.Stage == nil && first.SHA256 == "" {
		return journal.finishWithoutWrite(p, "conflict")
	}
	if first.Phase != "staged" || first.Stage == nil || first.SHA256 != "" || !first.Stage.valid(p.OperationID) {
		return patchReceipt{}, errPatchUncertain
	}
	if err = e.at("before_stage_record"); err != nil {
		return patchReceipt{}, err
	}
	if err = journal.recordStage(p, *first.Stage); err != nil {
		return patchReceipt{}, err
	}
	if err = e.at("after_stage_record"); err != nil {
		return patchReceipt{}, err
	}
	// Current, uncached owner/write policy is checked immediately before the
	// commit permit. Cancellation/expiry before it cannot replace the target.
	if runCtx.Err() != nil || !authorize() || p.ExpiresAt <= time.Now().Unix() {
		return patchReceipt{}, errPatchUncertain
	}
	if err = json.NewEncoder(input).Encode(struct {
		Commit bool `json:"commit"`
	}{true}); err != nil {
		return patchReceipt{}, errPatchUncertain
	}
	var final patchHelperReply
	if decoder.Decode(&final) != nil {
		return patchReceipt{}, errPatchUncertain
	}
	if final.Stage == nil || *final.Stage != *first.Stage {
		return patchReceipt{}, errPatchUncertain
	}
	if err = e.at("after_helper_result"); err != nil {
		return patchReceipt{}, err
	}
	if final.Phase == "applied" && final.SHA256 == p.ReplacementSHA256 {
		return journal.finishMutation(p, "applied", final.SHA256)
	}
	if final.Phase == "conflict" && final.SHA256 == "" {
		// The known stage is retained for identity-based cleanup; conservatively
		// block rather than calling this pre-rename conflict an unconsumed request.
		return journal.finishMutation(p, "uncertain", "")
	}
	return patchReceipt{}, errPatchUncertain
}

func (e *patchExecutor) recover(ctx context.Context, root *workspace, p patchRequest, journal *patchJournal) (patchReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || root == nil || !root.config.ManagedWrite || !root.config.ExclusiveWriter || journal == nil || p.validate() != nil {
		return patchReceipt{}, errForbidden
	}
	if syscall.Flock(root.fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return patchReceipt{}, errForbidden
	}
	defer syscall.Flock(root.fd, syscall.LOCK_UN)
	record, err := journal.executionRecord(p)
	if err != nil {
		return patchReceipt{}, err
	}
	if record.Receipt.Status == "applied" || record.Receipt.Status == "conflict" || record.Receipt.Status == "failed" {
		return record.Receipt, nil
	}
	if record.Stage == nil {
		return patchReceipt{}, errPatchUncertain
	}
	runCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd, decoder, input, err := e.start(runCtx, root, p, record.Stage)
	if err != nil {
		return patchReceipt{}, errPatchUncertain
	}
	input.Close()
	defer func() { cancel(); _ = cmd.Wait() }()
	var reply patchHelperReply
	if decoder.Decode(&reply) != nil || reply.Stage == nil || *reply.Stage != *record.Stage {
		return patchReceipt{}, errPatchUncertain
	}
	if reply.Phase == "applied" && reply.SHA256 == p.ReplacementSHA256 {
		return journal.finishMutation(p, "applied", reply.SHA256)
	}
	if reply.Phase == "failed" && reply.SHA256 == "" {
		return journal.finishMutation(p, "failed", "")
	}
	return patchReceipt{}, errPatchUncertain
}
