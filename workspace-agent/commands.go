package main

// Restricted command foundation only: deliberately not connected to config,
// discovery, tasks or HTTP. Even a fixed profile can execute hostile project code
// from its read-only inputs. Production use MUST first bind explicit human
// approval and current permission to the exact root, profile and input digest.
// Administrators must not allow secret-bearing inputs: text/name checks are not
// secret detection. Trusted runtime packages must contain code, never credentials.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

var errCommandUnavailable = errors.New("restricted command sandbox unavailable")

const (
	commandSnapshotBytes = 1 << 20
	commandSnapshotFiles = 128
	commandOutputBytes   = 64 << 10
)

// All fields are administrator policy, never request fields. RuntimePaths are
// individual immutable Nix store packages (including the executable and prlimit closures),
// not /nix/store itself. Files is an exact allowlist, not a directory traversal.
// MemoryBytes is the aggregate cgroup budget. AddressSpaceBytes separately bounds
// each process's virtual mappings; Go/Swift reserve substantially more than RSS.
type commandProfile struct {
	ID                string
	Executable        string
	Args              []string
	Files             []string
	RuntimePaths      []string
	RuntimeRoot       string
	RuntimeDigest     string
	RuntimeLimitPath  string
	Timeout           time.Duration
	MemoryBytes       uint64
	AddressSpaceBytes uint64
	Processes         uint64
	CPUSeconds        uint64
	ScratchBytes      uint64
	OutputBytes       int
}

type commandRunnerConfig struct {
	Enabled                bool
	SandboxPath, LimitPath string
	ScopePath, ControlPath string
	Profiles               []commandProfile
}

type commandRunner struct {
	sandbox, limit string
	scope, control string
	quarantined    atomic.Bool
	profiles       map[string]commandProfile
	slots          chan struct{}
	// Active operation cancellations stay process-local. The durable journal is
	// authoritative for operation ownership and terminal receipts. Never use an
	// unauthenticated operation ID alone to signal a process or scope.
	activeMu       sync.Mutex
	activeCommands map[string]context.CancelFunc
}

// ExitCode is -1 if no normal exit was observed. Nonzero command exits are
// results, not Go errors. Setup/IO errors fail closed; output on failure remains
// untrusted project output and must never be interpreted as authorization.
type commandResult struct {
	ProfileID           string `json:"profile_id"`
	SnapshotID          string `json:"snapshot_id,omitempty"`
	ProfileVersion      string `json:"profile_version,omitempty"`
	InputDigest         string `json:"input_digest,omitempty"`
	WorkspaceGeneration string `json:"workspace_generation,omitempty"`
	Stdout              string `json:"stdout"`
	Stderr              string `json:"stderr"`
	ExitCode            int    `json:"exit_code"`
	Truncated           bool   `json:"truncated"`
	TimedOut            bool   `json:"timed_out"`
	Cancelled           bool   `json:"cancelled"`
}

func newCommandRunner(cfg commandRunnerConfig) (*commandRunner, error) {
	if !cfg.Enabled {
		return nil, errForbidden
	}
	sandbox, e1 := trustedProgram(cfg.SandboxPath)
	limit, e2 := trustedProgram(cfg.LimitPath)
	scope, e3 := trustedProgram(cfg.ScopePath)
	control, e4 := trustedProgram(cfg.ControlPath)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(cfg.Profiles) == 0 || len(cfg.Profiles) > 32 {
		return nil, errCommandUnavailable
	}
	for _, path := range []string{sandbox, limit, scope, control} {
		if !utf8.ValidString(path) {
			return nil, errForbidden
		}
	}
	if filepath.Base(scope) != "systemd-run" || filepath.Base(control) != "systemctl" {
		return nil, errCommandUnavailable
	}
	r := &commandRunner{sandbox: sandbox, limit: limit, scope: scope, control: control,
		profiles: make(map[string]commandProfile), slots: make(chan struct{}, 1),
		activeCommands: make(map[string]context.CancelFunc)}
	for _, p := range cfg.Profiles {
		if !identifier.MatchString(p.ID) || r.profiles[p.ID].ID != "" {
			return nil, errForbidden
		}
		for _, path := range []string{p.Executable, p.RuntimeRoot, p.RuntimeLimitPath} {
			if !utf8.ValidString(path) {
				return nil, errForbidden
			}
		}
		executable := p.Executable
		if p.RuntimeRoot != "" {
			if len(p.RuntimePaths) != 0 || len(p.RuntimeDigest) != 64 {
				return nil, errForbidden
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			capsule, err := openCommandRuntime(ctx, p.RuntimeRoot)
			cancel()
			if err != nil {
				return nil, errForbidden
			}
			valid := capsule.digest == p.RuntimeDigest && capsule.executable(p.Executable) && capsule.executable(p.RuntimeLimitPath)
			capsule.root.Close()
			if !valid {
				return nil, errForbidden
			}
		} else {
			var err error
			executable, err = trustedProgram(p.Executable)
			if err != nil || p.RuntimeDigest != "" || p.RuntimeLimitPath != "" {
				return nil, errForbidden
			}
			p.Executable = executable
		}
		if !utf8.ValidString(executable) {
			return nil, errForbidden
		}
		if p.AddressSpaceBytes == 0 {
			p.AddressSpaceBytes = 8 << 30
		}
		if p.AddressSpaceBytes < p.MemoryBytes || p.AddressSpaceBytes > 16<<30 || p.MemoryBytes%4096 != 0 {
			return nil, errForbidden
		}
		if p.Timeout <= 0 || p.Timeout > 30*time.Second || p.MemoryBytes < 16<<20 || p.MemoryBytes > 512<<20 || p.Processes < 1 || p.Processes > 32 || p.CPUSeconds < 1 || p.CPUSeconds > 10 || p.ScratchBytes < 4096 || p.ScratchBytes > 16<<20 || p.OutputBytes < 1 || p.OutputBytes > commandOutputBytes {
			return nil, errForbidden
		}
		if len(p.Args) > 64 || len(p.Files) > commandSnapshotFiles || (p.RuntimeRoot == "" && len(p.RuntimePaths) == 0) || len(p.RuntimePaths) > 64 {
			return nil, errForbidden
		}
		total := 0
		for _, arg := range p.Args {
			total += len(arg)
			if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) || total > 8192 {
				return nil, errForbidden
			}
		}
		covered := false
		limitCovered := false
		for _, runtime := range p.RuntimePaths {
			if !utf8.ValidString(runtime) || filepath.Dir(runtime) != "/nix/store" || filepath.Clean(runtime) != runtime {
				return nil, errForbidden
			}
			info, err := os.Lstat(runtime)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0222 != 0 {
				return nil, errForbidden
			}
			if strings.HasPrefix(limit, runtime+"/") {
				limitCovered = true
			}
			if strings.HasPrefix(executable, runtime+"/") {
				covered = true
			}
		}
		if p.RuntimeRoot == "" && (!covered || !limitCovered) {
			return nil, errForbidden
		}
		seen := map[string]bool{}
		for _, file := range p.Files {
			if !utf8.ValidString(file) || !commandInputPath(file) || seen[file] {
				return nil, errForbidden
			}
			seen[file] = true
		}
		// Copy policy slices: changes to the administrator's config cannot race Run.
		p.Args = append([]string(nil), p.Args...)
		p.Files = append([]string(nil), p.Files...)
		p.RuntimePaths = append([]string(nil), p.RuntimePaths...)
		r.profiles[p.ID] = p
	}
	return r, nil
}

func commandInputPath(relative string) bool {
	parts, err := segments(relative, false)
	if err != nil {
		return false
	}
	for _, part := range parts {
		if forbiddenFilename(part) {
			return false
		}
		switch strings.ToLower(part) {
		case "gitconfig", "git-credentials", "config", "proc", "sys", "dev", "etc", "run", "home":
			return false
		}
	}
	return allowedTextFilename(parts[len(parts)-1])
}

// fdinfo's mount ID also catches same-device bind mounts. No dependency on the
// separately owned patch primitives; failure to obtain a mount ID denies input.
func commandMountID(fd int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return "", errForbidden
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:"))
			n, err := strconv.ParseUint(id, 10, 64)
			if err == nil && n > 0 {
				return id, nil
			}
		}
	}
	return "", errForbidden
}

// Read one existing allowed file through pinned, no-follow descriptors. Check
// each component's mount and the file's link count before AND after reading.
func commandReadFile(ctx context.Context, root *workspace, relative string) ([]byte, error) {
	if !commandInputPath(relative) {
		return nil, errForbidden
	}
	dir, err := root.openDir(nil)
	if err != nil {
		return nil, err
	}
	defer func() { dir.Close() }()
	mount, err := commandMountID(int(dir.Fd()))
	if err != nil {
		return nil, err
	}
	parts, _ := segments(relative, false)
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		fd, err := syscall.Openat(int(dir.Fd()), part, flags, 0)
		if err != nil {
			return nil, errForbidden
		}
		next := os.NewFile(uintptr(fd), "command-input")
		dir.Close()
		dir = next
		id, err := commandMountID(fd)
		if err != nil || id != mount {
			return nil, errForbidden
		}
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(int(dir.Fd()), &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || before.Size > maxReadBytes {
		return nil, errForbidden
	}
	data, err := io.ReadAll(io.LimitReader(dir, maxReadBytes+1))
	if err != nil || len(data) > maxReadBytes {
		return nil, errTooLarge
	}
	if syscall.Fstat(int(dir.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errForbidden
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errNotText
	}
	return data, nil
}

type commandOutput struct {
	mu             sync.Mutex
	stdout, stderr bytes.Buffer
	remaining      int
	exceeded       bool
	cancel         context.CancelFunc
}
type commandStream struct {
	output *commandOutput
	stderr bool
}

func (s commandStream) Write(data []byte) (int, error) {
	o := s.output
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(data)
	if n > o.remaining {
		n = o.remaining
		o.exceeded = true
		o.cancel()
	}
	b := &o.stdout
	if s.stderr {
		b = &o.stderr
	}
	b.Write(data[:n])
	o.remaining -= n
	// Consume writes after the cap while cancellation kills the entire sandbox.
	return len(data), nil
}

func (r *commandRunner) sandboxArgs(p commandProfile, inputArgs []string) []string {
	args := []string{fmt.Sprintf("--as=%d", p.AddressSpaceBytes), fmt.Sprintf("--cpu=%d", p.CPUSeconds), "--nofile=256", fmt.Sprintf("--fsize=%d", p.ScratchBytes), "--core=0", "--memlock=0", "--", r.sandbox,
		"--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"}
	for _, runtime := range p.RuntimePaths {
		args = append(args, "--ro-bind", runtime, runtime)
	}
	innerLimit := r.limit
	if p.RuntimeRoot != "" {
		args = append(args, "--ro-bind-fd", "3", "/")
		innerLimit = p.RuntimeLimitPath
	}
	// Only verified captured bytes are copied into the namespace. No original workspace descriptors,
	// metadata, host proc/dev, home, etc, run, sockets or ambient env are inherited.
	args = append(args, inputArgs...)
	args = append(args, "--dir", "/tmp", "--chdir", "/workspace", "--remount-ro", "/",
		"--size", strconv.FormatUint(p.ScratchBytes, 10), "--tmpfs", "/tmp",
		"--setenv", "HOME", "/nonexistent", "--setenv", "PATH", "/nonexistent", "--setenv", "LC_ALL", "C", "--setenv", "TMPDIR", "/tmp", "--", // Apply nproc after namespace creation: the host UID may already have
		// more processes than this sandbox permits. No project code runs first.
		innerLimit, fmt.Sprintf("--nproc=%d", p.Processes), "--nofile=64", "--", p.Executable)
	return append(args, p.Args...)
}

func (r *commandRunner) Run(ctx context.Context, root *workspace, profileID string) (commandResult, error) {
	prepared, err := r.Prepare(ctx, root, profileID)
	if err != nil {
		return commandResult{ProfileID: profileID, ExitCode: -1,
			Cancelled: errors.Is(ctx.Err(), context.Canceled), TimedOut: errors.Is(err, context.DeadlineExceeded)}, err
	}
	defer prepared.Close()
	return r.RunPrepared(ctx, root, prepared)
}

func (r *commandRunner) RunPrepared(ctx context.Context, root *workspace, prepared *preparedCommand) (commandResult, error) {
	return r.runPrepared(ctx, root, prepared, "", false)
}

func (r *commandRunner) runPrepared(ctx context.Context, root *workspace, prepared *preparedCommand, unit string, admissionHeld bool) (commandResult, error) {
	result := commandResult{ExitCode: -1}
	if r == nil || root == nil || prepared == nil {
		return result, errForbidden
	}
	result.ProfileID = prepared.metadata.ProfileID
	result.SnapshotID = prepared.metadata.ID
	result.ProfileVersion = prepared.metadata.Profile
	result.InputDigest = prepared.metadata.InputDigest
	result.WorkspaceGeneration = prepared.metadata.Generation
	if r.quarantined.Load() {
		return result, errCommandUnavailable
	}
	p, ok := r.profiles[result.ProfileID]
	if !ok || !r.preparedMatches(root, prepared, p) || !prepared.consumed.CompareAndSwap(false, true) {
		return result, errForbidden
	}
	runCtx, timeout := context.WithTimeout(ctx, p.Timeout)
	defer timeout()
	markContext := func() {
		result.Cancelled = errors.Is(ctx.Err(), context.Canceled)
		result.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
	}
	var err error
	if !admissionHeld {
		admission, lockErr := acquireCommandAdmission(runCtx, commandAdmissionDirectory())
		if lockErr != nil {
			markContext()
			return result, lockErr
		}
		defer admission.Close()
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-runCtx.Done():
		markContext()
		return result, runCtx.Err()
	}
	if r.quarantined.Load() {
		return result, errCommandUnavailable
	}
	if !r.commandScopesClear(runCtx) {
		markContext()
		if runCtx.Err() != nil {
			return result, runCtx.Err()
		}
		return result, errCommandUnavailable
	}
	var runtimeFile *os.File
	if p.RuntimeRoot != "" {
		capsule, err := openCommandRuntime(runCtx, p.RuntimeRoot)
		if err != nil {
			return result, errForbidden
		}
		defer capsule.root.Close()
		if capsule.digest != p.RuntimeDigest || !capsule.executable(p.Executable) || !capsule.executable(p.RuntimeLimitPath) {
			return result, errForbidden
		}
		// Scope/prlimit preserve this mount descriptor; bubblewrap consumes and
		// closes it before project execution. Never reopen an unverified path.
		runtimeFile = capsule.root
	}
	if !r.preparedMatches(root, prepared, p) {
		return result, errForbidden
	}
	inputs, err := prepared.verifiedInputs(runCtx)
	if err != nil {
		markContext()
		return result, err
	}
	startFD := 3
	if runtimeFile != nil {
		startFD++
	}
	inputFiles, inputArgs, err := anonymousCommandInputs(runCtx, inputs, startFD)
	if err != nil {
		markContext()
		return result, err
	}
	defer closeCommandInputs(inputFiles)
	if !r.preparedMatches(root, prepared, p) {
		return result, errForbidden
	}
	outputCtx, cancel := context.WithCancel(runCtx)
	defer cancel()
	if unit == "" {
		unit, err = commandScopeUnit()
		if err != nil {
			return result, errCommandUnavailable
		}
	} else if !commandScopeName.MatchString(unit) {
		return result, errForbidden
	}
	args := r.commandScopeArgs(unit, p, inputArgs)
	cmd := exec.CommandContext(outputCtx, r.scope, args...)
	cmd.Env = commandScopeEnvironment()
	if runtimeFile != nil {
		cmd.ExtraFiles = []*os.File{runtimeFile}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, inputFiles...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	output := &commandOutput{remaining: p.OutputBytes, cancel: cancel}
	cmd.Stdout = commandStream{output: output}
	cmd.Stderr = commandStream{output: output, stderr: true}
	err = cmd.Run()
	if !r.stopCommandScope(unit) {
		r.quarantined.Store(true)
		return result, errCommandUnavailable
	}
	// bwrap's private PID namespace and die-with-parent also reap descendants
	// that create new sessions; the outer prlimit/bwrap group is killed on cancel.
	result.Stdout = strings.ToValidUTF8(output.stdout.String(), "?")
	result.Stderr = strings.ToValidUTF8(output.stderr.String(), "?")
	result.Truncated = output.exceeded
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	markContext()
	if runCtx.Err() != nil {
		return result, runCtx.Err()
	}
	if result.Truncated {
		return result, errTooLarge
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return result, errCommandUnavailable
	}
	return result, nil
}
