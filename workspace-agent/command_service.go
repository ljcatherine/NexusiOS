package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type commandProfileLimits struct {
	TimeoutMS         int64  `json:"timeout_ms"`
	MemoryBytes       uint64 `json:"memory_bytes"`
	AddressSpaceBytes uint64 `json:"address_space_bytes"`
	Processes         uint64 `json:"processes"`
	CPUSeconds        uint64 `json:"cpu_seconds"`
	ScratchBytes      uint64 `json:"scratch_bytes"`
	OutputBytes       int    `json:"output_bytes"`
}
type commandInvocation struct {
	Executable string               `json:"executable"`
	Arguments  []string             `json:"arguments"`
	Limits     commandProfileLimits `json:"limits"`
}
type commandProfilePolicy struct {
	ID               string               `json:"id"`
	Executable       string               `json:"executable"`
	Arguments        []string             `json:"arguments"`
	Files            []string             `json:"files"`
	RuntimePaths     []string             `json:"runtime_paths,omitempty"`
	RuntimeRoot      string               `json:"runtime_root,omitempty"`
	RuntimeDigest    string               `json:"runtime_digest,omitempty"`
	RuntimeLimitPath string               `json:"runtime_limit_path,omitempty"`
	Limits           commandProfileLimits `json:"limits"`
}

func (p commandProfilePolicy) profile() commandProfile {
	return commandProfile{ID: p.ID, Executable: p.Executable, Args: p.Arguments, Files: p.Files, RuntimePaths: p.RuntimePaths, RuntimeRoot: p.RuntimeRoot, RuntimeDigest: p.RuntimeDigest, RuntimeLimitPath: p.RuntimeLimitPath, Timeout: time.Duration(p.Limits.TimeoutMS) * time.Millisecond, MemoryBytes: p.Limits.MemoryBytes, AddressSpaceBytes: p.Limits.AddressSpaceBytes, Processes: p.Limits.Processes, CPUSeconds: p.Limits.CPUSeconds, ScratchBytes: p.Limits.ScratchBytes, OutputBytes: p.Limits.OutputBytes}
}
func commandInvocationFor(p commandProfile) commandInvocation {
	return commandInvocation{p.Executable, append([]string{}, p.Args...), commandProfileLimits{p.Timeout.Milliseconds(), p.MemoryBytes, p.AddressSpaceBytes, p.Processes, p.CPUSeconds, p.ScratchBytes, p.OutputBytes}}
}

func (c *config) commandEnv() error {
	c.CommandExecutorToken = os.Getenv("NEXUS_WORKSPACE_COMMAND_EXECUTOR_TOKEN")
	c.CommandStateDir = os.Getenv("NEXUS_WORKSPACE_COMMAND_STATE_DIR")
	c.CommandSnapshotDir = os.Getenv("NEXUS_WORKSPACE_COMMAND_SNAPSHOT_DIR")
	c.ScopePath = os.Getenv("NEXUS_WORKSPACE_SYSTEMD_RUN_EXECUTABLE")
	c.ControlPath = os.Getenv("NEXUS_WORKSPACE_SYSTEMCTL_EXECUTABLE")
	raw := os.Getenv("NEXUS_WORKSPACE_COMMAND_PROFILES_JSON")
	if raw != "" {
		if len(raw) > 64<<10 {
			return errors.New("command profile policy exceeds 64 KiB")
		}
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&c.CommandProfiles) != nil || decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid command profile policy")
		}
	}
	return nil
}
func (c config) validateCommands() error {
	anyRoot := false
	for _, root := range c.Roots {
		anyRoot = anyRoot || len(root.CommandProfiles) > 0
	}
	enabled := len(c.CommandProfiles) > 0
	if !enabled && !anyRoot && c.CommandExecutorToken == "" && c.CommandStateDir == "" && c.CommandSnapshotDir == "" && c.ScopePath == "" && c.ControlPath == "" {
		return nil
	}
	if !enabled || !anyRoot || len(c.CommandProfiles) > 32 || !validExecutorToken(c.CommandExecutorToken) || c.CommandExecutorToken == c.Token || c.CommandExecutorToken == c.ExecutorToken {
		return errors.New("commands require profiles, root opt-in and separate executor credentials")
	}
	for _, ch := range c.CommandExecutorToken {
		if ch <= 32 || ch >= 127 {
			return errors.New("command credential must be private printable ASCII")
		}
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("command execution requires a loopback listener")
	}
	if c.SandboxPath == "" || c.LimitPath == "" || c.ScopePath == "" || c.ControlPath == "" {
		return errors.New("commands require explicit trusted sandbox and supervisor executables")
	}
	paths := []string{c.CommandStateDir, c.CommandSnapshotDir}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return errors.New("commands require separate absolute persistent state directories")
		}
	}
	overlap := func(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") }
	if overlap(paths[0], paths[1]) {
		return errors.New("command state and snapshot directories must be disjoint")
	}
	for _, path := range paths {
		if c.PatchStateDir != "" && overlap(path, c.PatchStateDir) {
			return errors.New("command state must be separate from patch state")
		}
		for _, root := range c.Roots {
			if overlap(path, root.Path) {
				return errors.New("command state must be outside all workspaces")
			}
		}
	}
	profiles := map[string]bool{}
	for _, p := range c.CommandProfiles {
		if !identifier.MatchString(p.ID) || profiles[p.ID] || p.Limits.TimeoutMS < 1 || p.Limits.TimeoutMS > 30000 {
			return errors.New("invalid command profile identity or deadline")
		}
		profiles[p.ID] = true
	}
	for _, root := range c.Roots {
		seen := map[string]bool{}
		if len(root.CommandProfiles) > 32 {
			return errors.New("too many root command profiles")
		}
		for _, id := range root.CommandProfiles {
			if !profiles[id] || seen[id] {
				return errors.New("root command profiles must be distinct configured identifiers")
			}
			seen[id] = true
		}
	}
	return nil
}
func (s *server) setupCommands(c config) error {
	if len(c.CommandProfiles) == 0 {
		return nil
	}
	cfg := commandRunnerConfig{Enabled: true, SandboxPath: c.SandboxPath, LimitPath: c.LimitPath, ScopePath: c.ScopePath, ControlPath: c.ControlPath}
	for _, p := range c.CommandProfiles {
		cfg.Profiles = append(cfg.Profiles, p.profile())
	}
	var err error
	s.commands, err = newCommandRunner(cfg)
	if err != nil {
		return err
	}
	s.commandJournal, err = openCommandJournal(c.CommandStateDir)
	if err != nil {
		return err
	}
	if err = s.commandJournal.bindRoots(c.Host, s.roots); err != nil {
		return err
	}
	s.commandSnapshots, err = openCommandSnapshots(c.CommandSnapshotDir)
	if err != nil {
		return err
	}
	s.commandToken = c.CommandExecutorToken
	s.commandRequests = make(chan struct{}, 4)
	return nil
}
func (s *server) commandRoot(w http.ResponseWriter, r *http.Request) *workspace {
	root := s.roots[r.PathValue("id")]
	if root == nil || len(root.config.CommandProfiles) == 0 {
		sendError(w, 404, "command_workspace_unavailable")
		return nil
	}
	return root
}
func (root *workspace) allowsCommand(id string) bool {
	for _, allowed := range root.config.CommandProfiles {
		if allowed == id {
			return true
		}
	}
	return false
}
func (s *server) commandAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || s.commandToken == "" {
			sendError(w, 401, "command_authentication_required")
			return
		}
		fields := strings.Fields(values[0])
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			sendError(w, 401, "command_authentication_required")
			return
		}
		actual, expected := sha256.Sum256([]byte(fields[1])), sha256.Sum256([]byte(s.commandToken))
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			sendError(w, 401, "command_authentication_required")
			return
		}
		next(w, r)
	})
}
func (s *server) boundedCommand(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.commandRequests <- struct{}{}:
			defer func() { <-s.commandRequests }()
			next(w, r)
		default:
			sendError(w, 429, "command_request_capacity")
		}
	}
}
func (s *server) registerCommands(mux *http.ServeMux) {
	if s.commands == nil {
		return
	}
	mux.Handle("GET /v1/workspaces/{id}/commands/profiles", s.authorize(http.HandlerFunc(s.commandProfiles)))
	mux.Handle("POST /v1/workspaces/{id}/commands/prepare", s.authorize(s.boundedCommand(s.prepareCommand)))
	mux.Handle("POST /v1/workspaces/{id}/commands/execute", s.commandAuth(s.boundedCommand(s.executeCommand)))
	mux.Handle("POST /v1/workspaces/{id}/commands/receipts/{operation_id}/reconcile", s.commandAuth(s.boundedCommand(s.reconcileCommand)))
	mux.Handle("POST /v1/workspaces/{id}/commands/receipts/{operation_id}/cancel", s.commandAuth(s.boundedCommand(s.cancelCommand)))
}
func decodeCommandBody(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.URL.RawQuery != "" || len(r.TransferEncoding) != 0 || r.ContentLength <= 0 || r.ContentLength > 4096 || len(r.Header.Values("Content-Type")) != 1 || strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		sendError(w, 400, "invalid_command_request")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		sendError(w, 400, "invalid_command_request")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		sendError(w, 400, "invalid_command_request")
		return false
	}
	return true
}
func (s *server) commandProfiles(w http.ResponseWriter, r *http.Request) {
	root := s.commandRoot(w, r)
	if root == nil {
		return
	}
	query := r.URL.Query()
	if len(query) != 1 || len(query["host"]) != 1 || r.ContentLength > 0 || len(r.TransferEncoding) > 0 || !s.requireHost(w, query.Get("host")) {
		if query.Get("host") == s.host {
			sendError(w, 400, "invalid_command_query")
		}
		return
	}
	profiles := []any{}
	for _, id := range root.config.CommandProfiles {
		p := s.commands.profiles[id]
		profiles = append(profiles, map[string]any{"id": id, "version": s.commands.profileVersion(p), "invocation": commandInvocationFor(p)})
	}
	sendJSON(w, 200, map[string]any{"host": s.host, "workspace_id": root.config.ID, "profiles": profiles})
}
func (s *server) prepareCommand(w http.ResponseWriter, r *http.Request) {
	root := s.commandRoot(w, r)
	if root == nil {
		return
	}
	var p struct {
		Host        string `json:"host"`
		WorkspaceID string `json:"workspace_id"`
		Owner       string `json:"owner"`
		ProfileID   string `json:"profile_id"`
		SnapshotID  string `json:"snapshot_id"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if !decodeCommandBody(w, r, &p) {
		return
	}
	if !s.requireHost(w, p.Host) {
		return
	}
	if p.WorkspaceID != root.config.ID || !root.allowsCommand(p.ProfileID) || !hex64.MatchString(p.Owner) || !hex32.MatchString(p.SnapshotID) || p.ExpiresAt <= time.Now().Unix() || p.ExpiresAt > time.Now().Unix()+300 {
		sendError(w, 400, "invalid_command_preparation")
		return
	}
	captured, err := s.commandSnapshots.Load(r.Context(), s.host, p.Owner, p.SnapshotID)
	if err == nil {
		defer captured.Close()
		m := captured.Metadata()
		if m.WorkspaceID != root.config.ID || m.Generation != root.generation || m.ProfileID != p.ProfileID || m.ExpiresAt != p.ExpiresAt || m.Profile != s.commands.profileVersion(s.commands.profiles[p.ProfileID]) {
			sendError(w, 409, "command_preparation_changed")
			return
		}
	} else {
		if errors.Is(err, errForbidden) {
			sendError(w, 403, "command_preparation_owner_mismatch")
			return
		}
		captured, err = s.commands.Prepare(r.Context(), root, p.ProfileID)
		if err != nil {
			sendError(w, 503, "command_preparation_unavailable")
			return
		}
		defer captured.Close()
		captured.metadata.ID = p.SnapshotID
		captured.metadata.ExpiresAt = p.ExpiresAt
		if err = s.commandSnapshots.Save(r.Context(), s.host, p.Owner, captured); err != nil {
			sendError(w, 503, "command_preparation_unavailable")
			return
		}
	}
	snapshot := struct {
		commandPreparation
		Invocation commandInvocation `json:"invocation"`
	}{captured.Metadata(), commandInvocationFor(s.commands.profiles[p.ProfileID])}
	sendJSON(w, 200, map[string]any{"host": s.host, "owner": p.Owner, "snapshot": snapshot})
}
func (s *server) readCommandRequest(w http.ResponseWriter, r *http.Request) (commandRequest, *workspace, bool) {
	var p commandRequest
	if !decodeCommandBody(w, r, &p) {
		return p, nil, false
	}
	if p.verifySignature(s.commandToken) != nil {
		sendError(w, 400, "invalid_command_binding")
		return p, nil, false
	}
	if !s.requireHost(w, p.Host) {
		return p, nil, false
	}
	root := s.commandRoot(w, r)
	if root == nil {
		return p, nil, false
	}
	if p.WorkspaceID != root.config.ID || !root.allowsCommand(p.ProfileID) {
		sendError(w, 403, "command_workspace_denied")
		return p, nil, false
	}
	return p, root, true
}
func (s *server) executeCommand(w http.ResponseWriter, r *http.Request) {
	p, root, ok := s.readCommandRequest(w, r)
	if !ok {
		return
	}
	var captured *preparedCommand
	if _, found, err := s.commandJournal.lookup(p); err != nil {
		sendError(w, 409, "command_execution_identity_conflict")
		return
	} else if !found {
		captured, err = s.commandSnapshots.Load(r.Context(), s.host, p.Owner, p.SnapshotID)
		if err != nil {
			sendError(w, 409, "command_snapshot_unavailable")
			return
		}
		defer captured.Close()
	}
	receipt, err := s.commands.ExecuteRecorded(r.Context(), s.commandJournal, s.commandToken, s.host, root, captured, p)
	if err != nil {
		sendError(w, 409, "command_execution_unavailable_reconcile_original")
		return
	}
	sendJSON(w, 200, receipt)
}
func (s *server) reconcileCommand(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.readCommandRequest(w, r)
	if !ok {
		return
	}
	if r.PathValue("operation_id") != p.OperationID {
		sendError(w, 400, "command_operation_mismatch")
		return
	}
	receipt, err := s.commands.ReconcileRecorded(r.Context(), s.commandJournal, s.commandToken, s.host, p)
	if err != nil {
		sendError(w, 409, "command_receipt_unresolved")
		return
	}
	sendJSON(w, 200, receipt)
}

func (s *server) cancelCommand(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.readCommandRequest(w, r)
	if !ok {
		return
	}
	if r.PathValue("operation_id") != p.OperationID {
		sendError(w, 400, "command_operation_mismatch")
		return
	}
	receipt, requested, err := s.commands.CancelRecorded(s.commandJournal, s.commandToken, s.host, p)
	if err != nil {
		// A missing active operation after crash is not proof it was never run.
		sendError(w, 409, "command_cancellation_unknown_reconcile_original")
		return
	}
	sendJSON(w, 200, map[string]any{"host": s.host, "workspace_id": p.WorkspaceID,
		"operation_id": p.OperationID, "cancel_requested": requested, "receipt_status": receipt.Status})
}
