package main

// Captured inputs are not approval. The future command dispatcher must bind
// human authorization and its durable once-only claim to this exact metadata.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

type commandInput struct {
	Path   string `json:"path"`
	Size   int    `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

type commandPreparation struct {
	ID          string         `json:"snapshot_id"`
	WorkspaceID string         `json:"workspace_id"`
	Generation  string         `json:"workspace_generation"`
	ProfileID   string         `json:"profile_id"`
	Profile     string         `json:"profile_version"`
	InputDigest string         `json:"input_digest"`
	Inputs      []commandInput `json:"inputs"`
	ExpiresAt   int64          `json:"expires_at"`
}

type preparedCommand struct {
	metadata commandPreparation
	files    []storedCommandInput
	mu       sync.Mutex
	closed   atomic.Bool
	device   uint64
	inode    uint64
	consumed atomic.Bool
}

func (p *preparedCommand) Metadata() commandPreparation {
	copy := p.metadata
	copy.Inputs = append([]commandInput(nil), copy.Inputs...)
	return copy
}

func (p *preparedCommand) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed.Store(true)
	p.files = nil
}

func (p *preparedCommand) copyInputs(ctx context.Context) ([]storedCommandInput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil, errForbidden
	}
	files := make([]storedCommandInput, 0, len(p.files))
	for _, file := range p.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		files = append(files, storedCommandInput{file.Path, append([]byte{}, file.Data...)})
	}
	return files, nil
}

func (r *commandRunner) profileVersion(p commandProfile) string {
	// Fixed Go struct field order and integer nanosecond duration. No maps,
	// environment, caller arguments or runtime measurements enter this binding.
	data, _ := json.Marshal(struct {
		Schema                         string
		Profile                        commandProfile
		Sandbox, Limit, Scope, Control string
	}{"nexus.command.profile.v2", p, r.sandbox, r.limit, r.scope, r.control})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func commandInputManifest(files []storedCommandInput) ([]commandInput, string, error) {
	if len(files) > commandSnapshotFiles {
		return nil, "", errTooLarge
	}
	inputs := make([]commandInput, 0, len(files))
	total := 0
	previous := ""
	for index, file := range files {
		if !utf8.ValidString(file.Path) || !commandInputPath(file.Path) || (index > 0 && file.Path <= previous) ||
			len(file.Data) > maxReadBytes || !utf8.Valid(file.Data) || bytes.IndexByte(file.Data, 0) >= 0 {
			return nil, "", errForbidden
		}
		total += len(file.Data)
		if total > commandSnapshotBytes {
			return nil, "", errTooLarge
		}
		inputs = append(inputs, commandInput{file.Path, len(file.Data), hashText(string(file.Data))})
		previous = file.Path
	}
	encoded, _ := json.Marshal(inputs)
	return inputs, hashText("nexus.command.inputs.v1\x00" + string(encoded)), nil
}

func captureCommandInputs(ctx context.Context, root *workspace, paths []string) ([]storedCommandInput, []commandInput, string, error) {
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	files := make([]storedCommandInput, 0, len(ordered))
	total := 0
	for _, path := range ordered {
		data, err := commandReadFile(ctx, root, path)
		if err != nil {
			return nil, nil, "", err
		}
		total += len(data)
		if total > commandSnapshotBytes {
			return nil, nil, "", errTooLarge
		}
		files = append(files, storedCommandInput{path, data})
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, "", err
	}
	inputs, digest, err := commandInputManifest(files)
	return files, inputs, digest, err
}

func (r *commandRunner) Prepare(ctx context.Context, root *workspace, profileID string) (*preparedCommand, error) {
	if r == nil || root == nil || !hex64.MatchString(root.generation) || !identifier.MatchString(root.config.ID) {
		return nil, errForbidden
	}
	p, ok := r.profiles[profileID]
	if !ok {
		return nil, errForbidden
	}
	if r.quarantined.Load() {
		return nil, errCommandUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	var st syscall.Stat_t
	if syscall.Fstat(root.fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, errForbidden
	}
	files, inputs, digest, err := captureCommandInputs(ctx, root, p.Files)
	if err != nil {
		return nil, err
	}
	id, err := commandScopeUnit()
	if err != nil {
		return nil, errCommandUnavailable
	}
	// Reuse the cryptographically random nonce format, not the scope prefix.
	id = id[len("nexus-command-") : len("nexus-command-")+32]
	return &preparedCommand{metadata: commandPreparation{
		ID: id, WorkspaceID: root.config.ID, Generation: root.generation,
		ProfileID: profileID, Profile: r.profileVersion(p), InputDigest: digest,
		Inputs: inputs, ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}, files: files, device: uint64(st.Dev), inode: st.Ino}, nil
}

func (r *commandRunner) preparedMatches(root *workspace, prepared *preparedCommand, p commandProfile) bool {
	var st syscall.Stat_t
	return prepared != nil && !prepared.closed.Load() && prepared.metadata.ExpiresAt > time.Now().Unix() &&
		prepared.metadata.Profile == r.profileVersion(p) &&
		prepared.metadata.WorkspaceID == root.config.ID && prepared.metadata.Generation == root.generation &&
		hex64.MatchString(root.generation) && syscall.Fstat(root.fd, &st) == nil &&
		uint64(st.Dev) == prepared.device && st.Ino == prepared.inode
}

func (p *preparedCommand) verifiedInputs(ctx context.Context) ([]storedCommandInput, error) {
	files, err := p.copyInputs(ctx)
	if err != nil {
		return nil, err
	}
	inputs, digest, err := commandInputManifest(files)
	if err != nil {
		return nil, err
	}
	expected, _ := json.Marshal(p.metadata.Inputs)
	actual, _ := json.Marshal(inputs)
	if digest != p.metadata.InputDigest || !bytes.Equal(expected, actual) {
		return nil, errForbidden
	}
	return files, nil
}
