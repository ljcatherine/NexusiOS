package main

// This store persists captured inputs, never authorization or command claims.
// The independent command journal is mandatory for every privileged execution.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const maxStoredCommandSnapshots = 8
const maxStoredCommandSnapshotBytes = 2 << 20

var errCommandSnapshots = errors.New("prepared command storage unavailable")

type storedCommandInput struct {
	Path string `json:"path"`
	Data []byte `json:"data"` // Base64 bounds disk usage independently of JSON escaping.
}
type storedCommandSnapshot struct {
	Host     string               `json:"host"`
	Owner    string               `json:"owner"`
	Metadata commandPreparation   `json:"metadata"`
	Device   uint64               `json:"device"`
	Inode    uint64               `json:"inode"`
	Files    []storedCommandInput `json:"files"`
	Checksum string               `json:"checksum"`
}

func (r storedCommandSnapshot) checksum() string {
	r.Checksum = ""
	data, _ := json.Marshal(r)
	return hashText(string(data))
}
func (r storedCommandSnapshot) valid() bool {
	m := r.Metadata
	if !identifier.MatchString(r.Host) || !hex64.MatchString(r.Owner) || !hex32.MatchString(m.ID) || !identifier.MatchString(m.WorkspaceID) || !hex64.MatchString(m.Generation) || !identifier.MatchString(m.ProfileID) || !hex64.MatchString(m.Profile) || !hex64.MatchString(m.InputDigest) || m.ExpiresAt <= 0 || r.Inode == 0 || len(r.Files) > commandSnapshotFiles || len(r.Files) != len(m.Inputs) {
		return false
	}
	total := 0
	previous := ""
	for i, file := range r.Files {
		if !utf8.ValidString(file.Path) || !commandInputPath(file.Path) || (i > 0 && file.Path <= previous) || len(file.Data) > maxReadBytes || !utf8.Valid(file.Data) || bytes.IndexByte(file.Data, 0) >= 0 {
			return false
		}
		total += len(file.Data)
		if total > commandSnapshotBytes {
			return false
		}
		input := m.Inputs[i]
		if input.Path != file.Path || input.Size != len(file.Data) || input.SHA256 != hashText(string(file.Data)) {
			return false
		}
		previous = file.Path
	}
	encoded, _ := json.Marshal(m.Inputs)
	return m.InputDigest == hashText("nexus.command.inputs.v1\x00"+string(encoded)) && r.Checksum == r.checksum()
}

type commandSnapshotStore struct {
	mu       sync.Mutex
	dir      *os.File
	poisoned bool
	fault    func(string) error // Test-only crash/durability boundary.
}

func openCommandSnapshots(directory string) (*commandSnapshotStore, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errCommandSnapshots
	}
	fd, err := openConfiguredRoot(directory)
	if err != nil {
		return nil, errCommandSnapshots
	}
	dir := os.NewFile(uintptr(fd), "command-snapshots")
	var fs syscall.Statfs_t
	if privateOwned(fd, true) != nil || syscall.Fstatfs(fd, &fs) != nil || (fs.Type != 0xef53 && fs.Type != 0x58465342 && fs.Type != 0x9123683e) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		dir.Close()
		return nil, errCommandSnapshots
	}
	s := &commandSnapshotStore{dir: dir}
	if _, err := s.cleanup(context.Background(), time.Now().Unix()); err != nil {
		dir.Close()
		return nil, err
	}
	// Establish publication durability when reopening a valid record after an
	// acknowledgement/directory-sync failure in the prior process.
	if dir.Sync() != nil {
		dir.Close()
		return nil, errCommandSnapshots
	}
	return s, nil
}
func (s *commandSnapshotStore) close() { s.dir.Close() }

func (s *commandSnapshotStore) names() ([]string, error) {
	fd, err := syscall.Openat(int(s.dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errCommandSnapshots
	}
	dir := os.NewFile(uintptr(fd), "snapshot-entries")
	defer dir.Close()
	entries, err := dir.ReadDir(2*maxStoredCommandSnapshots + 1)
	if (err != nil && err != io.EOF) || len(entries) > 2*maxStoredCommandSnapshots {
		return nil, errCommandSnapshots
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (s *commandSnapshotStore) read(name string) (storedCommandSnapshot, error) {
	var record storedCommandSnapshot
	fd, err := syscall.Openat(int(s.dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return record, errCommandSnapshots
	}
	file := os.NewFile(uintptr(fd), "stored-command-input")
	defer file.Close()
	dm, e1 := descriptorMountID(int(s.dir.Fd()))
	fm, e2 := descriptorMountID(fd)
	before, err := file.Stat()
	if err != nil || before.Size() > maxStoredCommandSnapshotBytes || privateOwned(fd, false) != nil || e1 != nil || e2 != nil || dm != fm {
		return record, errCommandSnapshots
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStoredCommandSnapshotBytes+1))
	if err != nil || len(data) > maxStoredCommandSnapshotBytes {
		return record, errCommandSnapshots
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || !record.valid() {
		return record, errCommandSnapshots
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(data, append(canonical, '\n')) {
		return record, errCommandSnapshots
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return record, errCommandSnapshots
	}
	return record, nil
}

// Called only under exclusive process ownership and s.mu. Never cleans the
// independent consumption journal or anything outside this private directory.
func (s *commandSnapshotStore) cleanup(ctx context.Context, now int64) (count int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	names, err := s.names()
	if err != nil {
		return 0, err
	}
	changed := false
	defer func() {
		// Sync recognized deletions even if a later entry/cancellation fails.
		if changed && s.dir.Sync() != nil {
			s.poisoned = true
			count = 0
			err = errCommandSnapshots
		}
	}()
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		pending := strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".pending")
		if pending {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".pending")
			if !hex32.MatchString(id) {
				return 0, errCommandSnapshots
			}
			fd, err := syscall.Openat(int(s.dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if err != nil {
				return 0, errCommandSnapshots
			}
			var st syscall.Stat_t
			valid := privateOwned(fd, false) == nil && syscall.Fstat(fd, &st) == nil && st.Size <= maxStoredCommandSnapshotBytes
			syscall.Close(fd)
			if !valid {
				return 0, errCommandSnapshots
			}
		} else {
			if !strings.HasSuffix(name, ".json") || !hex32.MatchString(strings.TrimSuffix(name, ".json")) {
				return 0, errCommandSnapshots
			}
			record, err := s.read(name)
			if err != nil || name != record.Metadata.ID+".json" {
				return 0, errCommandSnapshots
			}
			if record.Metadata.ExpiresAt > now {
				count++
				continue
			}
		}
		if syscall.Unlinkat(int(s.dir.Fd()), name) != nil {
			return 0, errCommandSnapshots
		}
		changed = true
	}
	if count > maxStoredCommandSnapshots {
		return 0, errCommandSnapshots
	}
	return count, nil
}

func (s *commandSnapshotStore) Save(ctx context.Context, host, owner string, prepared *preparedCommand) error {
	if s == nil || prepared == nil || !identifier.MatchString(host) || !hex64.MatchString(owner) || prepared.consumed.Load() {
		return errCommandBinding
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return errCommandSnapshots
	}
	count, err := s.cleanup(ctx, time.Now().Unix())
	if err != nil {
		return err
	}
	m := prepared.Metadata()
	if m.ExpiresAt <= time.Now().Unix() || m.ExpiresAt > time.Now().Add(5*time.Minute).Unix() {
		return errCommandBinding
	}
	files, err := prepared.verifiedInputs(ctx)
	if err != nil {
		return err
	}
	record := storedCommandSnapshot{Host: host, Owner: owner, Metadata: m, Device: prepared.device, Inode: prepared.inode, Files: files}
	record.Checksum = record.checksum()
	if !record.valid() {
		return errCommandSnapshots
	}
	name := m.ID + ".json"
	if old, err := s.read(name); err == nil {
		if old.Checksum == record.Checksum {
			return nil
		}
		return errCommandConflict
	}
	// Only ENOENT permits creation; corrupt/unsafe existing records never get replaced.
	check, err := syscall.Openat(int(s.dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == nil {
		syscall.Close(check)
		return errCommandSnapshots
	}
	if !errors.Is(err, syscall.ENOENT) {
		return errCommandSnapshots
	}
	if count >= maxStoredCommandSnapshots {
		return errTooLarge
	}
	data, _ := json.Marshal(record)
	data = append(data, '\n')
	if len(data) > maxStoredCommandSnapshotBytes {
		return errTooLarge
	}
	pending := "." + m.ID + ".pending"
	n, err := syscall.Openat(int(s.dir.Fd()), pending, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errCommandSnapshots
	}
	file := os.NewFile(uintptr(n), "pending-command-input")
	defer file.Close()
	s.poisoned = true
	if privateOwned(n, false) != nil {
		return errCommandSnapshots
	}
	if s.fault != nil && s.fault("before_write") != nil {
		return errCommandSnapshots
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		return errCommandSnapshots
	}
	if file.Sync() != nil {
		return errCommandSnapshots
	}
	if s.fault != nil && s.fault("before_publish") != nil {
		return errCommandSnapshots
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// One exclusive owner of this private directory; known names were checked
	// absent above. No snapshot path is supplied by a caller or project process.
	if syscall.Renameat(int(s.dir.Fd()), pending, int(s.dir.Fd()), name) != nil {
		return errCommandSnapshots
	}
	if s.fault != nil && s.fault("after_publish") != nil {
		return errCommandSnapshots
	}
	if s.dir.Sync() != nil {
		return errCommandSnapshots
	}
	if s.fault != nil && s.fault("after_directory_sync") != nil {
		return errCommandSnapshots
	}
	s.poisoned = false
	return nil
}

func (s *commandSnapshotStore) Load(ctx context.Context, host, owner, id string) (*preparedCommand, error) {
	if s == nil || !identifier.MatchString(host) || !hex64.MatchString(owner) || !hex32.MatchString(id) {
		return nil, errCommandBinding
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return nil, errCommandSnapshots
	}
	if _, err := s.cleanup(ctx, time.Now().Unix()); err != nil {
		return nil, err
	}
	record, err := s.read(id + ".json")
	if err != nil {
		return nil, err
	}
	if record.Host != host || record.Owner != owner {
		return nil, errForbidden
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &preparedCommand{metadata: record.Metadata, files: record.Files, device: record.Device, inode: record.Inode}, nil
}
