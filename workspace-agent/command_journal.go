package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

var errCommandJournal = errors.New("command ledger unavailable; manual investigation required")

const maxCommandJournalBytes = 32 << 20
const maxCommandJournalRecords = 2048

type commandJournalRecord struct {
	RecordedAt int64          `json:"recorded_at_ns"`
	Receipt    commandReceipt `json:"receipt"`
	Previous   string         `json:"previous"`
	Checksum   string         `json:"checksum"`
}

func (r commandJournalRecord) checksum() string {
	r.Checksum = ""
	data, _ := json.Marshal(r)
	return hashText(string(data))
}

// Append-only host consumption/audit ledger. Hash chaining detects torn writes
// and accidental corruption, not trusted-owner tampering or directory rollback.
// Never delete/reset the ledger to retry an uncertain operation.
type commandJournal struct {
	mu                    sync.Mutex
	dir, file             *os.File
	records               map[string]commandJournalRecord
	operations, snapshots map[string]string
	tail                  string
	count, size           int
	poisoned              bool
	fault                 func(string) error // Test-only durability boundary, nil normally.
}

func openCommandJournal(directory string) (*commandJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errCommandJournal
	}
	fd, err := openConfiguredRoot(directory)
	if err != nil {
		return nil, errCommandJournal
	}
	dir := os.NewFile(uintptr(fd), "command-state")
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) != nil || (fs.Type != 0xef53 && fs.Type != 0x58465342 && fs.Type != 0x9123683e) || privateOwned(fd, true) != nil || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		dir.Close()
		return nil, errCommandJournal
	}
	flags := syscall.O_RDWR | syscall.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	n, err := syscall.Openat(fd, "commands.jsonl", flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if errors.Is(err, syscall.EEXIST) {
		n, err = syscall.Openat(fd, "commands.jsonl", flags, 0)
	}
	if err != nil {
		dir.Close()
		return nil, errCommandJournal
	}
	j := &commandJournal{dir: dir, file: os.NewFile(uintptr(n), "command-records"), records: map[string]commandJournalRecord{}, operations: map[string]string{}, snapshots: map[string]string{}}
	fail := func() (*commandJournal, error) { j.close(); return nil, errCommandJournal }
	dm, e1 := descriptorMountID(fd)
	fm, e2 := descriptorMountID(n)
	if privateOwned(n, false) != nil || e1 != nil || e2 != nil || dm != fm {
		return fail()
	}
	info, err := j.file.Stat()
	if err != nil || info.Size() > maxCommandJournalBytes || j.file.Sync() != nil || dir.Sync() != nil {
		return fail()
	}
	scanner := bufio.NewScanner(j.file)
	scanner.Buffer(make([]byte, 4096), 512<<10)
	for scanner.Scan() {
		var record commandJournalRecord
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || record.Previous != j.tail || record.Checksum != record.checksum() || j.accept(record) != nil {
			return fail()
		}
		j.tail = record.Checksum
		j.count++
		if j.count > maxCommandJournalRecords {
			return fail()
		}
	}
	if scanner.Err() != nil {
		return fail()
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := j.file.ReadAt(last[:], info.Size()-1); err != nil || last[0] != '\n' {
			return fail()
		}
	}
	j.size = int(info.Size())
	return j, nil
}

func (j *commandJournal) close() { j.file.Close(); j.dir.Close() }
func cloneCommandReceipt(receipt commandReceipt) commandReceipt {
	if receipt.Result != nil {
		copy := *receipt.Result
		receipt.Result = &copy
	}
	return receipt
}
func (j *commandJournal) accept(record commandJournalRecord) error {
	receipt, p := record.Receipt, record.Receipt.Request
	if p.validate() != nil || p.Proof != "" || record.RecordedAt <= 0 {
		return errCommandJournal
	}
	old, exists := j.records[p.ApprovalID]
	if !exists {
		if receipt.Status != "claimed" || receipt.Result != nil || receipt.Failure != "" || j.operations[p.OperationID] != "" || j.snapshots[p.SnapshotID] != "" {
			return errCommandJournal
		}
	} else if old.Receipt.Status != "claimed" || old.Receipt.Request != p || (receipt.Status != "completed" && receipt.Status != "interrupted") {
		return errCommandJournal
	}
	if receipt.Status == "interrupted" {
		if receipt.Result != nil || receipt.Failure != "exit_unknown" {
			return errCommandJournal
		}
	} else if receipt.Status == "completed" {
		r := receipt.Result
		if r == nil || r.ProfileID != p.ProfileID || r.SnapshotID != p.SnapshotID || r.ProfileVersion != p.ProfileVersion || r.InputDigest != p.InputDigest || r.WorkspaceGeneration != p.Generation ||
			r.ExitCode < -1 || r.ExitCode > 255 || len(r.Stdout)+len(r.Stderr) > commandOutputBytes || !utf8.ValidString(r.Stdout) || !utf8.ValidString(r.Stderr) ||
			(receipt.Failure != "" && receipt.Failure != "execution_failed") || (receipt.Failure == "" && (r.Cancelled || r.TimedOut || r.Truncated)) {
			return errCommandJournal
		}
	}
	j.records[p.ApprovalID] = record
	j.operations[p.OperationID] = p.ApprovalID
	j.snapshots[p.SnapshotID] = p.ApprovalID
	return nil
}

func (j *commandJournal) append(record commandJournalRecord) error {
	if j.poisoned || j.count >= maxCommandJournalRecords {
		return errCommandJournal
	}
	record.RecordedAt = time.Now().UnixNano()
	record.Previous = j.tail
	record.Checksum = record.checksum()
	data, _ := json.Marshal(record)
	data = append(data, '\n')
	if j.size+len(data) > maxCommandJournalBytes {
		return errCommandJournal
	}
	j.poisoned = true
	if j.fault != nil && j.fault("before_append") != nil {
		return errCommandJournal
	}
	if n, err := j.file.Write(data); err != nil || n != len(data) {
		return errCommandJournal
	}
	if j.fault != nil && j.fault("before_fsync") != nil {
		return errCommandJournal
	}
	if j.file.Sync() != nil {
		return errCommandJournal
	}
	if j.fault != nil && j.fault("after_fsync") != nil {
		return errCommandJournal
	}
	if j.accept(record) != nil {
		return errCommandJournal
	}
	j.tail = record.Checksum
	j.count++
	j.size += len(data)
	j.poisoned = false
	return nil
}

func (j *commandJournal) lookup(p commandRequest) (commandReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return commandReceipt{}, false, errCommandJournal
	}
	if p.validate() != nil {
		return commandReceipt{}, false, errCommandBinding
	}
	old, found := j.records[p.ApprovalID]
	if found {
		if old.Receipt.Request.requestDigest() != p.requestDigest() {
			return commandReceipt{}, false, errCommandConflict
		}
		return cloneCommandReceipt(old.Receipt), true, nil
	}
	if j.operations[p.OperationID] != "" || j.snapshots[p.SnapshotID] != "" {
		return commandReceipt{}, false, errCommandConflict
	}
	return commandReceipt{}, false, nil
}

func (j *commandJournal) claim(p commandRequest) (commandReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return commandReceipt{}, false, errCommandJournal
	}
	if p.validate() != nil {
		return commandReceipt{}, false, errCommandBinding
	}
	if old, found := j.records[p.ApprovalID]; found {
		if old.Receipt.Request.requestDigest() != p.requestDigest() {
			return commandReceipt{}, false, errCommandConflict
		}
		return cloneCommandReceipt(old.Receipt), false, nil
	}
	if j.operations[p.OperationID] != "" || j.snapshots[p.SnapshotID] != "" {
		return commandReceipt{}, false, errCommandConflict
	}
	// Reserve space for a worst-case escaped output receipt before consuming.
	if j.count > maxCommandJournalRecords-2 || j.size > maxCommandJournalBytes-(1<<20) {
		return commandReceipt{}, false, errCommandJournal
	}
	for _, old := range j.records {
		if old.Receipt.Status == "claimed" {
			return commandReceipt{}, false, errCommandUncertain
		}
	}
	p.Proof = ""
	receipt := commandReceipt{Request: p, Status: "claimed"}
	if err := j.append(commandJournalRecord{Receipt: receipt}); err != nil {
		return commandReceipt{}, false, err
	}
	return receipt, true, nil
}

func (j *commandJournal) finish(p commandRequest, status string, result *commandResult, failure string) (commandReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return commandReceipt{}, errCommandJournal
	}
	old, found := j.records[p.ApprovalID]
	if !found || old.Receipt.Request.requestDigest() != p.requestDigest() || old.Receipt.Status != "claimed" || (status != "completed" && status != "interrupted") {
		return commandReceipt{}, errCommandConflict
	}
	receipt := cloneCommandReceipt(commandReceipt{Request: old.Receipt.Request, Status: status, Result: result, Failure: failure})
	if err := j.append(commandJournalRecord{Receipt: receipt}); err != nil {
		return commandReceipt{}, err
	}
	return cloneCommandReceipt(receipt), nil
}
