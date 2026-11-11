package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const maxPatchJournalBytes = 4 << 20
const maxPatchJournalRecords = 2048

var errPatchJournal = errors.New("patch journal unavailable; manual investigation required")

type patchJournalRecord struct {
	RequestSHA256 string              `json:"request_sha256"`
	Owner         string              `json:"owner"`
	Receipt       patchReceipt        `json:"receipt"`
	Stage         *patchStageIdentity `json:"stage,omitempty"`
	Previous      string              `json:"previous"`
	Checksum      string              `json:"checksum"`
}

func (r patchJournalRecord) checksum() string {
	r.Checksum = ""
	data, _ := json.Marshal(r)
	return hashText(string(data))
}

// Host-local append-only consumption ledger. Applied records require staged
// identity evidence from the confined helper. Hash chaining detects torn/accidental corruption,
// not tampering by the trusted OS owner or rollback of the whole directory.
// A dedicated persistent directory must never be deleted/reset to retry writes.
type patchJournal struct {
	mu          sync.Mutex
	dir, file   *os.File
	records     map[string]patchJournalRecord
	operations  map[string]string
	tail        string
	count, size int
	poisoned    bool
	// Test-only fault boundary, nil in normal use. Any failure poisons the ledger.
	fault func(string) error
}

func openPatchJournal(directory string) (*patchJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, errPatchJournal
	}
	fd, err := openConfiguredRoot(directory)
	if err != nil {
		return nil, errPatchJournal
	}
	dir := os.NewFile(uintptr(fd), "patch-state")
	fail := func() (*patchJournal, error) { dir.Close(); return nil, errPatchJournal }
	if privateOwned(fd, true) != nil || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	n, err := syscall.Openat(fd, "receipts.jsonl", syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, syscall.EEXIST) {
		n, err = syscall.Openat(fd, "receipts.jsonl", syscall.O_RDWR|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	}
	if err != nil {
		return fail()
	}
	file := os.NewFile(uintptr(n), "patch-receipts")
	j := &patchJournal{dir: dir, file: file, records: map[string]patchJournalRecord{}, operations: map[string]string{}}
	abort := func() (*patchJournal, error) { j.close(); return nil, errPatchJournal }
	dm, e1 := descriptorMountID(fd)
	fm, e2 := descriptorMountID(n)
	if privateOwned(n, false) != nil || e1 != nil || e2 != nil || dm != fm {
		return abort()
	}
	st, err := file.Stat()
	if err != nil || st.Size() > maxPatchJournalBytes {
		return abort()
	}
	if file.Sync() != nil || dir.Sync() != nil {
		return abort()
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 8192)
	for scanner.Scan() {
		line := scanner.Bytes()
		var r patchJournalRecord
		dec := json.NewDecoder(strings.NewReader(string(line)))
		dec.DisallowUnknownFields()
		if dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF || r.Previous != j.tail || r.Checksum != r.checksum() || j.accept(r) != nil {
			return abort()
		}
		j.tail = r.Checksum
		j.count++
		if j.count > maxPatchJournalRecords {
			return abort()
		}
	}
	if scanner.Err() != nil {
		return abort()
	}
	// Scanner accepts a final unterminated line; a torn append must never pass.
	if st.Size() > 0 {
		var end [1]byte
		if _, err = file.ReadAt(end[:], st.Size()-1); err != nil || end[0] != '\n' {
			return abort()
		}
	}
	j.size = int(st.Size())
	// No hash-based recovery. Every unfinished reservation stays uncertain,
	// including when the target happens to contain the requested replacement.
	for id, r := range j.records {
		if r.Receipt.Status == "reserved" || r.Receipt.Status == "staged" {
			r.Receipt.Status = "uncertain"
			j.records[id] = r
		}
	}
	return j, nil
}
func (j *patchJournal) close() { j.file.Close(); j.dir.Close() }
func (j *patchJournal) accept(r patchJournalRecord) error {
	p := r.Receipt
	if r.Stage != nil && !r.Stage.valid(p.OperationID) {
		return errPatchJournal
	}
	if !hex64.MatchString(r.RequestSHA256) || !hex64.MatchString(r.Owner) || !identifier.MatchString(p.Host) || !identifier.MatchString(p.WorkspaceID) || !hex32.MatchString(p.ApprovalID) || !hex32.MatchString(p.OperationID) || !hex64.MatchString(p.Digest) || (p.Status != "applied" && p.SHA256 != "") || (p.Status == "applied" && !hex64.MatchString(p.SHA256)) {
		return errPatchJournal
	}
	old, exists := j.records[p.ApprovalID]
	if !exists {
		if p.Status != "reserved" || r.Stage != nil || j.operations[p.OperationID] != "" || j.blocked(p.Host, p.WorkspaceID) {
			return errPatchJournal
		}
	} else {
		if (old.Receipt.Status != "reserved" && old.Receipt.Status != "staged" && old.Receipt.Status != "uncertain") || old.RequestSHA256 != r.RequestSHA256 || old.Owner != r.Owner || old.Receipt.Host != p.Host || old.Receipt.WorkspaceID != p.WorkspaceID || old.Receipt.OperationID != p.OperationID || old.Receipt.Digest != p.Digest {
			return errPatchJournal
		}
		if p.Status == "staged" {
			if old.Receipt.Status != "reserved" || r.Stage == nil || !r.Stage.valid(p.OperationID) {
				return errPatchJournal
			}
		} else if p.Status == "applied" {
			if old.Stage == nil || r.Stage == nil || *old.Stage != *r.Stage {
				return errPatchJournal
			}
		} else if p.Status != "conflict" && p.Status != "failed" && p.Status != "uncertain" {
			return errPatchJournal
		}
		if old.Stage != nil && (r.Stage == nil || *old.Stage != *r.Stage) {
			return errPatchJournal
		}
	}
	j.records[p.ApprovalID] = r
	j.operations[p.OperationID] = p.ApprovalID
	return nil
}
func (j *patchJournal) blocked(host, root string) bool {
	for _, r := range j.records {
		p := r.Receipt
		if p.Host == host && p.WorkspaceID == root && (p.Status == "reserved" || p.Status == "staged" || p.Status == "uncertain") {
			return true
		}
	}
	return false
}
func (j *patchJournal) append(r patchJournalRecord) error {
	if j.poisoned || j.count >= maxPatchJournalRecords {
		return errPatchJournal
	}
	r.Previous = j.tail
	r.Checksum = r.checksum()
	data, _ := json.Marshal(r)
	data = append(data, '\n')
	if j.size+len(data) > maxPatchJournalBytes {
		return errPatchJournal
	}
	// A failed append/sync may have reached stable storage. Never truncate,
	// roll back consumption or retry through this handle after such a failure.
	j.poisoned = true
	if j.fault != nil {
		if err := j.fault("before_append"); err != nil {
			return errPatchJournal
		}
	}
	if n, err := j.file.Write(data); err != nil || n != len(data) {
		return errPatchJournal
	}
	if j.fault != nil {
		if err := j.fault("before_fsync"); err != nil {
			return errPatchJournal
		}
	}
	if j.file.Sync() != nil {
		return errPatchJournal
	}
	if j.fault != nil {
		if err := j.fault("after_fsync"); err != nil {
			return errPatchJournal
		}
	}
	if j.accept(r) != nil {
		return errPatchJournal
	}
	j.tail = r.Checksum
	j.count++
	j.size += len(data)
	j.poisoned = false
	return nil
}

// reserve consumes approval AND operation IDs before any future side effect.
// Exact replay returns the stored receipt; it never grants dispatch permission.
// Callers must verify authentication, freshness and policy before first reserve.
func (j *patchJournal) reserve(p patchRequest) (patchReceipt, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return patchReceipt{}, false, errPatchJournal
	}
	if p.validate() != nil {
		return patchReceipt{}, false, errPatchBinding
	}
	if old, ok := j.records[p.ApprovalID]; ok {
		if old.RequestSHA256 != p.requestDigest() || old.Owner != p.Owner {
			return patchReceipt{}, false, errPatchConflict
		}
		receipt := old.Receipt
		if receipt.Status == "reserved" || receipt.Status == "staged" {
			receipt.Status = "uncertain"
		}
		return receipt, false, nil
	}
	if j.operations[p.OperationID] != "" {
		return patchReceipt{}, false, errPatchConflict
	}
	if j.blocked(p.Host, p.WorkspaceID) {
		return patchReceipt{}, false, errPatchUncertain
	}
	r := patchJournalRecord{RequestSHA256: p.requestDigest(), Owner: p.Owner, Receipt: p.receipt("reserved")}
	if err := j.append(r); err != nil {
		return patchReceipt{}, false, err
	}
	return r.Receipt, true, nil
}

// Only pre-mutation failures may use this path. Applied outcomes go through
// finishMutation with a matching durably recorded staged identity.
func (j *patchJournal) finishWithoutWrite(p patchRequest, status string) (patchReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return patchReceipt{}, errPatchJournal
	}
	r, ok := j.records[p.ApprovalID]
	if !ok || r.RequestSHA256 != p.requestDigest() || r.Receipt.Status != "reserved" {
		return patchReceipt{}, errPatchConflict
	}
	if status != "failed" && status != "conflict" && status != "uncertain" {
		return patchReceipt{}, errPatchBinding
	}
	r.Receipt.Status = status
	if err := j.append(r); err != nil {
		return patchReceipt{}, err
	}
	return r.Receipt, nil
}

func (j *patchJournal) lookup(p patchRequest) (patchReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned {
		return patchReceipt{}, errPatchJournal
	}
	r, ok := j.records[p.ApprovalID]
	if !ok {
		return patchReceipt{}, errMissing
	}
	if r.RequestSHA256 != p.requestDigest() || r.Owner != p.Owner {
		return patchReceipt{}, errPatchConflict
	}
	receipt := r.Receipt
	if receipt.Status == "reserved" || receipt.Status == "staged" {
		receipt.Status = "uncertain"
	}
	return receipt, nil
}

// Persist the installed-file evidence before the child receives commit permission.
func (j *patchJournal) recordStage(p patchRequest, stage patchStageIdentity) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.records[p.ApprovalID]
	if j.poisoned || !ok || r.RequestSHA256 != p.requestDigest() || r.Receipt.Status != "reserved" || !stage.valid(p.OperationID) {
		return errPatchJournal
	}
	r.Stage = &stage
	r.Receipt.Status = "staged"
	return j.append(r)
}

func (j *patchJournal) executionRecord(p patchRequest) (patchJournalRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.records[p.ApprovalID]
	if j.poisoned {
		return patchJournalRecord{}, errPatchJournal
	}
	if !ok {
		return patchJournalRecord{}, errMissing
	}
	if r.Owner != p.Owner || r.RequestSHA256 != p.requestDigest() {
		return patchJournalRecord{}, errPatchConflict
	}
	if r.Stage != nil {
		stage := *r.Stage
		r.Stage = &stage
	}
	return r, nil
}

func (j *patchJournal) finishMutation(p patchRequest, status, sha string) (patchReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.records[p.ApprovalID]
	if j.poisoned || !ok || r.RequestSHA256 != p.requestDigest() {
		return patchReceipt{}, errPatchJournal
	}
	if r.Receipt.Status != "staged" && r.Receipt.Status != "uncertain" {
		return patchReceipt{}, errPatchConflict
	}
	if r.Stage == nil || !r.Stage.valid(p.OperationID) {
		return patchReceipt{}, errPatchJournal
	}
	if status == "applied" {
		if sha != p.ReplacementSHA256 {
			return patchReceipt{}, errPatchBinding
		}
	} else if (status != "conflict" && status != "failed" && status != "uncertain") || sha != "" {
		return patchReceipt{}, errPatchBinding
	}
	r.Receipt.Status = status
	r.Receipt.SHA256 = sha
	if err := j.append(r); err != nil {
		return patchReceipt{}, err
	}
	return r.Receipt, nil
}
