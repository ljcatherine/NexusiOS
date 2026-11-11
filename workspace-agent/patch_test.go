package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

const executorTestToken = "dedicated-executor-credential-for-tests-only"

func samplePatch() patchRequest {
	p := patchRequest{Host: "nixos", WorkspaceID: "code", Owner: strings.Repeat("a", 64), ApprovalID: strings.Repeat("b", 32), Digest: strings.Repeat("c", 64), OperationID: strings.Repeat("d", 32), Path: "README.md", BaseSHA256: hashText("before\n"), Replacement: "after\n", ReplacementSHA256: hashText("after\n"), ExpiresAt: time.Now().Unix() + 900}
	p.Proof = p.sign(executorTestToken)
	return p
}
func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPatchBindingEveryFieldAndExpiry(t *testing.T) {
	p := samplePatch()
	now := time.Now()
	if err := p.verify(executorTestToken, now); err != nil {
		t.Fatal(err)
	}
	// Every field (including owner, digest and stable operation ID) affects proof.
	value := reflect.ValueOf(&p).Elem()
	for i := 0; i < value.NumField(); i++ {
		q := p
		field := reflect.ValueOf(&q).Elem().Field(i)
		if field.Kind() == reflect.String {
			field.SetString(field.String() + "x")
		} else {
			field.SetInt(field.Int() + 1)
		}
		if q.verify(executorTestToken, now) == nil {
			t.Fatalf("unbound field %s", value.Type().Field(i).Name)
		}
	}
	if p.verify(testToken, now) == nil || p.verify(executorTestToken, time.Unix(p.ExpiresAt, 0)) == nil || p.verify(executorTestToken, now.Add(-time.Hour)) == nil {
		t.Fatal("wrong credential or expiry accepted")
	}
	q := p
	q.Path = "a/b.md"
	q.Replacement = "c"
	r := p
	r.Path = "a"
	r.Replacement = "b.mdc"
	if string(q.binding()) == string(r.binding()) {
		t.Fatal("ambiguous binding")
	}
}
func TestPatchEndpointCredentialSeparationAndDisabled(t *testing.T) {
	h := setup(t)
	h.server.executorToken = executorTestToken
	h.handler = h.server.handler()
	p := samplePatch()
	data, _ := json.Marshal(p)
	uri := "/v1/workspaces/code/patches/apply"
	before, err := os.ReadFile(filepath.Join(h.root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", testToken, "review-credential-not-an-executor"} {
		if got := request(h, "POST", uri, token, string(data)); got.Code != 401 {
			t.Fatal(got.Code, got.Body.String())
		}
	}
	if got := request(h, "GET", "/v1/workspaces?host=nixos", executorTestToken, ""); got.Code != 401 {
		t.Fatal("executor used as read token")
	}
	for i := 0; i < 2; i++ {
		got := request(h, "POST", uri, executorTestToken, string(data))
		if got.Code != 503 || !strings.Contains(got.Body.String(), "managed_write_unavailable") {
			t.Fatal(got.Code, got.Body.String())
		}
	}
	for _, bad := range []string{string(data) + "{}", strings.Replace(string(data), `"owner":`, `"unexpected":1,"owner":`, 1), strings.Replace(string(data), p.Owner, strings.Repeat("f", 64), 1), `{"replacement":"` + strings.Repeat("a", 512<<10) + `"}`} {
		if got := request(h, "POST", uri, executorTestToken, bad); got.Code != 400 {
			t.Fatal(got.Code, got.Body.String())
		}
	}
	after, _ := os.ReadFile(filepath.Join(h.root, "README.md"))
	if string(before) != string(after) {
		t.Fatal("disabled endpoint wrote file")
	}
	entries, _ := os.ReadDir(h.root)
	for _, e := range entries {
		if strings.Contains(e.Name(), "receipt") || strings.Contains(e.Name(), "stage") {
			t.Fatal("disabled endpoint created state")
		}
	}
	got := request(h, "GET", "/v1/workspaces?host=nixos", testToken, "")
	if strings.Contains(got.Body.String(), "managed_write") || !strings.Contains(got.Body.String(), `"read_only":true`) {
		t.Fatal(got.Body.String())
	}
}
func TestManagedWriteOptInAlwaysFailsClosed(t *testing.T) {
	h := setup(t)
	cfg := config{Host: "nixos", Listen: "127.0.0.1:8896", Token: testToken, Roots: []rootConfig{{ID: "code", Name: "Code", Path: h.root}}}
	if cfg.validate() != nil {
		t.Fatal("default read config rejected")
	}
	cfg.ExecutorToken = testToken
	if cfg.validate() == nil {
		t.Fatal("same executor/read credentials accepted")
	}
	cfg.ExecutorToken = "short"
	if cfg.validate() == nil {
		t.Fatal("short executor credential accepted")
	}
	cfg.ExecutorToken = executorTestToken
	cfg.Roots[0].ManagedWrite = true
	if cfg.validate() == nil {
		t.Fatal("missing trust accepted")
	}
	cfg.Roots[0].ExclusiveWriter = true
	if cfg.validate() == nil {
		t.Fatal("unconfined writer enabled")
	}
}
func TestPatchSnapshotPolicy(t *testing.T) {
	h := setup(t)
	if err := os.Chmod(h.root, 0700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := h.server.roots["code"].inspectPatchFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Inode == 0 || snapshot.MountID == 0 || snapshot.SHA256 != hashText(snapshot.Text) {
		t.Fatal("missing identity")
	}
	for _, p := range []string{"../README.md", "/etc/passwd", "src//hello.py", ".git/config", "credentials.json", "linked.txt", "external/outside.txt", "binary.txt", "AGENTS.md", "nested/CLAUDE.md", "Makefile", "project.yml", "missing.txt"} {
		if _, err := h.server.roots["code"].inspectPatchFile(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	cases := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"exec.sh", []byte("echo hi\n"), 0700}, {"public.md", []byte("hi"), 0644}, {"invalid.md", []byte{255}, 0600}, {"large.md", []byte(strings.Repeat("x", maxReadBytes+1)), 0600},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(h.root, c.name), c.data, c.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := h.server.roots["code"].inspectPatchFile(c.name); err == nil {
			t.Errorf("accepted %s", c.name)
		}
	}
	original := filepath.Join(h.root, "README.md")
	if err := os.Link(original, filepath.Join(h.root, "alias.md")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"README.md", "alias.md"} {
		if _, err := h.server.roots["code"].inspectPatchFile(p); err == nil {
			t.Fatal("hardlink accepted")
		}
	}
	if err := os.Chmod(filepath.Join(h.root, "src"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.server.roots["code"].inspectPatchFile("src/hello.py"); err == nil {
		t.Fatal("nonprivate parent accepted")
	}
}
func TestPatchSnapshotRejectsMetadata(t *testing.T) {
	h := setup(t)
	if err := os.Chmod(h.root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h.root, "README.md")
	if err := syscall.Setxattr(file, "user.nexus-test", []byte("metadata"), 0); err != nil {
		t.Skipf("xattrs unavailable: %v", err)
	}
	if _, err := h.server.roots["code"].inspectPatchFile("README.md"); err == nil {
		t.Fatal("metadata silently discarded")
	}
}
func TestPatchJournalConsumeReplayConflictAndRestart(t *testing.T) {
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := samplePatch()
	receipt, fresh, err := j.reserve(p)
	if err != nil || !fresh || receipt.Status != "reserved" {
		t.Fatal(receipt, fresh, err)
	}
	receipt, fresh, err = j.reserve(p)
	if err != nil || fresh || receipt.Status != "uncertain" {
		t.Fatal(receipt, fresh, err)
	}
	for _, mutate := range []func(*patchRequest){func(q *patchRequest) { q.Owner = strings.Repeat("f", 64) }, func(q *patchRequest) { q.Digest = strings.Repeat("e", 64) }, func(q *patchRequest) { q.Path = "other.md" }, func(q *patchRequest) { q.OperationID = strings.Repeat("e", 32) }} {
		q := p
		mutate(&q)
		if _, _, err = j.reserve(q); !errors.Is(err, errPatchConflict) {
			t.Fatal("conflicting approval reused", err)
		}
	}
	q := p
	q.ApprovalID = strings.Repeat("e", 32)
	if _, _, err = j.reserve(q); !errors.Is(err, errPatchConflict) {
		t.Fatal("operation reused", err)
	}
	q.OperationID = strings.Repeat("e", 32)
	if _, _, err = j.reserve(q); !errors.Is(err, errPatchUncertain) {
		t.Fatal("root not blocked", err)
	}
	j.close()
	j, err = openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	receipt, fresh, err = j.reserve(p)
	if err != nil || fresh || receipt.Status != "uncertain" || receipt.SHA256 != "" {
		t.Fatal(receipt, fresh, err)
	}
	if _, err = j.finishWithoutWrite(p, "failed"); err == nil {
		t.Fatal("recovered uncertain reservation cleared")
	}
	if _, _, err = j.reserve(q); !errors.Is(err, errPatchUncertain) {
		t.Fatal("restart unblocked root", err)
	}
	q.WorkspaceID = "other"
	if _, fresh, err = j.reserve(q); err != nil || !fresh {
		t.Fatal("independent root blocked", err)
	}
}
func TestPatchJournalDurableFailureReceipts(t *testing.T) {
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := samplePatch()
	if _, _, err = j.reserve(p); err != nil {
		t.Fatal(err)
	}
	if _, err = j.finishWithoutWrite(p, "applied"); err == nil {
		t.Fatal("unproven applied accepted")
	}
	if _, err = j.finishWithoutWrite(p, "conflict"); err != nil {
		t.Fatal(err)
	}
	j.close()
	j, err = openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	r, fresh, err := j.reserve(p)
	if err != nil || fresh || r.Status != "conflict" {
		t.Fatal(r, fresh, err)
	}
	q := p
	q.OperationID = strings.Repeat("e", 32)
	q.ApprovalID = strings.Repeat("e", 32)
	if _, fresh, err = j.reserve(q); err != nil || !fresh {
		t.Fatal("safe failure blocked root", err)
	}
}
func TestPatchJournalFailureInjection(t *testing.T) {
	for _, boundary := range []string{"before_append", "before_fsync", "after_fsync"} {
		t.Run(boundary, func(t *testing.T) {
			dir := privateDir(t)
			j, err := openPatchJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			p := samplePatch()
			j.fault = func(at string) error {
				if at == boundary {
					return errors.New("injected IO failure")
				}
				return nil
			}
			if _, fresh, err := j.reserve(p); err == nil || fresh {
				t.Fatal("failed persistence allowed dispatch")
			}
			j.fault = nil
			if _, _, err := j.reserve(p); !errors.Is(err, errPatchJournal) {
				t.Fatal("poisoned handle retried", err)
			}
			j.close()
			j, err = openPatchJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			r, fresh, err := j.reserve(p)
			if boundary == "before_append" {
				if err != nil || !fresh {
					t.Fatal(err)
				}
			} else if err != nil || fresh || r.Status != "uncertain" {
				t.Fatal("potential persisted consumption retried", r, fresh, err)
			}
		})
	}
}
func TestPatchJournalPrivateStorageLockCorruptionAndLinks(t *testing.T) {
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if another, err := openPatchJournal(dir); err == nil {
		another.close()
		t.Fatal("concurrent journal owner")
	}
	p := samplePatch()
	if _, _, err := j.reserve(p); err != nil {
		t.Fatal(err)
	}
	j.close()
	file := filepath.Join(dir, "receipts.jsonl")
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{original[:len(original)-1], append(append([]byte{}, original...), []byte("{torn")...), []byte(strings.Replace(string(original), p.Digest, strings.Repeat("f", 64), 1))} {
		if err := os.WriteFile(file, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if unsafe, err := openPatchJournal(dir); err == nil {
			unsafe.close()
			t.Fatal("corrupt ledger accepted")
		}
	}
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openPatchJournal(dir); err == nil {
		unsafe.close()
		t.Fatal("hardlinked journal")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "alias"), file); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openPatchJournal(dir); err == nil {
		unsafe.close()
		t.Fatal("symlinked journal")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openPatchJournal(dir); err == nil {
		unsafe.close()
		t.Fatal("public state directory")
	}
}

// Mount changes occur only in a new user+mount namespace, never on the host.
func TestPatchSnapshotRejectsBindMounts(t *testing.T) {
	if os.Getenv("NEXUS_PATCH_MOUNT_HELPER") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestPatchSnapshotRejectsBindMounts$", "-test.v")
		cmd.Env = append(os.Environ(), "NEXUS_PATCH_MOUNT_HELPER=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}, GidMappingsEnableSetgroups: false}
		output, err := cmd.CombinedOutput()
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			t.Skipf("private mount namespace unavailable: %v", err)
		}
		if err != nil {
			t.Fatalf("mount probe: %v: %s", err, output)
		}
		t.Log(string(output))
		return
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	h := setup(t)
	if err := os.Chmod(h.root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := privateDir(t)
	file := filepath.Join(outside, "outside.md")
	if err := os.WriteFile(file, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{outside, filepath.Join(h.root, "src")}, {file, filepath.Join(h.root, "README.md")}} {
		if err := syscall.Mount(pair[0], pair[1], "", syscall.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		defer syscall.Unmount(pair[1], 0)
	}
	for _, name := range []string{"README.md", "src/outside.md"} {
		if _, err := h.server.roots["code"].inspectPatchFile(name); err == nil {
			t.Fatal("bind mount accepted", name)
		}
	}
}

func TestPatchReceiptLookupAfterExpiryIsReadOnly(t *testing.T) {
	h := setup(t)
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err := j.bindRoots(h.server.host, h.server.roots); err != nil {
		t.Fatal(err)
	}
	h.server.patchJournal = j
	h.server.executorToken = executorTestToken
	// setup cleanup owns only its original server descriptors.
	t.Cleanup(func() { h.server.patchJournal = nil })
	h.handler = h.server.handler()
	p := samplePatch()
	p.ExpiresAt = time.Now().Unix() - 10
	p.Proof = p.sign(executorTestToken)
	if _, _, err := j.reserve(p); err != nil {
		t.Fatal(err)
	}
	uri := "/v1/workspaces/code/patches/receipts/" + p.OperationID
	data, _ := json.Marshal(p)
	before, err := os.ReadFile(filepath.Join(dir, "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	response := request(h, "GET", uri, executorTestToken, string(data))
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"status":"uncertain"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), p.Replacement) || strings.Contains(response.Body.String(), p.Owner) || strings.Contains(response.Body.String(), p.Proof) {
		t.Fatal("receipt disclosed signed payload")
	}
	if response := request(h, "POST", "/v1/workspaces/code/patches/apply", executorTestToken, string(data)); response.Code != 400 {
		t.Fatal("expired apply accepted")
	}
	if response := request(h, "GET", uri, testToken, string(data)); response.Code != 401 {
		t.Fatal("read credential reconciled writes")
	}
	q := p
	q.Owner = strings.Repeat("f", 64)
	q.Proof = q.sign(executorTestToken)
	bad, _ := json.Marshal(q)
	if response := request(h, "GET", uri, executorTestToken, string(bad)); response.Code != 409 {
		t.Fatal("wrong owner read receipt", response.Code)
	}
	q = p
	q.ExpiresAt++
	q.Proof = q.sign(executorTestToken)
	bad, _ = json.Marshal(q)
	if response := request(h, "GET", uri, executorTestToken, string(bad)); response.Code != 409 {
		t.Fatal("refreshed expiry reconciled old operation", response.Code)
	}
	q = p
	q.ApprovalID = strings.Repeat("e", 32)
	q.Proof = q.sign(executorTestToken)
	bad, _ = json.Marshal(q)
	if response := request(h, "GET", uri, executorTestToken, string(bad)); response.Code != 404 {
		t.Fatal("lookup reserved absent approval", response.Code)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "receipts.jsonl"))
	if string(before) != string(after) {
		t.Fatal("GET mutated journal")
	}
}

func TestPatchStateRootAnchorAndLoopbackPolicy(t *testing.T) {
	h := setup(t)
	dir := privateDir(t)
	cfg := config{Host: "nixos", Listen: "127.0.0.1:8896", Token: testToken, ExecutorToken: executorTestToken, PatchStateDir: dir, Roots: []rootConfig{{ID: "code", Name: "Code", Path: h.root}}}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	s, err = newServer(cfg)
	if err != nil {
		t.Fatal("stable root failed", err)
	}
	s.close()
	cfg.Roots[0].Path = privateDir(t)
	if s, err = newServer(cfg); err == nil {
		s.close()
		t.Fatal("root reconfiguration reused old state")
	}
	cfg.Listen = "192.0.2.1:8896"
	cfg.AllowWAN = true
	if cfg.validate() == nil {
		t.Fatal("executor secret allowed over plain remote HTTP")
	}
	cfg.Listen = "127.0.0.1:8896"
	cfg.ExecutorToken = ""
	if cfg.validate() == nil {
		t.Fatal("unauthenticated patch state configured")
	}
}

func TestPatchJournalConcurrentDuplicateReservation(t *testing.T) {
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	p := samplePatch()
	results := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func() {
			_, fresh, err := j.reserve(p)
			if err != nil {
				t.Error(err)
			}
			results <- fresh
		}()
	}
	count := 0
	for i := 0; i < 16; i++ {
		if <-results {
			count++
		}
	}
	if count != 1 {
		t.Fatal("multiple dispatch permits", count)
	}
}

func TestPatchJournalTerminalDurabilityFailureCannotRedispatch(t *testing.T) {
	dir := privateDir(t)
	j, err := openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := samplePatch()
	if _, _, err = j.reserve(p); err != nil {
		t.Fatal(err)
	}
	j.fault = func(at string) error {
		if at == "after_fsync" {
			return errors.New("lost response after durable receipt")
		}
		return nil
	}
	if _, err := j.finishWithoutWrite(p, "conflict"); err == nil {
		t.Fatal("injected error lost")
	}
	if _, err := j.lookup(p); !errors.Is(err, errPatchJournal) {
		t.Fatal("poisoned journal served certainty")
	}
	j.close()
	j, err = openPatchJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	r, fresh, err := j.reserve(p)
	if err != nil || fresh || r.Status != "conflict" {
		t.Fatal(r, fresh, err)
	}
}
