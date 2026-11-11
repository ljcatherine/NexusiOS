package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func buildPatchTestHelper(t *testing.T, source string, crash ...string) string {
	t.Helper()
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "patch-helper")
	args := []string{"build", "-o", output}
	if len(crash) == 1 {
		args = append(args, "-ldflags=-X main.patchHelperCrashPoint="+crash[0])
	}
	if source != "" {
		path := filepath.Join(t.TempDir(), "probe.go")
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	} else {
		args = append(args, ".")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, goPath, args...)
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CGO_ENABLED=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("static helper build: %v %s", err, out)
	}
	return output
}

func mutationFixture(t *testing.T, helper string) (*patchExecutor, *workspace, string, *patchJournal, patchRequest, string) {
	t.Helper()
	engine, err := newPatchExecutor(commandTestBwrap, commandTestPrlimit)
	if err != nil {
		t.Skipf("trusted sandbox tools unavailable: %v", err)
	}
	engine.helperPath = helper
	directory := privateDir(t)
	if err := os.WriteFile(filepath.Join(directory, "README.md"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := openConfiguredRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	root := &workspace{fd: fd, config: rootConfig{ID: "code", Path: directory, ManagedWrite: true, ExclusiveWriter: true}}
	t.Cleanup(func() { syscall.Close(fd) })
	state := privateDir(t)
	journal, err := openPatchJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	// Tests that simulate restart close/reopen this handle themselves.
	t.Cleanup(func() {
		if journal.file != nil {
			journal.close()
			journal.file = nil
		}
	})
	return engine, root, directory, journal, samplePatch(), state
}

func reopenMutationJournal(t *testing.T, j *patchJournal, path string) *patchJournal {
	t.Helper()
	j.close()
	j.file = nil
	restored, err := openPatchJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restored.close() })
	return restored
}

func TestPatchActualMutationEngine(t *testing.T) {
	helper := buildPatchTestHelper(t, "")
	t.Run("apply and duplicate receipt", func(t *testing.T) {
		e, root, path, j, p, _ := mutationFixture(t, helper)
		calls := 0
		receipt, err := e.execute(context.Background(), root, p, j, func() bool { calls++; return true })
		if err != nil || receipt.Status != "applied" || receipt.SHA256 != p.ReplacementSHA256 {
			t.Fatalf("apply: %+v %v", receipt, err)
		}
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != p.Replacement || calls != 2 {
			t.Fatal("commit policy/contents", calls, string(data))
		}
		previous, err := root.inspectPatchFile(p.Path)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err = e.execute(context.Background(), root, p, j, func() bool { return true })
		after, _ := root.inspectPatchFile(p.Path)
		if err != nil || receipt.Status != "applied" || after.Version != previous.Version {
			t.Fatal("duplicate repeated a mutation", receipt, err)
		}
	})
	t.Run("stale baseline", func(t *testing.T) {
		e, root, path, j, p, _ := mutationFixture(t, helper)
		os.WriteFile(filepath.Join(path, p.Path), []byte("someone else's edit\n"), 0600)
		receipt, err := e.execute(context.Background(), root, p, j, func() bool { return true })
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if err != nil || receipt.Status != "conflict" || string(data) != "someone else's edit\n" {
			t.Fatal(receipt, err, string(data))
		}
	})
	t.Run("crash after staged identity then restart", func(t *testing.T) {
		e, root, path, j, p, state := mutationFixture(t, helper)
		e.fault = func(point string) error {
			if point == "after_stage_record" {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("fault not reached")
		}
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != "before\n" {
			t.Fatal("mutation before permit")
		}
		restored := reopenMutationJournal(t, j, state)
		e.fault = nil
		receipt, err := e.recover(context.Background(), root, p, restored)
		if err != nil || receipt.Status != "failed" {
			t.Fatal("uncommitted stage recovery", receipt, err)
		}
		data, _ = os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != "before\n" {
			t.Fatal("recovery repeated write")
		}
		entries, _ := os.ReadDir(path)
		if len(entries) != 1 {
			t.Fatal("private stage was not cleaned")
		}
	})
	t.Run("crash after rename before receipt", func(t *testing.T) {
		e, root, path, j, p, state := mutationFixture(t, helper)
		e.fault = func(point string) error {
			if point == "after_helper_result" {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("fault not reached")
		}
		before, _ := root.inspectPatchFile(p.Path)
		restored := reopenMutationJournal(t, j, state)
		e.fault = nil
		receipt, err := e.recover(context.Background(), root, p, restored)
		after, _ := root.inspectPatchFile(p.Path)
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if err != nil || receipt.Status != "applied" || string(data) != p.Replacement || after.Inode != before.Inode {
			t.Fatal("applied identity recovery", receipt, err)
		}
	})
	t.Run("matching bytes without staged inode stay uncertain", func(t *testing.T) {
		e, root, path, j, p, state := mutationFixture(t, helper)
		e.fault = func(point string) error {
			if point == "after_helper_result" {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("fault not reached")
		}
		impostor := filepath.Join(path, "impostor.md")
		os.WriteFile(impostor, []byte(p.Replacement), 0600)
		os.Rename(impostor, filepath.Join(path, p.Path))
		restored := reopenMutationJournal(t, j, state)
		e.fault = nil
		if _, err := e.recover(context.Background(), root, p, restored); !errors.Is(err, errPatchUncertain) {
			t.Fatal("hash alone accepted", err)
		}
		other := p
		other.OperationID = strings.Repeat("e", 32)
		other.ApprovalID = strings.Repeat("f", 32)
		if _, _, err := restored.reserve(other); !errors.Is(err, errPatchUncertain) {
			t.Fatal("uncertain root not blocked", err)
		}
	})
	t.Run("revoked permit never renames", func(t *testing.T) {
		e, root, path, j, p, _ := mutationFixture(t, helper)
		calls := 0
		if _, err := e.execute(context.Background(), root, p, j, func() bool { calls++; return calls == 1 }); !errors.Is(err, errPatchUncertain) {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != "before\n" {
			t.Fatal("revoked write applied")
		}
		receipt, err := e.recover(context.Background(), root, p, j)
		if err != nil || receipt.Status != "failed" {
			t.Fatal(receipt, err)
		}
	})
	t.Run("receipt fsync ambiguity reconciles without redispatch", func(t *testing.T) {
		e, root, _, j, p, state := mutationFixture(t, helper)
		writes := 0
		j.fault = func(point string) error {
			if point == "after_fsync" {
				writes++
				if writes == 3 {
					return io.ErrUnexpectedEOF
				}
			}
			return nil
		}
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("fault not reached")
		}
		restored := reopenMutationJournal(t, j, state)
		receipt, err := e.recover(context.Background(), root, p, restored)
		if err != nil || receipt.Status != "applied" {
			t.Fatal(receipt, err)
		}
	})
}

func TestPatchHelperCrashBoundaries(t *testing.T) {
	for _, point := range []string{"before_stage_sync", "before_stage_reply", "before_rename", "after_rename", "after_parent_sync"} {
		t.Run(point, func(t *testing.T) {
			helper := buildPatchTestHelper(t, "", point)
			e, root, path, j, p, state := mutationFixture(t, helper)
			if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
				t.Fatal("helper crash did not interrupt execution")
			}
			restored := reopenMutationJournal(t, j, state)
			receipt, err := e.recover(context.Background(), root, p, restored)
			switch point {
			case "after_rename", "after_parent_sync":
				if err != nil || receipt.Status != "applied" {
					t.Fatal("post-rename recovery", receipt, err)
				}
				data, _ := os.ReadFile(filepath.Join(path, p.Path))
				if string(data) != p.Replacement {
					t.Fatal("replacement lost")
				}
			case "before_rename":
				if err != nil || receipt.Status != "failed" {
					t.Fatal("pre-rename recovery", receipt, err)
				}
				data, _ := os.ReadFile(filepath.Join(path, p.Path))
				if string(data) != "before\n" {
					t.Fatal("unexpected edit")
				}
			default:
				if !errors.Is(err, errPatchUncertain) {
					t.Fatal("missing durable staging evidence must remain unknown", receipt, err)
				}
				data, _ := os.ReadFile(filepath.Join(path, p.Path))
				if string(data) != "before\n" {
					t.Fatal("write before permit")
				}
			}
		})
	}
}

func TestPatchMutationRequiresManagedRootAndCurrentAuthorization(t *testing.T) {
	helper := buildPatchTestHelper(t, "")
	e, root, path, j, p, _ := mutationFixture(t, helper)
	root.config.ManagedWrite = false
	if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); !errors.Is(err, errForbidden) {
		t.Fatal("read-only root mutated", err)
	}
	root.config.ManagedWrite = true
	if _, err := e.execute(context.Background(), root, p, j, func() bool { return false }); !errors.Is(err, errForbidden) {
		t.Fatal("missing authorization", err)
	}
	if _, err := j.lookup(p); !errors.Is(err, errMissing) {
		t.Fatal("denied request consumed approval", err)
	}
	data, _ := os.ReadFile(filepath.Join(path, p.Path))
	if string(data) != "before\n" {
		t.Fatal("denied request changed file")
	}
}

func TestPatchUnknownStageCollisionAndMissingEvidenceStayBlocked(t *testing.T) {
	helper := buildPatchTestHelper(t, "")
	t.Run("existing private name is never overwritten", func(t *testing.T) {
		e, root, path, j, p, _ := mutationFixture(t, helper)
		filename := filepath.Join(path, ".nexus-patch-"+p.OperationID+".tmp")
		os.WriteFile(filename, []byte("unrelated existing bytes"), 0600)
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("stage collision ignored")
		}
		data, _ := os.ReadFile(filename)
		if string(data) != "unrelated existing bytes" {
			t.Fatal("unknown stage overwritten")
		}
		data, _ = os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != "before\n" {
			t.Fatal("target changed")
		}
	})
	t.Run("reply lost before durable identity", func(t *testing.T) {
		e, root, path, j, p, state := mutationFixture(t, helper)
		e.fault = func(point string) error {
			if point == "before_stage_record" {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if _, err := e.execute(context.Background(), root, p, j, func() bool { return true }); err == nil {
			t.Fatal("fault not reached")
		}
		restored := reopenMutationJournal(t, j, state)
		e.fault = nil
		if _, err := e.recover(context.Background(), root, p, restored); !errors.Is(err, errPatchUncertain) {
			t.Fatal("missing identity accepted", err)
		}
		data, _ := os.ReadFile(filepath.Join(path, p.Path))
		if string(data) != "before\n" {
			t.Fatal("unexpected edit")
		}
	})
	t.Run("cancel before dispatch consumes nothing", func(t *testing.T) {
		e, root, _, j, p, _ := mutationFixture(t, helper)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := e.execute(ctx, root, p, j, func() bool { return true }); !errors.Is(err, errForbidden) {
			t.Fatal(err)
		}
		if _, err := j.lookup(p); !errors.Is(err, errMissing) {
			t.Fatal("cancelled request consumed intent", err)
		}
	})
}

func TestPatchHelperActualFilesystemAndNetworkConfinement(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("private fixture"), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	source := fmt.Sprintf(`package main
import("encoding/json";"net";"os";"time")
func main(){
 var request map[string]any
 if json.NewDecoder(os.Stdin).Decode(&request)!=nil{os.Exit(2)}
 if _,err:=os.ReadFile(%s);err==nil{os.Exit(3)}
 if os.WriteFile("/outside.txt",[]byte("bad"),0600)==nil{os.Exit(4)}
 if c,err:=net.DialTimeout("tcp",%s,100*time.Millisecond);err==nil{c.Close();os.Exit(5)}
 if os.Getenv("HOME")!="/nonexistent"{os.Exit(6)}
 if os.WriteFile("/workspace/probe.txt",[]byte("root only"),0600)!=nil{os.Exit(7)}
 json.NewEncoder(os.Stdout).Encode(map[string]string{"phase":"confined"})
}`, strconv.Quote(outside), strconv.Quote(listener.Addr().String()))
	helper := buildPatchTestHelper(t, source)
	e, root, path, _, p, _ := mutationFixture(t, helper)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, decoder, input, err := e.start(ctx, root, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.Close()
	var reply patchHelperReply
	if err = decoder.Decode(&reply); err != nil {
		cmd.Wait()
		t.Fatal("probe", err)
	}
	if err = cmd.Wait(); err != nil || reply.Phase != "confined" {
		t.Fatal(reply, err)
	}
	if data, err := os.ReadFile(filepath.Join(path, "probe.txt")); err != nil || string(data) != "root only" {
		t.Fatal("missing root probe", err)
	}
	if data, _ := os.ReadFile(outside); string(data) != "private fixture" {
		t.Fatal("outside changed")
	}
}

func TestPatchWritePathRejectsInvisibleControls(t *testing.T) {
	for _, name := range []string{"src/a\tb.md", "src/a\u202eb.md", "src/a\u200db.md", "src/a\x01b.md"} {
		if validPatchPath(name) {
			t.Fatalf("ambiguous displayed write path accepted: %q", name)
		}
	}
	if !validPatchPath("src/café.md") {
		t.Fatal("ordinary Unicode path rejected")
	}
}

func TestManagedRootHTTPGenerationAndMutation(t *testing.T) {
	helper := buildPatchTestHelper(t, "")
	directory := privateDir(t)
	os.WriteFile(filepath.Join(directory, "README.md"), []byte("before\n"), 0600)
	cfg := config{Host: "nixos", Listen: "127.0.0.1:8896", Token: testToken, ExecutorToken: executorTestToken,
		PatchStateDir: privateDir(t), SandboxPath: commandTestBwrap, LimitPath: commandTestPrlimit,
		Roots: []rootConfig{{ID: "code", Name: "Managed", Path: directory, ManagedWrite: true, ExclusiveWriter: true}}}
	service, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	service.executor.helperPath = helper
	handler := service.handler()
	call := func(method, route, token string, payload any) *httptest.ResponseRecorder {
		var body io.Reader
		if payload != nil {
			data, _ := json.Marshal(payload)
			body = bytes.NewReader(data)
		}
		r := httptest.NewRequest(method, route, body)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	p := samplePatch()
	p.Generation = service.roots["code"].generation
	p.Proof = p.sign(executorTestToken)
	if !hex64.MatchString(p.Generation) {
		t.Fatal("missing persisted generation")
	}
	for _, route := range []string{"/v1/workspaces?host=nixos", "/v1/workspaces/code/context?host=nixos&path=README.md"} {
		w := call("GET", route, testToken, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), p.Generation) {
			t.Fatal("discovery/context missing generation", w.Code, w.Body.String())
		}
	}
	stale := p
	stale.Generation = strings.Repeat("e", 64)
	stale.Proof = stale.sign(executorTestToken)
	if w := call("POST", "/v1/workspaces/code/patches/apply", executorTestToken, stale); w.Code != 409 {
		t.Fatal("stale generation accepted", w.Code)
	}
	if w := call("POST", "/v1/workspaces/code/patches/apply", testToken, p); w.Code != 401 {
		t.Fatal("read credential wrote", w.Code)
	}
	if w := call("POST", "/v1/workspaces/code/patches/apply", executorTestToken, p); w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"applied"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	data, _ := os.ReadFile(filepath.Join(directory, "README.md"))
	if string(data) != p.Replacement {
		t.Fatal("HTTP did not apply")
	}
	originalGeneration := p.Generation
	service.close()
	restarted, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	restarted.executor.helperPath = helper
	handler = restarted.handler()
	if restarted.roots["code"].generation != originalGeneration {
		t.Fatal("generation changed across restart")
	}
	if w := call("POST", "/v1/workspaces/code/patches/receipts/"+p.OperationID+"/reconcile", executorTestToken, p); w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"applied"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestManagedRootRefusesLegacyGenerationAndOverlappingState(t *testing.T) {
	directory := privateDir(t)
	cfg := config{Host: "nixos", Listen: "127.0.0.1:8896", Token: testToken, ExecutorToken: executorTestToken,
		PatchStateDir: privateDir(t), SandboxPath: commandTestBwrap, LimitPath: commandTestPrlimit,
		Roots: []rootConfig{{ID: "code", Name: "Managed", Path: directory}}}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	path := filepath.Join(cfg.PatchStateDir, "roots.json")
	data, _ := os.ReadFile(path)
	var anchors patchRootAnchors
	if err := json.Unmarshal(data, &anchors); err != nil {
		t.Fatal(err)
	}
	anchor := anchors.Roots["code"]
	anchor.Generation = ""
	anchors.Roots["code"] = anchor
	data, _ = json.Marshal(anchors)
	os.WriteFile(path, data, 0600)
	cfg.Roots[0].ManagedWrite = true
	cfg.Roots[0].ExclusiveWriter = true
	if s, err := newServer(cfg); err == nil {
		s.close()
		t.Fatal("legacy root implicitly enabled writes")
	}
	cfg.PatchStateDir = directory
	if cfg.validate() == nil {
		t.Fatal("receipt state inside mutable workspace accepted")
	}
}
