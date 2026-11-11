package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testToken = "z8Pv6DQ7hcNGT2e5S0q4rBW9avYHjK3L"

type testHarness struct {
	root    string
	server  *server
	handler http.Handler
}

func setup(t *testing.T) testHarness {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"README.md":        "Welcome to Nexus\nThe project is safe\n",
		"main.go":          "package main\n// Nexus runtime\n",
		"config.json":      "{\"name\":\"demo\"}\n",
		".env":             "SUPER_SECRET_DO_NOT_RETURN\n",
		"credentials.json": "PRIVATE_CREDENTIAL_DO_NOT_RETURN\n",
		"private_key.txt":  "PRIVATE_KEY_DO_NOT_RETURN\n",
		"binary.txt":       "\x00bin\n",
		"image.png":        "not an image",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "hello.py"), []byte("# Nexus source\nprint('hi')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte("LEAK"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "outside.txt"), filepath.Join(root, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	cfg := config{Host: "nixos", Listen: "127.0.0.1:8896", Token: testToken, Roots: []rootConfig{{ID: "code", Name: "Code", Path: root}}}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return testHarness{root: root, server: s, handler: s.handler()}
}

func request(h testHarness, method, uri, bearer, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, uri, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}

func TestAuthenticationAndHostBinding(t *testing.T) {
	h := setup(t)
	for _, tc := range []struct {
		name, token, uri string
		status           int
	}{
		{"missing", "", "/v1/workspaces?host=nixos", 401},
		{"wrong", strings.Repeat("a", 32), "/v1/workspaces?host=nixos", 401},
		{"host-other", "" + testToken, "/v1/workspaces?host=debian", 400},
		{"host-missing", testToken, "/v1/workspaces", 400},
		{"success", testToken, "/v1/workspaces?host=nixos", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(h, "GET", tc.uri, tc.token, "")
			if r.Code != tc.status {
				t.Fatalf("status %d body %s", r.Code, r.Body.String())
			}
			if r.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
	r := request(h, "GET", "/v1/workspaces?host=nixos", testToken, "")
	if strings.Contains(r.Body.String(), h.root) {
		t.Fatal("filesystem root path leaked")
	}
	if !strings.Contains(r.Body.String(), `"id":"code"`) {
		t.Fatal(r.Body.String())
	}
	dup := httptest.NewRequest("GET", "/v1/workspaces?host=nixos", nil)
	dup.Header.Add("Authorization", "Bearer "+testToken)
	dup.Header.Add("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, dup)
	if w.Code != 401 {
		t.Fatalf("duplicate authorization headers accepted: %d", w.Code)
	}
}

func TestTraversalAndSymlinkDenied(t *testing.T) {
	h := setup(t)
	paths := []string{"../README.md", "/etc/passwd", "src/../README.md", "src//README.md", "src/./README.md", ".env", "external/outside.txt", "linked.txt", "src%5C..%5CREADME.md", "src/%2e%2e/README.md"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			uri := "/v1/workspaces/code/context?host=nixos&path=" + p
			r := request(h, "GET", uri, testToken, "")
			if r.Code == 200 {
				t.Fatalf("accepted unsafe path %s: %s", p, r.Body.String())
			}
			if strings.Contains(r.Body.String(), "LEAK") {
				t.Fatal("outside root leaked")
			}
		})
	}
	for _, p := range []string{"external", "../", ".git"} {
		r := request(h, "GET", "/v1/workspaces/code/files?host=nixos&path="+p, testToken, "")
		if r.Code == 200 {
			t.Fatalf("unsafe listing %q accepted: %s", p, r.Body.String())
		}
	}
}

func TestReadOnlyContextAndFilteredListing(t *testing.T) {
	h := setup(t)
	r := request(h, "GET", "/v1/workspaces/code/files?host=nixos", testToken, "")
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	for _, forbidden := range []string{".env", "linked.txt", "external", "credentials.json", "private_key.txt", "image.png"} {
		if strings.Contains(r.Body.String(), forbidden) {
			t.Fatalf("sensitive entry %q exposed: %s", forbidden, r.Body.String())
		}
	}
	if !strings.Contains(r.Body.String(), `"name":"src"`) {
		t.Fatal("directory absent", r.Body.String())
	}
	r = request(h, "GET", "/v1/workspaces/code/context?host=nixos&path=src/hello.py", testToken, "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "Nexus source") {
		t.Fatal(r.Code, r.Body.String())
	}
	for _, path := range []string{"binary.txt", "image.png", "credentials.json", ".env"} {
		r = request(h, "GET", "/v1/workspaces/code/context?host=nixos&path="+path, testToken, "")
		if r.Code == 200 {
			t.Fatalf("sensitive/binary file read: %s", path)
		}
	}
	if err := os.WriteFile(filepath.Join(h.root, "oversized.md"), bytes.Repeat([]byte("x"), maxReadBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	r = request(h, "GET", "/v1/workspaces/code/context?host=nixos&path=oversized.md", testToken, "")
	if r.Code != 413 {
		t.Fatal(r.Code, r.Body.String())
	}
	if _, err := os.Stat(filepath.Join(h.root, "README.md")); err != nil {
		t.Fatal("read unexpectedly mutated source")
	}
}

func TestTasksInventorySearchAndValidation(t *testing.T) {
	h := setup(t)
	for _, tc := range []struct {
		body     string
		status   int
		contains string
	}{
		{`{"host":"nixos","workspace_id":"code","operation":"inventory","path":""}`, 200, "src/hello.py"},
		{`{"host":"nixos","workspace_id":"code","operation":"find_text","path":"","query":"Nexus"}`, 200, "README.md"},
		{`{"host":"nixos","workspace_id":"code","operation":"find_text","path":"src","query":"Nexus"}`, 200, "hello.py"},
		{`{"host":"debian","workspace_id":"code","operation":"inventory"}`, 400, "host_mismatch"},
		{`{"host":"nixos","workspace_id":"code","operation":"shell","command":"rm -rf /"}`, 400, "invalid_task"},
		{`{"host":"nixos","workspace_id":"code","operation":"run_shell"}`, 400, "unsupported_operation"},
		{`{"host":"nixos","workspace_id":"code","operation":"find_text","query":"x"}`, 400, "invalid_query"},
		{`{"host":"nixos","workspace_id":"code","operation":"inventory","path":"../"}`, 400, "invalid_path"},
		{`{"host":"nixos","workspace_id":"code","operation":"inventory"}{} `, 400, "invalid_task"},
	} {
		r := request(h, "POST", "/v1/subagents/tasks", testToken, tc.body)
		if r.Code != tc.status || !strings.Contains(r.Body.String(), tc.contains) {
			t.Errorf("body %s: got %d/%s expected %d and %q", tc.body, r.Code, r.Body.String(), tc.status, tc.contains)
		}
	}
	oversize := fmt.Sprintf(`{"host":"nixos","workspace_id":"code","operation":"inventory","garbage":"%s"}`, strings.Repeat("x", maxRequestBytes))
	if request(h, "POST", "/v1/subagents/tasks", testToken, oversize).Code == 200 {
		t.Fatal("oversized task accepted")
	}
}

func TestConcurrentAccessAndBoundedInventory(t *testing.T) {
	h := setup(t)
	for i := 0; i < 150; i++ {
		name := fmt.Sprintf("file%03d.txt", i)
		if err := os.WriteFile(filepath.Join(h.root, name), []byte("Nexus\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r := request(h, "GET", "/v1/workspaces/code/files?host=nixos", testToken, "")
			if r.Code != 200 {
				t.Errorf("concurrent request returned %d", r.Code)
			}
		}()
	}
	group.Wait()
	r := request(h, "POST", "/v1/subagents/tasks", testToken, `{"host":"nixos","workspace_id":"code","operation":"inventory"}`)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var response struct {
		Entries   []fileEntry `json:"entries"`
		Truncated bool        `json:"truncated"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) > maxEntries || !response.Truncated {
		t.Fatalf("inventory not bounded: %d truncated=%v", len(response.Entries), response.Truncated)
	}
}

func TestSearchLimitsAndSpecialBasenames(t *testing.T) {
	h := setup(t)
	if err := os.WriteFile(filepath.Join(h.root, "Dockerfile"), []byte("FROM scratch\n# Nexus image\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		file := fmt.Sprintf("match%02d.md", i)
		content := strings.Repeat("Nexus line\n", 5)
		if err := os.WriteFile(filepath.Join(h.root, file), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := request(h, "GET", "/v1/workspaces/code/context?host=nixos&path=Dockerfile", testToken, "")
	if r.Code != 200 {
		t.Fatal("Dockerfile denied", r.Code, r.Body.String())
	}
	r = request(h, "POST", "/v1/subagents/tasks", testToken, `{"host":"nixos","workspace_id":"code","operation":"find_text","path":"","query":"Nexus"}`)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var result taskResult
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Hits) > 20 || result.Scanned > 24 || !result.Truncated {
		t.Fatalf("search limits not applied: hits=%d scanned=%d truncated=%v", len(result.Hits), result.Scanned, result.Truncated)
	}
}

func TestTwoHostsWithSharedWorkspaceIDsAreIsolated(t *testing.T) {
	first := setup(t)
	secondRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(secondRoot, "README.md"), []byte("Debian only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config{Host: "debian", Listen: "127.0.0.1:8896", Token: strings.Repeat("B", 40), Roots: []rootConfig{{ID: "code", Name: "Debian Code", Path: secondRoot}}}
	second, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.close)
	debian := testHarness{root: secondRoot, server: second, handler: second.handler()}
	for _, tc := range []struct {
		h                 testHarness
		host, token, want string
	}{
		{first, "nixos", testToken, "Welcome to Nexus"},
		{debian, "debian", cfg.Token, "Debian only"},
	} {
		r := request(tc.h, "GET", "/v1/workspaces/code/context?host="+tc.host+"&path=README.md", tc.token, "")
		if r.Code != 200 || !strings.Contains(r.Body.String(), tc.want) {
			t.Fatalf("host isolation failed: %d %s", r.Code, r.Body.String())
		}
	}
	if response := request(debian, "GET", "/v1/workspaces/code/context?host=nixos&path=README.md", cfg.Token, ""); response.Code != 400 {
		t.Fatal("cross host query accepted")
	}
	if response := request(debian, "GET", "/v1/workspaces/code/context?host=debian&path=README.md", testToken, ""); response.Code != 401 {
		t.Fatal("cross host token accepted")
	}
}

func TestConfigValidationFailsClosed(t *testing.T) {
	h := setup(t)
	base := config{Host: "debian", Listen: "127.0.0.1:8896", Token: testToken, Roots: []rootConfig{{ID: "code", Name: "Code", Path: h.root}}}
	for name, mutate := range map[string]func(*config){
		"short-token":    func(c *config) { c.Token = "weak" },
		"all-interfaces": func(c *config) { c.Listen = "0.0.0.0:8896" },
		"missing-host":   func(c *config) { c.Host = "" },
		"root-fs":        func(c *config) { c.Roots[0].Path = "/" },
		"relative-root":  func(c *config) { c.Roots[0].Path = "somewhere" },
		"duplicate-root": func(c *config) { c.Roots = append(c.Roots, c.Roots[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			c.Roots = append([]rootConfig(nil), base.Roots...)
			mutate(&c)
			if err := c.validate(); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(h.root, link); err != nil {
		t.Fatal(err)
	}
	base.Roots[0].Path = link
	if err := base.validate(); err == nil {
		t.Fatal("symlink root accepted")
	}
	base.Roots[0].Path = h.root
	base.AllowWAN = true
	base.Listen = "0.0.0.0:8896"
	if err := base.validate(); err != nil {
		t.Fatal("explicit opt in refused", err)
	}
}
