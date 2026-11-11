package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func commandServiceTestConfig(t *testing.T) config {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "code")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return config{
		Host:                 "nixos",
		Listen:               "127.0.0.1:8896",
		Token:                strings.Repeat("r", 48),
		CommandExecutorToken: strings.Repeat("c", 48),
		CommandStateDir:      filepath.Join(base, "command-journal"),
		CommandSnapshotDir:   filepath.Join(base, "command-snapshots"),
		SandboxPath:          "/usr/bin/bwrap",
		LimitPath:            "/usr/bin/prlimit",
		ScopePath:            "/usr/bin/systemd-run",
		ControlPath:          "/usr/bin/systemctl",
		Roots:                []rootConfig{{ID: "code", Name: "Code", Path: root, CommandProfiles: []string{"probe"}}},
		CommandProfiles:      []commandProfilePolicy{{ID: "probe", Executable: "/bin/sh", Limits: commandProfileLimits{TimeoutMS: 1000}}},
	}
}

func TestCommandServiceConfigRequiresExplicitIndependentAuthority(t *testing.T) {
	cfg := commandServiceTestConfig(t)
	if err := cfg.validate(); err != nil {
		t.Fatalf("valid opt-in rejected: %v", err)
	}
	checks := []struct {
		name string
		edit func(*config)
	}{
		{"no profiles", func(c *config) { c.CommandProfiles = nil }},
		{"no root opt-in", func(c *config) { c.Roots[0].CommandProfiles = nil }},
		{"read credential reused", func(c *config) { c.CommandExecutorToken = c.Token }},
		{"patch credential reused", func(c *config) { c.ExecutorToken = c.CommandExecutorToken }},
		{"no command credential", func(c *config) { c.CommandExecutorToken = "" }},
		{"non-loopback command listener", func(c *config) { c.Listen = "0.0.0.0:8896"; c.AllowWAN = true }},
		{"no sandbox", func(c *config) { c.SandboxPath = "" }},
		{"same journal and snapshot directory", func(c *config) { c.CommandSnapshotDir = c.CommandStateDir }},
		{"nested state directories", func(c *config) { c.CommandSnapshotDir = filepath.Join(c.CommandStateDir, "captures") }},
		{"state inside workspace", func(c *config) { c.CommandStateDir = filepath.Join(c.Roots[0].Path, "private") }},
		{"unknown root profile", func(c *config) { c.Roots[0].CommandProfiles = []string{"unconfigured"} }},
		{"duplicate profile policy", func(c *config) { c.CommandProfiles = append(c.CommandProfiles, c.CommandProfiles[0]) }},
		{"unbounded profile deadline", func(c *config) { c.CommandProfiles[0].Limits.TimeoutMS = 30001 }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			copy := cfg
			copy.Roots = append([]rootConfig(nil), cfg.Roots...)
			copy.Roots[0].CommandProfiles = append([]string(nil), cfg.Roots[0].CommandProfiles...)
			copy.CommandProfiles = append([]commandProfilePolicy(nil), cfg.CommandProfiles...)
			check.edit(&copy)
			if err := copy.validate(); err == nil {
				t.Fatal("unsafe command configuration accepted")
			}
		})
	}
}

func TestCommandServiceRoutesDefaultOffAndRoleSeparated(t *testing.T) {
	cfg := commandServiceTestConfig(t)
	readToken, executeToken := cfg.Token, cfg.CommandExecutorToken
	cfg.CommandExecutorToken, cfg.CommandStateDir, cfg.CommandSnapshotDir = "", "", ""
	cfg.ScopePath, cfg.ControlPath = "", ""
	cfg.CommandProfiles = nil
	cfg.Roots[0].CommandProfiles = nil
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	call := func(handler http.Handler, method, path, token, body string) int {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	path := "/v1/workspaces/code/commands/profiles?host=nixos"
	if code := call(s.handler(), http.MethodGet, path, readToken, ""); code != 404 {
		t.Fatalf("command routes must not exist by default: HTTP %d", code)
	}

	// Use a non-executing in-memory runner to inspect route/auth boundaries.
	// No sandbox, command journal, machine service or remote host is touched.
	s.commands = &commandRunner{profiles: map[string]commandProfile{"probe": {ID: "probe", Timeout: 1000}}}
	s.roots["code"].config.CommandProfiles = []string{"probe"}
	s.roots["code"].generation = strings.Repeat("a", 64)
	s.commandToken = executeToken
	s.commandRequests = make(chan struct{}, 4)
	handler := s.handler()
	for _, tc := range []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"read may list fixed profiles", "GET", path, readToken, "", 200},
		{"executor cannot use read profile route", "GET", path, executeToken, "", 401},
		{"wrong host refused", "GET", "/v1/workspaces/code/commands/profiles?host=debian", readToken, "", 400},
		{"read cannot execute", "POST", "/v1/workspaces/code/commands/execute", readToken, `{}`, 401},
		{"missing command executor refused", "POST", "/v1/workspaces/code/commands/execute", "", `{}`, 401},
		{"executor cannot prepare", "POST", "/v1/workspaces/code/commands/prepare", executeToken, `{}`, 401},
		{"executor malformed command denied", "POST", "/v1/workspaces/code/commands/execute", executeToken, `{}`, 400},
		{"executor malformed reconcile denied", "POST", "/v1/workspaces/code/commands/receipts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/reconcile", executeToken, `{}`, 400},
		{"read cannot cancel", "POST", "/v1/workspaces/code/commands/receipts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cancel", readToken, `{}`, 401},
		{"missing executor cannot cancel", "POST", "/v1/workspaces/code/commands/receipts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cancel", "", `{}`, 401},
		{"malformed signed cancel denied", "POST", "/v1/workspaces/code/commands/receipts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cancel", executeToken, `{}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := call(handler, tc.method, tc.path, tc.token, tc.body); code != tc.want {
				t.Fatalf("got HTTP %d, want %d", code, tc.want)
			}
		})
	}
}
