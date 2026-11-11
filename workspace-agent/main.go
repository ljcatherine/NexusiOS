// Nexus workspace agent. Linux-only: file access uses descriptor-relative openat.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	maxRequestBytes = 4096
	maxReadBytes    = 64 << 10
	maxEntries      = 128
	maxRoots        = 16
)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

type rootConfig struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	GitRead         bool     `json:"git_read,omitempty"`
	ManagedWrite    bool     `json:"managed_write,omitempty"`
	ExclusiveWriter bool     `json:"exclusive_writer,omitempty"`
	CommandProfiles []string `json:"command_profiles,omitempty"`
}

type config struct {
	Host                                                      string
	Listen                                                    string
	Token                                                     string
	ExecutorToken                                             string
	PatchStateDir                                             string
	Roots                                                     []rootConfig
	AllowWAN                                                  bool
	GitPath, SandboxPath, LimitPath                           string
	CommandExecutorToken, CommandStateDir, CommandSnapshotDir string
	ScopePath, ControlPath                                    string
	CommandProfiles                                           []commandProfilePolicy
}

func fromEnv() (config, error) {
	cfg := config{
		Host:          strings.TrimSpace(os.Getenv("NEXUS_WORKSPACE_HOST")),
		Listen:        strings.TrimSpace(os.Getenv("NEXUS_WORKSPACE_LISTEN")),
		Token:         os.Getenv("NEXUS_WORKSPACE_TOKEN"),
		ExecutorToken: os.Getenv("NEXUS_WORKSPACE_EXECUTOR_TOKEN"),
		PatchStateDir: os.Getenv("NEXUS_WORKSPACE_PATCH_STATE_DIR"),
		AllowWAN:      os.Getenv("NEXUS_WORKSPACE_ALLOW_NON_LOOPBACK") == "1",
		GitPath:       os.Getenv("NEXUS_WORKSPACE_GIT_EXECUTABLE"),
		SandboxPath:   os.Getenv("NEXUS_WORKSPACE_BWRAP_EXECUTABLE"),
		LimitPath:     os.Getenv("NEXUS_WORKSPACE_PRLIMIT_EXECUTABLE"),
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8896"
	}
	if err := json.Unmarshal([]byte(os.Getenv("NEXUS_WORKSPACE_ROOTS_JSON")), &cfg.Roots); err != nil {
		return config{}, errors.New("NEXUS_WORKSPACE_ROOTS_JSON must be a JSON array")
	}
	if err := cfg.commandEnv(); err != nil {
		return config{}, err
	}
	return cfg, cfg.validate()
}

func (c config) validate() error {
	if !identifier.MatchString(c.Host) {
		return errors.New("NEXUS_WORKSPACE_HOST must be a simple host identifier")
	}
	if len(c.Token) < 32 || len(c.Token) > 256 || strings.ContainsAny(c.Token, " \t\r\n") {
		return errors.New("NEXUS_WORKSPACE_TOKEN must contain 32–256 non-whitespace characters")
	}
	if c.ExecutorToken != "" && (!validExecutorToken(c.ExecutorToken) || c.ExecutorToken == c.Token) {
		return errors.New("executor credential must be distinct from the read credential and contain 32–256 non-whitespace characters")
	}
	if len(c.Roots) == 0 || len(c.Roots) > maxRoots {
		return fmt.Errorf("configure between 1 and %d workspace roots", maxRoots)
	}
	listenHost, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid NEXUS_WORKSPACE_LISTEN: %w", err)
	}
	ip := net.ParseIP(listenHost)
	if !c.AllowWAN && (ip == nil || !ip.IsLoopback()) {
		return errors.New("non-loopback listener refused; use loopback with a private authenticated proxy")
	}
	if c.ExecutorToken != "" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("executor credential requires a loopback listener; use an authenticated SSH tunnel or HTTPS proxy")
	}
	if c.PatchStateDir != "" && c.ExecutorToken == "" {
		return errors.New("patch receipt state requires a separate executor credential")
	}
	seen := make(map[string]bool)
	for _, root := range c.Roots {
		if !identifier.MatchString(root.ID) || seen[root.ID] {
			return errors.New("workspace IDs must be distinct lowercase identifiers")
		}
		seen[root.ID] = true
		if c.PatchStateDir != "" && (c.PatchStateDir == root.Path || strings.HasPrefix(c.PatchStateDir, root.Path+"/") || strings.HasPrefix(root.Path, c.PatchStateDir+"/")) {
			return errors.New("patch state must be outside every workspace root")
		}
		// Mutations are opt-in and require independent executor credentials/state.
		if root.ManagedWrite {
			var targetFS, stateFS syscall.Statfs_t
			localPersistent := func(kind int64) bool { return kind == 0xef53 || kind == 0x58465342 || kind == 0x9123683e }
			if syscall.Statfs(root.Path, &targetFS) != nil || syscall.Statfs(c.PatchStateDir, &stateFS) != nil || !localPersistent(targetFS.Type) || !localPersistent(stateFS.Type) {
				return errors.New("managed writes require local ext4, XFS or Btrfs for workspace and receipt state")
			}
			if !root.ExclusiveWriter {
				return errors.New("managed_write requires explicit exclusive_writer trust: private owned directories and no untrusted writers")
			}
			if c.ExecutorToken == "" || c.PatchStateDir == "" || c.SandboxPath == "" || c.LimitPath == "" {
				return errors.New("managed_write requires executor credential, durable state and trusted sandbox tools")
			}
		}
		if len(root.Name) == 0 || len(root.Name) > 80 || strings.ContainsAny(root.Name, "\r\n\x00") {
			return errors.New("workspace names must contain 1–80 printable characters")
		}
		if !filepath.IsAbs(root.Path) || filepath.Clean(root.Path) != root.Path || root.Path == "/" {
			return errors.New("workspace roots must be absolute, clean, and not the filesystem root")
		}
		canonical, err := filepath.EvalSymlinks(root.Path)
		if err != nil || canonical != root.Path {
			return errors.New("workspace roots must exist and contain no symlink components")
		}
	}
	return c.validateCommands()
}

type workspace struct {
	config     rootConfig
	fd         int
	generation string
}

type server struct {
	host             string
	key              [32]byte
	executorToken    string
	patchJournal     *patchJournal
	executor         *patchExecutor
	roots            map[string]*workspace
	tasks            chan struct{}
	git              *gitInspector
	commands         *commandRunner
	commandJournal   *commandJournal
	commandSnapshots *commandSnapshotStore
	commandToken     string
	commandRequests  chan struct{}
}

func newServer(cfg config) (*server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &server{executorToken: cfg.ExecutorToken, host: cfg.Host, key: sha256.Sum256([]byte(cfg.Token)), roots: make(map[string]*workspace), tasks: make(chan struct{}, 4)}
	for _, root := range cfg.Roots {
		if root.GitRead && s.git == nil {
			var err error
			s.git, err = newGitInspector(cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, root := range cfg.Roots {
		fd, err := openConfiguredRoot(root.Path)
		if err != nil {
			s.close()
			return nil, errors.New("could not open a configured workspace root")
		}
		if root.ManagedWrite {
			if privateOwned(fd, true) != nil {
				syscall.Close(fd)
				s.close()
				return nil, errors.New("managed root must be private and owned by the service")
			}
			if s.executor == nil {
				var err error
				s.executor, err = newPatchExecutor(cfg.SandboxPath, cfg.LimitPath)
				if err != nil {
					syscall.Close(fd)
					s.close()
					return nil, err
				}
			}
		}
		s.roots[root.ID] = &workspace{config: root, fd: fd}
	}
	if cfg.PatchStateDir != "" {
		var err error
		s.patchJournal, err = openPatchJournal(cfg.PatchStateDir)
		if err != nil {
			s.close()
			return nil, err
		}
		if err = s.patchJournal.bindRoots(cfg.Host, s.roots); err != nil {
			s.close()
			return nil, err
		}
	}
	if err := s.setupCommands(cfg); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *server) close() {
	if s.commandJournal != nil {
		s.commandJournal.close()
	}
	if s.commandSnapshots != nil {
		s.commandSnapshots.close()
	}
	if s.patchJournal != nil {
		s.patchJournal.close()
	}
	for _, root := range s.roots {
		_ = syscall.Close(root.fd)
	}
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { sendJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("GET /v1/workspaces", s.authorize(http.HandlerFunc(s.listRoots)))
	mux.Handle("GET /v1/workspaces/{id}/files", s.authorize(http.HandlerFunc(s.listFiles)))
	mux.Handle("GET /v1/workspaces/{id}/context", s.authorize(http.HandlerFunc(s.context)))
	mux.Handle("POST /v1/subagents/tasks", s.authorize(http.HandlerFunc(s.runTask)))
	mux.Handle("POST /v1/workspaces/{id}/patches/apply", s.authorizeExecutor(http.HandlerFunc(s.applyPatch)))
	mux.Handle("GET /v1/workspaces/{id}/patches/receipts/{operation_id}", s.authorizeExecutor(http.HandlerFunc(s.patchReceiptLookup)))
	mux.Handle("POST /v1/workspaces/{id}/patches/receipts/{operation_id}/reconcile", s.authorizeExecutor(http.HandlerFunc(s.reconcilePatch)))
	s.registerCommands(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { sendError(w, http.StatusNotFound, "not_found") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		head := r.Header.Values("Authorization")
		if len(head) != 1 {
			sendError(w, 401, "authentication_required")
			return
		}
		parts := strings.Fields(head[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 256 {
			sendError(w, 401, "authentication_required")
			return
		}
		digest := sha256.Sum256([]byte(parts[1]))
		if subtle.ConstantTimeCompare(digest[:], s.key[:]) != 1 {
			sendError(w, 401, "invalid_authentication")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) requireHost(w http.ResponseWriter, host string) bool {
	if host != s.host {
		sendError(w, http.StatusBadRequest, "host_mismatch")
		return false
	}
	return true
}

func (s *server) root(w http.ResponseWriter, id string) *workspace {
	root, ok := s.roots[id]
	if !ok {
		sendError(w, http.StatusNotFound, "unknown_workspace")
		return nil
	}
	return root
}

func (s *server) listRoots(w http.ResponseWriter, r *http.Request) {
	if !s.requireHost(w, r.URL.Query().Get("host")) {
		return
	}
	type item struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		ReadOnly     bool     `json:"read_only"`
		Capabilities []string `json:"capabilities"`
		Generation   string   `json:"generation,omitempty"`
	}
	items := make([]item, 0, len(s.roots))
	for _, root := range s.roots {
		capabilities := []string{"list", "read_file", "inventory", "find_text"}
		if root.config.GitRead && s.git != nil {
			capabilities = append(capabilities, "git_status", "git_diff", "git_diff_staged")
		}
		if root.config.ManagedWrite && s.executor != nil {
			capabilities = append(capabilities, "apply_patch")
		}
		// Restricted commands are separately opt-in and independently authorized;
		// they never turn a read-only workspace into a writable one. Discovery
		// must agree with the registered profile/prepare/execute handlers so the
		// parent can validate generation and exact fixed profile before review.
		if s.commands != nil && root.generation != "" && len(root.config.CommandProfiles) != 0 {
			capabilities = append(capabilities, "run_command")
		}
		items = append(items, item{root.config.ID, root.config.Name, !root.config.ManagedWrite, capabilities, root.generation})
	}
	// Stable UI ordering; do not disclose host filesystem paths.
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	sendJSON(w, 200, map[string]any{"host": s.host, "workspaces": items})
}

func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	if !s.requireHost(w, r.URL.Query().Get("host")) {
		return
	}
	root := s.root(w, r.PathValue("id"))
	if root == nil {
		return
	}
	path := r.URL.Query().Get("path")
	entries, truncated, err := root.list(path, maxEntries)
	if err != nil {
		respondFSError(w, err)
		return
	}
	sendJSON(w, 200, map[string]any{"host": s.host, "workspace_id": root.config.ID, "path": path, "entries": entries, "truncated": truncated})
}

func (s *server) context(w http.ResponseWriter, r *http.Request) {
	if !s.requireHost(w, r.URL.Query().Get("host")) {
		return
	}
	root := s.root(w, r.PathValue("id"))
	if root == nil {
		return
	}
	path := r.URL.Query().Get("path")
	text, err := root.readText(path)
	if err != nil {
		respondFSError(w, err)
		return
	}
	result := map[string]any{"host": s.host, "workspace_id": root.config.ID, "path": path, "text": text, "size_bytes": len(text)}
	if root.config.ManagedWrite && root.generation != "" {
		snapshot, err := root.inspectPatchFile(path)
		if err == nil && snapshot.Text == text {
			result["workspace_generation"] = root.generation
		}
	}
	sendJSON(w, 200, result)
}

func sendJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func sendError(w http.ResponseWriter, status int, code string) {
	sendJSON(w, status, map[string]string{"error": code})
}

func respondFSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidPath):
		sendError(w, 400, "invalid_path")
	case errors.Is(err, errForbidden):
		sendError(w, 403, "path_forbidden")
	case errors.Is(err, errMissing):
		sendError(w, 404, "not_found")
	case errors.Is(err, errTooLarge):
		sendError(w, 413, "content_too_large")
	case errors.Is(err, errNotText):
		sendError(w, 415, "not_text")
	default:
		sendError(w, 400, "invalid_resource")
	}
}

func main() {
	cfg, err := fromEnv()
	if err != nil {
		log.Fatal(err)
	}
	s, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer s.close()
	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 12 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	log.Printf("Nexus workspace agent ready: host=%s (roots=%d); access requires bearer authentication", cfg.Host, len(cfg.Roots))
	log.Fatal(httpServer.ListenAndServe())
}
