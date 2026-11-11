package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Git is an explicit per-root capability. Never fall back to an unsandboxed
// command if namespaces, resource limits or any configured tool are unavailable.
type gitInspector struct{ git, sandbox, limit string }

var errGitUnavailable = errors.New("Git inspection unavailable")

type gitChange struct {
	Path     string `json:"path"`
	Index    string `json:"index"`
	Worktree string `json:"worktree"`
}
type gitResult struct {
	Path      string      `json:"path"`
	Changes   []gitChange `json:"changes"`
	Diff      string      `json:"diff"`
	Truncated bool        `json:"truncated"`
}

func trustedProgram(input string) (string, error) {
	if !filepath.IsAbs(input) {
		return "", errForbidden
	}
	resolved, err := filepath.EvalSymlinks(input)
	if err != nil {
		return "", errForbidden
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return "", errForbidden
	}
	// Nix packages have immutable permissions and can have a remapped store
	// owner in development containers. Validate the package subtree itself.
	if strings.HasPrefix(resolved, "/nix/store/") {
		for current := resolved; current != "/nix/store"; current = filepath.Dir(current) {
			entry, err := os.Stat(current)
			if err != nil || entry.Mode().Perm()&0222 != 0 {
				return "", errForbidden
			}
		}
		return resolved, nil
	}
	// Tools and their ancestry must be administered independently of the agent.
	for current := resolved; ; current = filepath.Dir(current) {
		entry, err := os.Stat(current)
		if err != nil {
			return "", errForbidden
		}
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || (current != "/nix/store" && entry.Mode().Perm()&0022 != 0) {
			return "", errForbidden
		}
		if current == "/" {
			break
		}
	}
	return resolved, nil
}

func newGitInspector(cfg config) (*gitInspector, error) {
	git, err1 := trustedProgram(cfg.GitPath)
	sandbox, err2 := trustedProgram(cfg.SandboxPath)
	limit, err3 := trustedProgram(cfg.LimitPath)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("Git inspection requires trusted Git, bubblewrap and prlimit executables")
	}
	return &gitInspector{git: git, sandbox: sandbox, limit: limit}, nil
}

// This is a fixed runtime mount policy, not a caller-controlled bind list.
// /etc, /home, /run, host /proc, temporary files and other workspaces are absent.
func (g *gitInspector) sandboxArgs() []string {
	args := []string{"--as=536870912", "--cpu=3", "--nofile=128", "--fsize=0", "--core=0", "--",
		g.sandbox, "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"}
	for _, runtime := range []string{"/nix/store", "/usr/bin", "/usr/lib", "/usr/lib64", "/bin", "/lib", "/lib64"} {
		if info, err := os.Stat(runtime); err == nil && info.IsDir() {
			args = append(args, "--ro-bind", runtime, runtime)
		}
	}
	args = append(args, "--ro-bind-fd", "3", "/workspace", "--ro-bind-fd", "4", "/git-metadata",
		// Ignore repository config entirely: clean filters can execute commands
		// even when diff's --no-ext-diff and --no-textconv flags are present.
		"--ro-bind-data", "5", "/git-metadata/config",
		"--dev", "/dev", "--chdir", "/workspace", "--remount-ro", "/")
	for _, pair := range [][2]string{
		{"HOME", "/nonexistent"}, {"PATH", "/nonexistent"}, {"LC_ALL", "C"},
		{"GIT_CONFIG_NOSYSTEM", "1"}, {"GIT_CONFIG_SYSTEM", "/dev/null"}, {"GIT_CONFIG_GLOBAL", "/dev/null"},
		{"GIT_ATTR_NOSYSTEM", "1"}, {"GIT_OPTIONAL_LOCKS", "0"}, {"GIT_TERMINAL_PROMPT", "0"},
		{"GIT_NO_LAZY_FETCH", "1"},
	} {
		args = append(args, "--setenv", pair[0], pair[1])
	}
	return args
}

type cappedBuffer struct {
	buffer   bytes.Buffer // Do not embed Buffer: its ReaderFrom bypasses Write's cap.
	exceeded bool
	cancel   context.CancelFunc
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > maxReadBytes {
		b.exceeded = true
		if b.cancel != nil {
			b.cancel()
		}
		return 0, errTooLarge
	}
	return b.buffer.Write(p)
}

func (g *gitInspector) run(ctx context.Context, root *workspace, args []string) ([]byte, error) {
	rootFD, err := syscall.Dup(root.fd)
	if err != nil {
		return nil, errForbidden
	}
	directory := os.NewFile(uintptr(rootFD), "workspace-root")
	defer directory.Close()
	// External gitdirs and linked worktrees require separate administration;
	// never follow their .git pointer files or symlinks outside the allowed root.
	gitFD, err := syscall.Openat(root.fd, ".git", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errForbidden
	}
	metadata := os.NewFile(uintptr(gitFD), "git-metadata")
	defer metadata.Close()
	emptyConfig, err := os.Open("/dev/null")
	if err != nil {
		return nil, errForbidden
	}
	defer emptyConfig.Close()
	command := append(g.sandboxArgs(), "--", g.git,
		"--no-pager", "--no-optional-locks", "--literal-pathspecs", "--git-dir=/git-metadata", "--work-tree=/workspace",
		"-c", "safe.directory=/workspace", "-c", "core.bare=false", "-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=/nonexistent", "-c", "core.untrackedCache=false",
		"-c", "core.excludesFile=/dev/null", "-c", "core.attributesFile=/dev/null", "-c", "color.ui=false")
	command = append(command, args...)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, g.limit, command...)
	cmd.ExtraFiles = []*os.File{directory, metadata, emptyConfig}
	cmd.Env = []string{"LC_ALL=C", "PATH=/nonexistent"}
	cmd.WaitDelay = 250 * time.Millisecond
	output := cappedBuffer{cancel: cancel}
	cmd.Stdout = &output
	cmd.Stderr = io.Discard // Never return Git's filesystem paths or config errors.
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if output.exceeded {
		return nil, errTooLarge
	}
	if err != nil {
		return nil, errGitUnavailable
	}
	return output.buffer.Bytes(), nil
}

func safeGitPath(path string) bool {
	parts, err := segments(path, false)
	if err != nil {
		return false
	}
	for _, part := range parts {
		if forbiddenFilename(part) {
			return false
		}
	}
	return allowedTextFilename(parts[len(parts)-1])
}

func (g *gitInspector) inspect(ctx context.Context, root *workspace, operation, relative string) (*gitResult, error) {
	result := &gitResult{Path: relative, Changes: []gitChange{}}
	if operation == "git_status" {
		parts, err := segments(relative, true)
		if err != nil {
			return nil, err
		}
		dir, err := root.openDir(parts)
		if err != nil {
			return nil, err
		}
		dir.Close()
		scope := relative
		if scope == "" {
			scope = "."
		}
		output, err := g.run(ctx, root, []string{"status", "--porcelain=v1", "-z", "--untracked-files=no", "--ignore-submodules=all", "--no-renames", "--", scope})
		if err != nil {
			return nil, err
		}
		if len(output) > 0 && output[len(output)-1] != 0 {
			return nil, errNotText
		}
		for _, item := range bytes.Split(output, []byte{0}) {
			if len(item) == 0 {
				continue
			}
			if len(item) < 4 || item[2] != ' ' || !strings.ContainsRune(" MADTURC", rune(item[0])) || !strings.ContainsRune(" MADTURC", rune(item[1])) {
				return nil, errNotText
			}
			path := string(item[3:])
			if !safeGitPath(path) {
				continue
			}
			if relative != "" && !strings.HasPrefix(path, relative+"/") {
				return nil, errForbidden
			}
			if len(result.Changes) == maxEntries {
				result.Truncated = true
				break
			}
			result.Changes = append(result.Changes, gitChange{Path: path, Index: string(item[0]), Worktree: string(item[1])})
		}
		return result, nil
	}
	if operation != "git_diff" && operation != "git_diff_staged" {
		return nil, errInvalidPath
	}
	if !safeGitPath(relative) {
		return nil, errForbidden
	}
	f, err := root.openFile(relative)
	if err == nil {
		f.Close()
	} else if !errors.Is(err, errMissing) {
		return nil, err
	}
	args := []string{"diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=all", "--no-color", "--src-prefix=a/", "--dst-prefix=b/"}
	if operation == "git_diff_staged" {
		args = append(args, "--cached")
	}
	args = append(args, "--", relative)
	output, err := g.run(ctx, root, args)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(output) || bytes.ContainsRune(output, '\x00') {
		return nil, errNotText
	}
	result.Diff = string(output)
	return result, nil
}
