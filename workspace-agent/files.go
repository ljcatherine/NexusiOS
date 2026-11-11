package main

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

var (
	errInvalidPath = errors.New("invalid relative path")
	errForbidden   = errors.New("forbidden filesystem object")
	errMissing     = errors.New("missing filesystem object")
	errTooLarge    = errors.New("file too large")
	errNotText     = errors.New("unsupported file contents")
)

// Linux O_PATH is 010000000 (0x200000) on the supported Linux AMD64/ARM64
// targets. The frozen standard-library syscall package does not expose it.
const linuxOPath = 0x200000

// The policy is intentionally stricter than filesystem permissions. Hidden
// directories/files (including .git/.env/.ssh), symlinks and non-text content
// cannot be read, even if the OS user has access to them.
var textExtensions = map[string]bool{
	".md": true, ".txt": true, ".swift": true, ".go": true, ".py": true,
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".json": true,
	".yaml": true, ".yml": true, ".toml": true, ".sh": true, ".nix": true,
	".rs": true, ".html": true, ".css": true, ".scss": true, ".sql": true,
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true,
	".java": true, ".kt": true, ".cs": true, ".xml": true, ".rb": true,
	".php": true, ".gradle": true,
}

var textBasenames = map[string]bool{
	"Dockerfile": true, "Containerfile": true, "Makefile": true,
	"CMakeLists.txt": true, "Justfile": true, "Gemfile": true,
}

func allowedTextFilename(name string) bool {
	return textBasenames[name] || textExtensions[strings.ToLower(path.Ext(name))]
}

type fileEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// Traverse every configured-root component without following any symlink;
// a symlink swapped into an ancestor between validation and open fails closed.
func openConfiguredRoot(absolute string) (int, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func segments(relative string, allowEmpty bool) ([]string, error) {
	if relative == "" && allowEmpty {
		return nil, nil
	}
	if relative == "" || len(relative) > 512 || strings.HasPrefix(relative, "/") || strings.ContainsAny(relative, "\\\x00") {
		return nil, errInvalidPath
	}
	parts := strings.Split(relative, "/")
	if len(parts) > 12 {
		return nil, errInvalidPath
	}
	for _, segment := range parts {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 || strings.HasPrefix(segment, ".") {
			return nil, errInvalidPath
		}
		if !utf8.ValidString(segment) || strings.ContainsAny(segment, "\r\n") {
			return nil, errInvalidPath
		}
	}
	return parts, nil
}

func forbiddenFilename(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(name, ".") || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\r\n\x00") {
		return true
	}
	// Common credential/config secret names; the admin must also keep secret
	// files entirely outside configured roots wherever possible.
	for _, marker := range []string{"password", "passwd", "credential", "private_key", "secret", "token", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, ext := range []string{".pem", ".key", ".p12", ".pfx", ".kdbx", ".sqlite", ".db"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// openDir walks from an already-open trusted root descriptor. Each component
// is independently opened with O_NOFOLLOW and O_DIRECTORY, so renaming a
// directory to a symlink during traversal never causes the agent to follow it.
func (w *workspace) openDir(parts []string) (*os.File, error) {
	// Dup shares the root's underlying directory stream offset; a fresh openat
	// of "." gives each request independent enumeration state.
	fd, err := syscall.Openat(w.fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errForbidden
	}
	for _, component := range parts {
		if forbiddenFilename(component) {
			_ = syscall.Close(fd)
			return nil, errForbidden
		}
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, classifyOpen(openErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "workspace-directory"), nil
}

func classifyOpen(err error) error {
	switch {
	case errors.Is(err, syscall.ENOENT):
		return errMissing
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return errForbidden
	default:
		return errForbidden
	}
}

func (w *workspace) openFile(relative string) (*os.File, error) {
	parts, err := segments(relative, false)
	if err != nil {
		return nil, err
	}
	name := parts[len(parts)-1]
	if forbiddenFilename(name) || !allowedTextFilename(name) {
		return nil, errForbidden
	}
	parent, err := w.openDir(parts[:len(parts)-1])
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, classifyOpen(err)
	}
	f := os.NewFile(uintptr(fd), "workspace-file")
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		f.Close()
		return nil, errForbidden
	}
	if stat.Size() > maxReadBytes {
		f.Close()
		return nil, errTooLarge
	}
	return f, nil
}

func (w *workspace) readText(relative string) (string, error) {
	f, err := w.openFile(relative)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return "", errForbidden
	}
	if len(data) > maxReadBytes {
		return "", errTooLarge
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return "", errNotText
	}
	return string(data), nil
}

func (w *workspace) list(relative string, limit int) ([]fileEntry, bool, error) {
	parts, err := segments(relative, true)
	if err != nil {
		return nil, false, err
	}
	dir, err := w.openDir(parts)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, errForbidden
	}
	truncated := len(entries) > limit
	// ReadDir(limit + 1) bounds work and avoids unbounded listings on huge trees.
	if truncated {
		entries = entries[:limit]
	}
	out := make([]fileEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if forbiddenFilename(name) {
			continue
		}
		// The directory was opened by descriptor, not by pathname. Resolve entry
		// metadata relative to that descriptor; DirEntry.Info would attempt a
		// filesystem lookup using os.File's synthetic display name instead.
		entryFD, openErr := syscall.Openat(int(dir.Fd()), name, linuxOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			continue
		}
		var stat syscall.Stat_t
		infoErr := syscall.Fstat(entryFD, &stat)
		_ = syscall.Close(entryFD)
		if infoErr != nil {
			continue
		}
		kind := ""
		switch stat.Mode & syscall.S_IFMT {
		case syscall.S_IFDIR:
			kind = "directory"
		case syscall.S_IFREG:
			if allowedTextFilename(name) {
				kind = "file"
			}
		default:
			continue
		}
		if kind == "" {
			continue
		}
		rel := name
		if relative != "" {
			rel = relative + "/" + name
		}
		out = append(out, fileEntry{Name: name, Path: rel, Kind: kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, truncated, nil
}
