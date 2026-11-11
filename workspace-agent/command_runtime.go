package main

// Runtime capsules are administrator-owned toolchain roots, not workspaces.
// No capsule path or executable is accepted from a client request.
import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type commandRuntime struct {
	root   *os.File
	digest string
}

func runtimeField(h hash.Hash, value string) {
	_ = binary.Write(h, binary.BigEndian, uint32(len(value)))
	_, _ = io.WriteString(h, value)
}

func runtimeAncestry(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	nix := filepath.Dir(path) == "/nix/store"
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		if nix {
			if current == "/nix/store" {
				return true
			}
			if info.Mode().Perm()&0222 != 0 {
				return false
			}
		} else if stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		if current == "/" {
			return true
		}
	}
}

func openCommandRuntime(ctx context.Context, path string) (*commandRuntime, error) {
	if !runtimeAncestry(path) {
		return nil, errForbidden
	}
	fd, err := openConfiguredRoot(path)
	if err != nil {
		return nil, errForbidden
	}
	root := os.NewFile(uintptr(fd), "command-runtime")
	ok := false
	defer func() {
		if !ok {
			root.Close()
		}
	}()
	mount, err := commandMountID(fd)
	if err != nil {
		return nil, errForbidden
	}
	nix := filepath.Dir(path) == "/nix/store"
	h := sha256.New()
	_, _ = io.WriteString(h, "nexus.command.runtime.v1\x00")
	files, bytes := 0, int64(0)
	buffer := make([]byte, 64<<10)
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, relative string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 32 {
			return errTooLarge
		}
		info, err := dir.Stat()
		if err != nil || info.Mode().Perm()&0222 != 0 {
			return errForbidden
		}
		runtimeField(h, relative)
		runtimeField(h, "dir")
		runtimeField(h, fmt.Sprint(info.Mode().Perm()))
		var entries []os.DirEntry
		for {
			batch, err := dir.ReadDir(128)
			files += len(batch)
			if files > 20000 {
				return errTooLarge
			}
			entries = append(entries, batch...)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			child := name
			if relative != "" {
				child = relative + "/" + name
			}
			if len(child) > 2048 {
				return errTooLarge
			}
			// File.ReadDir's lazy Info uses its display name, not openat. Resolve
			// metadata through the live descriptor instead of a synthetic name.
			info, err := os.Lstat(fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), name))
			if err != nil {
				return errForbidden
			}
			st, valid := info.Sys().(*syscall.Stat_t)
			if !valid || (!nix && st.Uid != 0) || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return errForbidden
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), name))
				if err != nil || len(target) > 2048 {
					return errForbidden
				}
				runtimeField(h, child)
				runtimeField(h, "link")
				runtimeField(h, target)
				continue
			}
			if info.Mode().Perm()&0222 != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return errForbidden
			}
			flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
			if info.IsDir() {
				flags |= syscall.O_DIRECTORY
			}
			childFD, err := syscall.Openat(int(dir.Fd()), name, flags, 0)
			if err != nil {
				return errForbidden
			}
			file := os.NewFile(uintptr(childFD), "runtime-entry")
			id, err := commandMountID(childFD)
			if err != nil || id != mount {
				file.Close()
				return errForbidden
			}
			actual, statErr := file.Stat()
			if statErr != nil || !os.SameFile(info, actual) || actual.Mode().Perm()&0222 != 0 {
				file.Close()
				return errForbidden
			}
			actualStat, valid := actual.Sys().(*syscall.Stat_t)
			if !valid || (!nix && actualStat.Uid != 0) {
				file.Close()
				return errForbidden
			}
			if info.IsDir() {
				err = walk(file, child, depth+1)
			} else {
				fileHash := sha256.New()
				for {
					if e := ctx.Err(); e != nil {
						err = e
						break
					}
					n, e := file.Read(buffer)
					bytes += int64(n)
					if bytes > 2<<30 {
						err = errTooLarge
						break
					}
					_, _ = fileHash.Write(buffer[:n])
					if e == io.EOF {
						break
					}
					if e != nil {
						err = e
						break
					}
				}
				if err == nil {
					runtimeField(h, child)
					runtimeField(h, "file")
					runtimeField(h, fmt.Sprint(actual.Mode().Perm()))
					runtimeField(h, hex.EncodeToString(fileHash.Sum(nil)))
				}
			}
			file.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return nil, err
	}
	for _, name := range []string{"tmp", "workspace"} {
		d, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, errForbidden
		}
		syscall.Close(d)
	}
	ok = true
	return &commandRuntime{root: root, digest: hex.EncodeToString(h.Sum(nil))}, nil
}

func (r *commandRuntime) executable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return false
	}
	dir, err := syscall.Dup(int(r.root.Fd()))
	if err != nil {
		return false
	}
	defer func() { syscall.Close(dir) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if index != len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(dir, part, flags, 0)
		if err != nil {
			return false
		}
		syscall.Close(dir)
		dir = next
	}
	var stat syscall.Stat_t
	return syscall.Fstat(dir, &stat) == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFREG && stat.Mode&0111 != 0
}
