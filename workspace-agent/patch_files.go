package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// Managed writes intentionally have a narrower scope than reads. No hidden or
// credential paths, agent policy files, build entry points or executable files.
func validPatchPath(relative string) bool {
	for _, r := range relative {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	parts, err := segments(relative, false)
	if err != nil {
		return false
	}
	for _, part := range parts {
		if forbiddenFilename(part) {
			return false
		}
		switch strings.ToLower(part) {
		case "agents.md", "claude.md", "gemini.md", "dockerfile", "containerfile", "makefile", "justfile", "cmakelists.txt", "go.mod", "go.sum", "package.json", "package-lock.json", "project.yml":
			return false
		}
	}
	return allowedTextFilename(parts[len(parts)-1])
}

// Linux mount IDs distinguish bind mounts even when st_dev is unchanged.
// /proc must be the trusted process procfs. Unavailable IDs fail closed.
func descriptorMountID(fd int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, errForbidden
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			id, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err == nil && id != 0 {
				return id, nil
			}
		}
	}
	return 0, errForbidden
}

func privateOwned(fd int, directory bool) error {
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
		return errForbidden
	}
	want := uint32(syscall.S_IFREG | 0600)
	if directory {
		want = syscall.S_IFDIR | 0700
	}
	if st.Mode != want || (!directory && st.Nlink != 1) {
		return errForbidden
	}
	// Reject ACLs, security labels, capabilities and all other xattrs instead of
	// silently losing them on replacement. Missing kernel support is a denial.
	n, err := syscall.Listxattr(fmt.Sprintf("/proc/self/fd/%d", fd), nil)
	if err != nil || n != 0 {
		return errForbidden
	}
	return nil
}

type patchSnapshot struct {
	Version string
	Device  uint64
	Inode   uint64
	MountID uint64
	SHA256  string
	Text    string
}

// Non-mutating preflight primitive only. A snapshot is NOT a CAS or confinement
// boundary. Managed roots require exclusive trusted writers, including no
// competing same-UID processes and no untrusted ancestor renames/mount changes.
func (w *workspace) inspectPatchFile(relative string) (patchSnapshot, error) {
	var result patchSnapshot
	if !validPatchPath(relative) {
		return result, errForbidden
	}
	parts, _ := segments(relative, false)
	fd, err := syscall.Openat(w.fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return result, errForbidden
	}
	current := os.NewFile(uintptr(fd), "patch-root")
	defer func() { _ = current.Close() }()
	mount, err := descriptorMountID(fd)
	if err != nil {
		return result, err
	}
	if err = privateOwned(fd, true); err != nil {
		return result, err
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		directory := i < len(parts)-1
		if directory {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(int(current.Fd()), part, flags, 0)
		if err != nil {
			return result, classifyOpen(err)
		}
		file := os.NewFile(uintptr(next), "patch-object")
		id, merr := descriptorMountID(next)
		if merr != nil || id != mount || privateOwned(next, directory) != nil {
			file.Close()
			return result, errForbidden
		}
		current.Close()
		current = file
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(int(current.Fd()), &before) != nil {
		return result, errForbidden
	}
	if before.Size > maxReadBytes {
		return result, errTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(current, maxReadBytes+1))
	if err != nil {
		return result, errForbidden
	}
	if len(data) > maxReadBytes {
		return result, errTooLarge
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return result, errNotText
	}
	if syscall.Fstat(int(current.Fd()), &after) != nil || !samePatchStat(before, after) {
		return result, errPatchConflict
	}
	return patchSnapshot{Version: hashText(fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", before.Dev, before.Ino, before.Nlink, before.Mode, before.Uid, before.Gid, before.Size, before.Mtim.Sec, before.Mtim.Nsec, before.Ctim.Sec, before.Ctim.Nsec)), Device: uint64(before.Dev), Inode: before.Ino, MountID: mount, SHA256: hashText(string(data)), Text: string(data)}, nil
}

// Reading may update atime. Identity, content timestamps and security metadata
// must remain unchanged; neither size nor a matching content hash is identity.
func samePatchStat(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Nlink == b.Nlink && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
