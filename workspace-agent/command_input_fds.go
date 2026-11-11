package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func closeCommandInputs(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

// Unnamed tmpfs files have no directory entry to orphan on parent death. The
// read-only descriptors are consumed/closed by bwrap before project execution.
func anonymousCommandInputs(ctx context.Context, inputs []storedCommandInput, startFD int) ([]*os.File, []string, error) {
	if startFD < 3 || startFD > 4 {
		return nil, nil, errForbidden
	}
	if _, _, err := commandInputManifest(inputs); err != nil {
		return nil, nil, err
	}
	dir, err := openConfiguredRoot(commandAdmissionDirectory())
	if err != nil {
		return nil, nil, errCommandUnavailable
	}
	defer syscall.Close(dir)
	var parent syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(dir, &parent) != nil || parent.Mode != syscall.S_IFDIR|0700 || parent.Uid != uint32(os.Getuid()) || syscall.Fstatfs(dir, &fs) != nil || fs.Type != 0x01021994 {
		return nil, nil, errCommandUnavailable
	}
	files := make([]*os.File, 0, len(inputs))
	ok := false
	defer func() {
		if !ok {
			closeCommandInputs(files)
		}
	}()
	args := []string{"--size", "8388608", "--tmpfs", "/workspace"}
	directories := map[string]bool{}
	for index, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// Linux __O_TMPFILE | O_DIRECTORY. There is deliberately no named-file
		// fallback on filesystems/kernels that cannot provide this boundary.
		n, err := syscall.Openat(dir, ".", syscall.O_RDWR|syscall.O_CLOEXEC|0x400000|syscall.O_DIRECTORY, 0600)
		if err != nil {
			return nil, nil, errCommandUnavailable
		}
		write := os.NewFile(uintptr(n), "anonymous-command-input")
		var st syscall.Stat_t
		if syscall.Fstat(n, &st) != nil || st.Mode != syscall.S_IFREG|0600 || st.Nlink != 0 || st.Uid != uint32(os.Getuid()) || st.Dev != parent.Dev {
			write.Close()
			return nil, nil, errCommandUnavailable
		}
		if count, err := write.Write(input.Data); err != nil || count != len(input.Data) {
			write.Close()
			return nil, nil, errCommandUnavailable
		}
		read, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", n))
		write.Close()
		if err != nil {
			return nil, nil, errCommandUnavailable
		}
		files = append(files, read)
		parts := strings.Split(input.Path, "/")
		directory := "/workspace"
		for _, part := range parts[:len(parts)-1] {
			directory += "/" + part
			if !directories[directory] {
				args = append(args, "--dir", directory)
				directories[directory] = true
			}
		}
		args = append(args, "--perms", "0400", "--file", strconv.Itoa(startFD+index), "/workspace/"+input.Path)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	args = append(args, "--remount-ro", "/workspace")
	ok = true
	return files, args, nil
}
