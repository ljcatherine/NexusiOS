package main

// One kernel lock serializes command admission across service processes sharing
// a UID. It is separate from approval/receipts and never enters the sandbox.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const commandAdmissionFile = "nexus-command.lock"

func commandAdmissionDirectory() string {
	// Do not trust XDG_RUNTIME_DIR supplied by an environment/client.
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}

func acquireCommandAdmission(ctx context.Context, directory string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dirFD, err := openConfiguredRoot(directory)
	if err != nil {
		return nil, errCommandUnavailable
	}
	defer syscall.Close(dirFD)
	var parent syscall.Stat_t
	if syscall.Fstat(dirFD, &parent) != nil || parent.Uid != uint32(os.Getuid()) || parent.Mode != syscall.S_IFDIR|0700 {
		return nil, errCommandUnavailable
	}
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	fd, err := syscall.Openat(dirFD, commandAdmissionFile, flags|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Openat(dirFD, commandAdmissionFile, flags, 0)
	}
	if err != nil {
		return nil, errCommandUnavailable
	}
	file := os.NewFile(uintptr(fd), "command-admission")
	ok := false
	defer func() {
		if !ok {
			file.Close()
		}
	}()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode != syscall.S_IFREG|0600 || st.Nlink != 1 || st.Size != 0 || st.Dev != parent.Dev {
		return nil, errCommandUnavailable
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return nil, errCommandUnavailable
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	// Refuse a replaced/unlinked name rather than taking a lock on an old inode.
	actual, err := os.Lstat(fmt.Sprintf("/proc/self/fd/%d/%s", dirFD, commandAdmissionFile))
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(actual, opened) || actual.Mode() != 0600 {
		return nil, errCommandUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ok = true
	// Close releases flock. Never unlink: waiters must keep one shared inode.
	return file, nil
}
