package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"syscall"
)

type patchRootAnchor struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Generation string `json:"generation,omitempty"`
}
type patchRootAnchors struct {
	Host  string                     `json:"host"`
	Roots map[string]patchRootAnchor `json:"roots"`
}

// Pin the configured descriptor identities independently of caller paths. A
// changed root set/host/inode requires investigation, not an automatic reset.
// Opaque persisted generations bind approved bytes to this exact configured
// root identity. Legacy anchors remain readable, but cannot enable mutation.
func (j *patchJournal) bindRoots(host string, roots map[string]*workspace) error {
	return bindWorkspaceRoots(j.dir, j.size, host, roots)
}

func (j *commandJournal) bindRoots(host string, roots map[string]*workspace) error {
	if err := bindWorkspaceRoots(j.dir, j.size, host, roots); err != nil {
		return errCommandJournal
	}
	return nil
}

func bindWorkspaceRoots(dir *os.File, size int, host string, roots map[string]*workspace) error {
	expected := patchRootAnchors{Host: host, Roots: map[string]patchRootAnchor{}}
	for id, root := range roots {
		var st syscall.Stat_t
		if syscall.Fstat(root.fd, &st) != nil {
			return errPatchJournal
		}
		expected.Roots[id] = patchRootAnchor{Device: uint64(st.Dev), Inode: st.Ino}
	}
	fd, err := syscall.Openat(int(dir.Fd()), "roots.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == syscall.ENOENT {
		if size != 0 {
			return errPatchJournal
		}
		fd, err = syscall.Openat(int(dir.Fd()), "roots.json", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return errPatchJournal
		}
		f := os.NewFile(uintptr(fd), "patch-root-anchors")
		defer f.Close()
		if privateOwned(fd, false) != nil {
			return errPatchJournal
		}
		for id, anchor := range expected.Roots {
			var nonce [32]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return errPatchJournal
			}
			anchor.Generation = roots[id].generation
			if anchor.Generation == "" {
				anchor.Generation = hex.EncodeToString(nonce[:])
			}
			expected.Roots[id] = anchor
			roots[id].generation = anchor.Generation
		}
		data, _ := json.Marshal(expected)
		if n, err := f.Write(data); err != nil || n != len(data) {
			return errPatchJournal
		}
		if f.Sync() != nil || dir.Sync() != nil {
			return errPatchJournal
		}
		return nil
	}
	if err != nil {
		return errPatchJournal
	}
	f := os.NewFile(uintptr(fd), "patch-root-anchors")
	defer f.Close()
	dm, e1 := descriptorMountID(int(dir.Fd()))
	fm, e2 := descriptorMountID(fd)
	if privateOwned(fd, false) != nil || e1 != nil || e2 != nil || dm != fm {
		return errPatchJournal
	}
	dec := json.NewDecoder(io.LimitReader(f, 8193))
	dec.DisallowUnknownFields()
	var saved patchRootAnchors
	if dec.Decode(&saved) != nil || dec.Decode(new(any)) != io.EOF || saved.Host != host || len(saved.Roots) != len(expected.Roots) {
		return errPatchJournal
	}
	for id, want := range expected.Roots {
		anchor, present := saved.Roots[id]
		if !present || anchor.Device != want.Device || anchor.Inode != want.Inode ||
			(anchor.Generation != "" && !hex64.MatchString(anchor.Generation)) ||
			((roots[id].config.ManagedWrite || len(roots[id].config.CommandProfiles) > 0) && anchor.Generation == "") ||
			(roots[id].generation != "" && roots[id].generation != anchor.Generation) {
			return errPatchJournal
		}
		roots[id].generation = anchor.Generation
	}
	return nil
}
