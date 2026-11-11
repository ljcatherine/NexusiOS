package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type pendingModelSwitch struct {
	Version int    `json:"version"`
	Target  string `json:"target"`
}

func readPendingModelSwitch(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read model switch journal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("model switch journal must be a private regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read model switch journal: %w", err)
	}
	var state pendingModelSwitch
	if err := json.Unmarshal(contents, &state); err != nil || state.Version != 1 ||
		(state.Target != "unload" && !orchestratorModelID.MatchString(state.Target)) {
		return "", errors.New("model switch journal is invalid; inference remains disabled")
	}
	return state.Target, nil
}

func writePendingModelSwitch(path, target string) error {
	if target != "unload" && !orchestratorModelID.MatchString(target) {
		return errors.New("invalid pending model switch target")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create private model state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("model state directory must be a private directory with mode 0700")
	}
	data, err := json.Marshal(pendingModelSwitch{Version: 1, Target: target})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".pending-switch-*")
	if err != nil {
		return fmt.Errorf("create model switch journal: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure model switch journal: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write model switch journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync model switch journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close model switch journal: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace model switch journal: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open model state directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync model state directory: %w", err)
	}
	return nil
}

func clearPendingModelSwitch(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear model switch journal: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open model state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync model state directory: %w", err)
	}
	return nil
}
