// SPDX-License-Identifier: GPL-2.0-only

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const EnvName = "MEMENTO_STATE_DIR"

type Layout struct {
	Root      string
	Log       string
	Dump      string
	Recovered string
	Lab       string
	Stats     string
	Keys      string
}

func Resolve(flagValue string) (Layout, error) {
	root := flagValue
	if root == "" {
		root = os.Getenv(EnvName)
	}
	if root == "" {
		root = "./var"
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Layout{}, fmt.Errorf("resolve state directory: %w", err)
	}
	l := Layout{
		Root:      filepath.Clean(abs),
		Log:       filepath.Join(abs, "log"),
		Dump:      filepath.Join(abs, "dump"),
		Recovered: filepath.Join(abs, "recovered"),
		Lab:       filepath.Join(abs, "lab"),
		Stats:     filepath.Join(abs, "stats"),
		Keys:      filepath.Join(abs, "keys"),
	}
	return l, nil
}

func (l Layout) Ensure() error {
	for _, dir := range []string{l.Root, l.Log, l.Dump, l.Recovered, l.Lab, l.Stats, l.Keys} {
		if err := ensureDirectory(dir); err != nil {
			return err
		}
	}
	return nil
}

func ensureDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create state directory %q: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect state directory %q: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state directory %q must be a real directory", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure state directory %q: %w", path, err)
	}
	return nil
}

func OpenPrivate(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
