// Package safepath prepares directories that hold secrets or security
// settings (the agent socket, the generated ssh config) and refuses locations
// another user could tamper with.
//
// A 0700 directory is not private if one of its ancestors can be renamed or
// replaced by someone else, or if the path reaches it through a symlink
// someone else can repoint. The check follows OpenSSH's safe_path(): every
// ancestor up to / must belong to root or the current user and must not be
// writable by group or others.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnsurePrivateDir creates dir if needed (mode 0700), checks that the path
// to it is safe, and returns the path with symlinks in the ancestors
// resolved. Callers should use the returned path for everything that
// follows, so a symlink swapped in later cannot redirect them.
//
// The checks, in order:
//   - dir is absolute, and its last component is not a symlink;
//   - every ancestor of the resolved path is owned by root or the current
//     user and is not group- or world-writable. The one exception is a
//     sticky writable directory such as /tmp, and only when the next
//     component below it is owned by the current user with mode 0700;
//   - dir itself is owned by the current user. A mode other than 0700 is
//     tightened to 0700.
//
// Every directory it creates is made durable: the parent of each one is
// fsynced, from the deepest up to the first ancestor that already existed,
// so a crash cannot lose a directory that files were then written into.
//
// It fails closed: on any doubt it returns an error and leaves permissions
// alone. Directories it created before failing are left in place.
func EnsurePrivateDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("safepath: %q is not absolute", dir)
	}
	dir = filepath.Clean(dir)
	missing, err := missingDirs(dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := syncDir(filepath.Dir(missing[i])); err != nil {
			return "", fmt.Errorf("safepath: syncing %s: %w", filepath.Dir(missing[i]), err)
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("safepath: %s is a symlink", dir)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("safepath: %s is not a directory", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	if err := checkPrivateDir(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// missingDirs lists dir and those of its ancestors that do not exist yet,
// from dir upwards.
func missingDirs(dir string) ([]string, error) {
	var missing []string
	for p := dir; ; p = filepath.Dir(p) {
		_, err := os.Lstat(p)
		if err == nil {
			return missing, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, p)
		if p == filepath.Dir(p) {
			return missing, nil
		}
	}
}

// syncDir fsyncs a directory, so the entries just created in it survive a
// crash. Tests replace it to see which directories are synced.
var syncDir = syncDirOS
