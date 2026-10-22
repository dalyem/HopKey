//go:build unix

package safepath

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkPrivateDir verifies the ancestors of resolved, then the directory
// itself, and tightens its mode. resolved must already have its symlinks
// resolved.
func checkPrivateDir(resolved string) error {
	self := uint32(os.Geteuid())

	// Components from / down to resolved itself.
	var chain []string
	for p := resolved; ; p = filepath.Dir(p) {
		chain = append([]string{p}, chain...)
		if p == filepath.Dir(p) {
			break
		}
	}

	infos := make([]os.FileInfo, len(chain))
	for i, p := range chain {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("safepath: %s is not a plain directory", p)
		}
		infos[i] = fi
	}

	last := len(chain) - 1
	for i := 0; i < last; i++ {
		p, fi := chain[i], infos[i]
		uid, ok := ownerOf(fi)
		if !ok || (uid != 0 && uid != self) {
			return fmt.Errorf("safepath: %s is owned by uid %d, want root or uid %d", p, uid, self)
		}
		if fi.Mode().Perm()&0o022 == 0 {
			continue
		}
		// Writable by others. A sticky directory is acceptable only when
		// the next component down cannot be replaced or entered by them.
		if fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("safepath: %s is writable by group or others (mode %o)", p, fi.Mode().Perm())
		}
		next, nextInfo := chain[i+1], infos[i+1]
		nextUID, ok := ownerOf(nextInfo)
		if i+1 == last {
			// The final directory is tightened below; judge the mode it
			// will have once we own it.
			if !ok || nextUID != self {
				return fmt.Errorf("safepath: %s is under sticky %s but is not owned by uid %d", next, p, self)
			}
			continue
		}
		if !ok || nextUID != self || nextInfo.Mode().Perm() != 0o700 {
			return fmt.Errorf("safepath: %s is writable by group or others and %s is not a 0700 directory owned by uid %d", p, next, self)
		}
	}

	fi := infos[last]
	if uid, ok := ownerOf(fi); !ok || uid != self {
		return fmt.Errorf("safepath: %s is not owned by uid %d", resolved, self)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(resolved, 0o700); err != nil {
			return err
		}
	}
	// Re-check after the chmod so a swap between Lstat and Chmod shows up.
	after, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if !os.SameFile(fi, after) || after.Mode().Perm() != 0o700 || after.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("safepath: %s changed while it was being checked", resolved)
	}
	return nil
}

func ownerOf(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(st.Uid), true
}
