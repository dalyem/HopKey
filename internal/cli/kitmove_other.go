//go:build !linux && !darwin

package cli

import "errors"

// renameNoReplace has no atomic implementation here; writeKitFile uses a
// hard link instead.
func renameNoReplace(oldpath, newpath string) error { return errNoReplaceUnsupported }

// linkUnsupported reports whether a link error means the filesystem cannot
// make hard links.
func linkUnsupported(err error) bool { return errors.Is(err, errors.ErrUnsupported) }
