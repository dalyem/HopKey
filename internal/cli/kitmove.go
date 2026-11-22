package cli

import "errors"

// errNoReplaceUnsupported means the system or the filesystem has no atomic
// no-replace rename. writeKitFile then tries a hard link.
var errNoReplaceUnsupported = errors.New("no atomic no-replace rename here")
