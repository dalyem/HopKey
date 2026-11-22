// Package version holds the build version shared by the hop binaries.
package version

// Version is overridden at link time: -ldflags "-X github.com/dalyem/hopkey/internal/version.Version=v1.2.3".
var Version = "dev"
