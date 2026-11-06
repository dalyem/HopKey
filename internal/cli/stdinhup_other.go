//go:build !linux

package cli

import "context"

// watchStdinHangup does nothing here: a hangup still arrives as SIGHUP, and
// a prompt that reads stdin sees the end of input.
func watchStdinHangup(ctx context.Context, f interface{ Fd() uintptr }, hangup func()) {}
