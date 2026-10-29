//go:build !linux && !darwin

package procs

import "syscall"

// Lookup is not supported here.
func Lookup(pid int) (Proc, error) { return Proc{}, ErrUnsupported }

// List is not supported here.
func List(uid int) ([]Proc, error) { return nil, ErrUnsupported }

// Signal is not supported here.
func Signal(p Proc, sig syscall.Signal) error { return ErrUnsupported }
