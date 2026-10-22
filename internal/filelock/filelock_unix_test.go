//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package filelock

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTryLockConflictsAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	first, err := TryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second TryLock error = %v, want ErrLocked", err)
	}
	first.Close()
	second, err := TryLock(path)
	if err != nil {
		t.Fatalf("TryLock after release: %v", err)
	}
	second.Close()
}

func TestLockWaitsForRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	first, err := TryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		f, err := Lock(path)
		if err == nil {
			f.Close()
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("Lock returned while the lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Lock after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock did not return after the lock was released")
	}
}
