package sshagent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerUID(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "p.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			defer c.Close()
			<-done // hold the connection open until the test ends
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	uid, err := peerUID(c)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Errorf("peerUID = %d, want %d", uid, os.Getuid())
	}
}
