package cli_test

import (
	"bytes"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
)

// x/crypto/ssh has no way for a server to send SSH_MSG_DEBUG, the message
// OpenSSH logs as "Remote: ...". The tests reach the connection's own
// packet writer for it.
//
//go:linkname sshWritePacket golang.org/x/crypto/ssh.(*handshakeTransport).writePacket
func sshWritePacket(t unsafe.Pointer, p []byte) error

// sendDebug sends an SSH_MSG_DEBUG with msg on the connection c, which a
// server callback was given.
func sendDebug(t *testing.T, c ssh.ConnMetadata, msg string) {
	t.Helper()
	tr := reflect.ValueOf(c).Elem().FieldByName("transport")
	if !tr.IsValid() || tr.IsNil() {
		t.Error("x/crypto/ssh's connection has no transport field any more")
		return
	}
	pkt := ssh.Marshal(&struct {
		AlwaysDisplay bool `sshtype:"4"`
		Message       string
		Language      string
	}{Message: msg})
	if err := sshWritePacket(tr.Elem().UnsafePointer(), pkt); err != nil {
		t.Errorf("sending the debug message: %v", err)
	}
}

// After the old key is offered, the server sends a debug message whose
// last line is ssh's verdict for a refusal, word for word, and then stalls
// until the check times out. ssh never wrote a verdict of its own: the
// old key is not shown to be refused.
func TestKeyRotateTimedOutCheckIsNotARefusal(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	cli.SetRotateStepTimeout(t, 4*time.Second)
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	var sent atomic.Bool
	oldPub := w.oldKey.PublicKey().Marshal()
	afterOldKeyRemoved(w.srv[0], func() {
		w.srv[0].setOnAuth(func(c ssh.ConnMetadata, k ssh.PublicKey) {
			if !bytes.Equal(k.Marshal(), oldPub) || !sent.CompareAndSwap(false, true) {
				return
			}
			sendDebug(t, c, "checking\n"+c.User()+"@127.0.0.1: Permission denied (publickey).")
			select {
			case <-stall:
			case <-time.After(time.Minute):
			}
		})
	})
	hosts := rotateJSON(t, w, "--hosts", "web-1")
	if !sent.Load() {
		t.Fatal("the server never saw the old key offered after its lines were removed: the test proves nothing")
	}
	wantAttention(t, w, hosts, "web-1", "timed out")
}
