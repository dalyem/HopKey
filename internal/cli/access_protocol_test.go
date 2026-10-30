package cli

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/access"
)

// The client's side of a locked session (§7.7) over pipes: the host is
// the test, writing the header and the file into out and reading the
// decision from in.

type protoRun struct {
	end    sessionEnd
	gaveUp bool
}

// startProtocol runs protocol with decide. It returns the host's end of
// the output, what the client sent (once it closes its input; it is read
// all along, as ssh reads its stdin), and the result, which arrives once
// protocol returns.
func startProtocol(t *testing.T, decide func(context.Context, string, []byte) sessionDecision) (io.Writer, <-chan string, <-chan protoRun) {
	t.Helper()
	outR, outW := io.Pipe()
	inR, inW := io.Pipe()
	t.Cleanup(func() {
		outW.Close()
		inR.Close()
	})
	sent := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(inR)
		sent <- string(b)
	}()
	done := make(chan protoRun, 1)
	c := &accessConn{}
	go func() {
		var r protoRun
		r.gaveUp = c.protocol(context.Background(), outR, inW, decide, &r.end)
		inW.Close()
		done <- r
	}()
	return outW, sent, done
}

// setDeadline sets the client's deadline for the test. Each test waits
// for its protocol to return before it ends.
func setDeadline(t *testing.T, d time.Duration) {
	old := accessDecisionDeadline
	accessDecisionDeadline = d
	t.Cleanup(func() { accessDecisionDeadline = old })
}

func waitProto(t *testing.T, done <-chan protoRun, within time.Duration) protoRun {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(within):
		t.Fatalf("protocol did not return within %v", within)
	}
	return protoRun{}
}

func waitSent(t *testing.T, sent <-chan string) string {
	t.Helper()
	select {
	case s := <-sent:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not close its input")
	}
	return ""
}

var protoFile = []byte("ssh-ed25519 AAAA one\n# a comment\n")

func protoHeader(content []byte) string {
	return "hop-session 1 deploy " + cksum(content) + "\n"
}

// Review r2 #2: the deadline starts at the header. A host that sends a
// valid header and then trickles the file gets an abort at the deadline,
// decide never runs, and the rest of the host's output is still read, so
// the host's writes never block.
func TestProtocolDeadlineCoversTheFile(t *testing.T) {
	setDeadline(t, 200*time.Millisecond)
	called := make(chan struct{}, 1)
	out, in, done := startProtocol(t, func(context.Context, string, []byte) sessionDecision {
		called <- struct{}{}
		return sessionDecision{}
	})
	go func() {
		io.WriteString(out, protoHeader(protoFile))
		out.Write(protoFile[:5]) // and then nothing, for now
	}()
	start := time.Now()
	r := waitProto(t, done, 3*time.Second)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("protocol took %v", el)
	}
	if got := waitSent(t, in); got != "abort\n" {
		t.Fatalf("the client sent %q", got)
	}
	if !r.gaveUp || r.end.sent != sentAbort || r.end.abortWhy != errSessionDeadline.Error() || r.end.gotHeader || r.end.decided {
		t.Fatalf("end %+v, gave up %v", r.end, r.gaveUp)
	}
	select {
	case <-called:
		t.Fatal("decide ran for a file that never arrived")
	default:
	}
	// The rest of the file, and more, is drained.
	wrote := make(chan error, 1)
	go func() {
		_, err := out.Write(append(protoFile[5:], strings.Repeat("x", 64<<10)...))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("the host's write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the host's output is no longer read")
	}
}

// A decision that comes back after the deadline is dropped whole: abort
// is sent, nothing it found is in the session's end, and its context had
// ended. Run under -race, the late return touches nothing the caller
// reads.
func TestProtocolLateDecisionIsDropped(t *testing.T) {
	setDeadline(t, 200*time.Millisecond)
	release := make(chan struct{})
	ctxEnded := make(chan bool, 1)
	returned := make(chan struct{})
	out, in, done := startProtocol(t, func(ctx context.Context, user string, content []byte) sessionDecision {
		<-release
		ctxEnded <- ctx.Err() != nil
		defer close(returned)
		next := append([]byte(nil), content...)
		return sessionDecision{to: append(next, "ssh-ed25519 BBBB two\n"...), userChanged: true, fenced: "late", d: access.Decision{Outcome: access.OutWrite}}
	})
	go func() {
		io.WriteString(out, protoHeader(protoFile))
		out.Write(protoFile)
	}()
	r := waitProto(t, done, 3*time.Second)
	if got := waitSent(t, in); got != "abort\n" {
		t.Fatalf("the client sent %q", got)
	}
	if !r.gaveUp || r.end.sent != sentAbort || r.end.abortWhy != errSessionDeadline.Error() || !r.end.gotHeader || r.end.decided {
		t.Fatalf("end %+v", r.end)
	}
	if r.end.decision.to != nil || r.end.decision.userChanged || r.end.decision.fenced != "" || r.end.decision.d.Outcome != 0 {
		t.Fatalf("a late decision reached the end: %+v", r.end.decision)
	}
	// The caller goes on reading the end while the late decision returns.
	close(release)
	for range 1000 {
		_ = r.end.decision.fenced
		_ = r.end.content
	}
	if ended := <-ctxEnded; !ended {
		t.Error("the late decision's context had not ended")
	}
	<-returned
}

// A decision in time is sent, with the payload, and kept in the end.
func TestProtocolDecisionInTime(t *testing.T) {
	setDeadline(t, 5*time.Second)
	next := append(append([]byte(nil), protoFile...), "ssh-ed25519 BBBB two\n"...)
	out, in, done := startProtocol(t, func(ctx context.Context, user string, content []byte) sessionDecision {
		if user != "deploy" || string(content) != string(protoFile) || ctx.Err() != nil {
			t.Errorf("decide(%q, %q), ctx %v", user, content, ctx.Err())
		}
		return sessionDecision{to: next, fenced: ""}
	})
	go func() {
		io.WriteString(out, protoHeader(protoFile))
		out.Write(protoFile)
	}()
	got := waitSent(t, in)
	r := waitProto(t, done, 3*time.Second)
	if want := "write " + cksum(protoFile) + " " + cksum(next) + "\n" + string(next); got != want {
		t.Fatalf("the client sent %q, want %q", got, want)
	}
	if r.gaveUp || r.end.sent != sentWrite || !r.end.decided || string(r.end.decision.to) != string(next) {
		t.Fatalf("end %+v", r.end)
	}
}
