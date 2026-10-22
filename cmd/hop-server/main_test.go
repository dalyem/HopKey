package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/server"
)

func TestCheckListen(t *testing.T) {
	for _, c := range []struct {
		addr      string
		tls, http bool
		ok        bool
	}{
		{"127.0.0.1:8443", false, false, true},
		{"[::1]:8443", false, false, true},
		{"localhost:8443", false, false, true},
		{":8443", false, false, false},
		{"0.0.0.0:8443", false, false, false},
		{"192.0.2.10:8443", false, false, false},
		{"hop.example.com:8443", false, false, false},
		{":8443", true, false, true},
		{"0.0.0.0:8443", false, true, true},
		{"nonsense", false, true, false},
	} {
		err := checkListen(c.addr, c.tls, c.http)
		if (err == nil) != c.ok {
			t.Errorf("checkListen(%q, tls=%v, insecure=%v) = %v", c.addr, c.tls, c.http, err)
		}
	}
}

func TestServeRefusesPlainHTTPOnPublicAddress(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{"serve", "--listen", "0.0.0.0:0", "--data", t.TempDir(), "--origin", "https://hop.example.com"}, &bytes.Buffer{}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "refusing plain HTTP") {
		t.Errorf("serve on 0.0.0.0 without TLS: %v", err)
	}
	err = run([]string{"serve", "--listen", "127.0.0.1:0", "--data", t.TempDir()}, &bytes.Buffer{}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--origin") {
		t.Errorf("serve without --origin: %v", err)
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "1d": 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0d", "-1d", "xd", "0s", "-5m", "7"} {
		if _, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) succeeded", in)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1": 1, "4096": 4096, "512MiB": 512 << 20, "2GiB": 2 << 30, "1TiB": 1 << 40, "8KiB": 8 << 10} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "-1", "1.5GiB", "MiB", "1MB", "1 MiB", "9223372036854775807TiB", "99999999999999999999"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) succeeded", in)
		}
	}
}

// quota needs an account and a size; SetQuota itself is tested in the
// server package.
func TestQuotaCommand(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"quota", "--data", dir},
		{"quota", "a@example.com", "--data", dir},
		{"quota", "a@example.com", "1GB", "--data", dir},
		{"quota", "a@example.com", "1GiB"},
	} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
	err := run([]string{"quota", "a@example.com", "1GiB", "--data", dir}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no such account") {
		t.Errorf("quota for an unknown account: %v", err)
	}
}

// invite prints one code that the server accepts for exactly that email;
// backup writes a database holding the invite.
func TestInviteAndBackup(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"invite", "Alice@EXAMPLE.com", "--ttl", "2d", "--data", dir}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	code := strings.TrimSpace(out.String())
	if len(code) != 43 || strings.ContainsAny(code, "=+/ \n") {
		t.Fatalf("code %q is not 32 bytes of unpadded base64url", code)
	}
	if err := run([]string{"invite", "not-an-email", "--data", dir}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("invite accepted an invalid email")
	}

	backupPath := filepath.Join(t.TempDir(), "copy.db")
	if err := run([]string{"backup", backupPath, "--data", dir}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"backup", backupPath, "--data", dir}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Error("backup overwrote an existing file")
	}
	for _, path := range []string{filepath.Join(dir, dbName), backupPath} {
		st, err := server.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := server.New(context.Background(), server.Config{Origin: "https://hop.example.com", Store: st})
		if err != nil {
			t.Fatal(err)
		}
		h := srv.Handler()
		for email, want := range map[string]int{"Alice@example.com": 200, "alice@example.com": 401} {
			body := `{"email":"` + email + `","registration_code":"` + code + `"}`
			rec := newRecorder()
			h.ServeHTTP(rec, newRequest("POST", "/v1/signup/challenge", body))
			if rec.Code != want {
				t.Errorf("%s: signup challenge for %s: %d %s, want %d", path, email, rec.Code, rec.Body, want)
			}
		}
		srv.Close()
		st.Close()
	}
	if _, err := os.Stat(filepath.Join(dir, dbName)); err != nil {
		t.Error(err)
	}
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func newRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	return r
}
