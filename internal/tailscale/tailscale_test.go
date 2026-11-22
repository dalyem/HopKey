package tailscale

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRunning(t *testing.T) {
	st, err := Parse(fixture(t, "running.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available || st.MagicDNSSuffix != "tailnet-example.ts.net" {
		t.Fatalf("status = %+v", st)
	}
	if st.Self.ID != "nSELF01CNTRL" || !st.Self.Self || st.Self.DNSName != "laptop.tailnet-example.ts.net" {
		t.Errorf("self = %+v", st.Self)
	}
	var names []string
	for _, p := range st.Peers {
		names = append(names, p.ID)
	}
	// Sorted by lower-cased host name, then ID: "build" twice, "daly's iphone", "prod-db".
	want := []string{"nBUILD01CNTRL", "nBUILD02CNTRL", "nPHONE01CNTRL", "nPRODDB1CNTRL"}
	if !slices.Equal(names, want) {
		t.Errorf("peer order = %v, want %v", names, want)
	}
	n, ok := st.NodeByID("nPRODDB1CNTRL")
	if !ok || !n.Online || n.SSH() != "yes" || len(n.SSHHostKeys) != 1 {
		t.Errorf("prod-db = %+v ok=%v", n, ok)
	}
	if b, _ := st.NodeByID("nBUILD01CNTRL"); b.SSH() != "unknown" {
		t.Errorf("a node with no ssh host keys has ssh hint %q, want unknown", b.SSH())
	}
	if _, ok := st.NodeByID(""); ok {
		t.Error("NodeByID found the empty ID")
	}
}

func TestParseNotRunning(t *testing.T) {
	for file, reason := range map[string]string{
		"stopped.json":    "tailscale is Stopped",
		"needslogin.json": "tailscale is NeedsLogin",
	} {
		st, err := Parse(fixture(t, file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if st.Available || st.Reason != reason {
			t.Errorf("%s: available=%v reason=%q, want unavailable %q", file, st.Available, st.Reason, reason)
		}
		if len(st.Nodes()) != 0 || len(st.Find("laptop")) != 0 {
			t.Errorf("%s: an unavailable status returned nodes", file)
		}
	}
	if _, err := Parse([]byte("not json")); err == nil {
		t.Error("Parse accepted malformed JSON")
	}
}

func TestFind(t *testing.T) {
	st, err := Parse(fixture(t, "running.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		target string
		want   []string // node IDs
	}{
		{"prod-db", []string{"nPRODDB1CNTRL"}},
		{"PROD-DB", []string{"nPRODDB1CNTRL"}},
		{"prod-db.tailnet-example.ts.net", []string{"nPRODDB1CNTRL"}},
		{"prod-db.tailnet-example.ts.net.", []string{"nPRODDB1CNTRL"}}, // trailing dot
		{"100.64.0.2", []string{"nPRODDB1CNTRL"}},
		{"fd7a:115c:a1e0::2", []string{"nPRODDB1CNTRL"}},
		{"build", []string{"nBUILD01CNTRL", "nBUILD02CNTRL"}}, // duplicate host name
		{"build-1", []string{"nBUILD02CNTRL"}},                // MagicDNS label of the second
		{"build-1.tailnet-example.ts.net.", []string{"nBUILD02CNTRL"}},
		{"Daly's iPhone", []string{"nPHONE01CNTRL"}},
		{"dalys-iphone", []string{"nPHONE01CNTRL"}},
		{"laptop", []string{"nSELF01CNTRL"}},
		{"100.64.0.99", nil},
		{"prod", nil}, // no prefix matching here
		{"", nil},
	}
	for _, tt := range tests {
		var got []string
		for _, n := range st.Find(tt.target) {
			got = append(got, n.ID)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("Find(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestClientStatus(t *testing.T) {
	good := fixture(t, "running.json")
	tests := []struct {
		name      string
		run       func(ctx context.Context, bin string, args ...string) ([]byte, error)
		wantAvail bool
		wantWhy   string
		wantErr   bool
	}{
		{
			name: "running",
			run: func(_ context.Context, bin string, args ...string) ([]byte, error) {
				if !slices.Equal(args, []string{"status", "--json"}) {
					t.Errorf("args = %v", args)
				}
				return good, nil
			},
			wantAvail: true,
		},
		{
			name: "binary missing everywhere",
			run: func(context.Context, string, ...string) ([]byte, error) {
				return nil, &exec.Error{Name: "tailscale", Err: exec.ErrNotFound}
			},
			wantWhy: "tailscale is not installed",
		},
		{
			name: "first binary missing, second works",
			run: func(_ context.Context, bin string, _ ...string) ([]byte, error) {
				if bin == "tailscale" {
					return nil, &fs.PathError{Op: "fork/exec", Path: bin, Err: fs.ErrNotExist}
				}
				return good, nil
			},
			wantAvail: true,
		},
		{
			name: "daemon not running",
			run: func(context.Context, string, ...string) ([]byte, error) {
				return nil, errors.New("exit status 1: failed to connect to local tailscaled")
			},
			wantWhy: "tailscale is not running: exit status 1: failed to connect to local tailscaled",
		},
		{
			name:      "stopped",
			run:       func(context.Context, string, ...string) ([]byte, error) { return fixture(t, "stopped.json"), nil },
			wantAvail: false,
			wantWhy:   "tailscale is Stopped",
		},
		{
			name:    "garbage output",
			run:     func(context.Context, string, ...string) ([]byte, error) { return []byte("<html>"), nil },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{Binaries: []string{"tailscale", "/app/tailscale"}, Run: tt.run}
			st, err := c.Status(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if st.Available != tt.wantAvail || st.Reason != tt.wantWhy {
				t.Errorf("available=%v reason=%q, want %v %q", st.Available, st.Reason, tt.wantAvail, tt.wantWhy)
			}
		})
	}
}
