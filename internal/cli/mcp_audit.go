package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/safepath"
)

// auditLog is hop mcp's local record of every exec and run_snippet: one JSON
// object per line, appended to mcpAuditFile in the state directory, mode
// 0600. A run writes a "start" line before anything runs and an "end" line
// with each host's exit code after. It records what ran where and for which
// client, never the output. The file is never rotated or truncated by hop.
type auditLog struct {
	mu   sync.Mutex
	path string
}

func newAuditLog(e *Env) *auditLog {
	return &auditLog{path: filepath.Join(e.Paths.StateDir, mcpAuditFile)}
}

type auditEntry struct {
	Time          time.Time     `json:"time"`
	Event         string        `json:"event"` // start or end
	Run           string        `json:"run"`   // the same in a run's start and end
	PID           int           `json:"pid"`
	Tool          string        `json:"tool"` // exec or run_snippet
	Client        string        `json:"client,omitempty"`
	ClientVersion string        `json:"client_version,omitempty"`
	Snippet       string        `json:"snippet,omitempty"`
	Hosts         []string      `json:"hosts"`
	Command       string        `json:"command"`
	TimeoutS      int           `json:"timeout_s"`
	Results       []auditResult `json:"results,omitempty"` // end only
}

type auditResult struct {
	Host       string `json:"host"`
	ExitCode   int    `json:"exit_code"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func (a *auditLog) start(entry *auditEntry) error {
	var id [8]byte
	rand.Read(id[:])
	entry.Run, entry.PID, entry.Event = hex.EncodeToString(id[:]), os.Getpid(), "start"
	return a.append(*entry)
}

// end logs the results: exit codes and hop's own errors, which redact
// scrubs as it does every answer. Output is not logged.
func (a *auditLog) end(entry *auditEntry, results []ExecResult, redact func(string) string) error {
	end := *entry
	end.Event = "end"
	for _, r := range results {
		end.Results = append(end.Results, auditResult{Host: r.Host, ExitCode: r.ExitCode, Error: redact(r.Error), DurationMS: r.DurationMS})
	}
	return a.append(end)
}

func (a *auditLog) append(entry auditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry.Time = time.Now().UTC()
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := safepath.EnsurePrivateDir(filepath.Dir(a.path)); err != nil {
		return err
	}
	f, err := openPrivateLog(a.path, "the MCP audit log", os.Getuid(), 0)
	if err != nil {
		return err
	}
	// One write per line, so lines from several hop mcp processes do not
	// interleave.
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
