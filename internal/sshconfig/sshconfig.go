// Package sshconfig writes the OpenSSH files that make a plain `ssh <alias>`
// use HopKey: a config of Host blocks, a known_hosts file holding the pinned
// host keys, and one public key file per distinct key.
//
// Everything here is generated, so nothing is parsed back. The files are
// meant to be pulled in with `Include <dir>/config` from ~/.ssh/config.
//
// Host keys are pinned per alias. Each Host block sets HostKeyAlias to its
// alias and known_hosts is keyed by that alias, so two aliases for the same
// address never share pins, and an alias with no pins has no entries at all.
// ssh then refuses it under StrictHostKeyChecking yes.
package sshconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/safepath"
)

// Host is one vault host as ssh needs to see it.
type Host struct {
	Alias     string          // what the user types: ssh <alias>
	HostName  string          // address to connect to
	Port      int             // 0 means 22
	User      string          // empty leaves ssh's own default
	PublicKey ssh.PublicKey   // selects the agent key; the private half never leaves the agent
	HostKeys  []ssh.PublicKey // pinned server keys; none means ssh refuses the host
}

// Options says where the files go and which agent socket they point at.
type Options struct {
	Dir         string // absolute; receives config, known_hosts-<id> and keys/
	AgentSocket string // absolute path of the sshagent socket
}

var (
	aliasRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	hostNameRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	userRe     = regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`)
)

// testHookBeforeConfig, if set, runs after every file the new config refers
// to is on disk and before the config itself is renamed into place. Tests use
// it to inject a failure at that point.
var testHookBeforeConfig func() error

// Write generates the files in opts.Dir.
//
// opts.Dir and opts.Dir/keys must pass safepath.EnsurePrivateDir, which also
// creates them. Public key files are named keys/<id>.pub and the pins file
// known_hosts-<id>, where <id> is 16 hex characters of the SHA-256 of the
// content, so a file never changes after it is written. Write puts those
// files down first and fsyncs them, then renames the config over the old one
// as the last step. A running ssh therefore sees either the old config with
// all its files or the new config with all its files.
//
// Afterwards Write removes the key and known_hosts files that neither the new
// config nor the config it replaced refers to. Keeping the previous
// generation means an ssh that read the old config a moment ago can still
// open the files that config names.
//
// Write does not lock: callers must not run two Writes on one directory at
// the same time.
func Write(opts Options, hosts []Host) error {
	for _, p := range []string{opts.Dir, opts.AgentSocket} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("sshconfig: path %q is not absolute", p)
		}
	}
	if _, err := checkHosts(hosts); err != nil {
		return err
	}
	dir, err := safepath.EnsurePrivateDir(opts.Dir)
	if err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	keysDir, err := safepath.EnsurePrivateDir(filepath.Join(dir, "keys"))
	if err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	// Render with the resolved directory, so the paths in the config do not
	// depend on a symlink that could be repointed later.
	opts.Dir = dir
	f, err := render(opts, hosts)
	if err != nil {
		return err
	}
	configPath := filepath.Join(dir, "config")
	prevConfig, _ := os.ReadFile(configPath) // absent or unreadable: nothing to keep

	for name, data := range f.pubKeys {
		if err := writeImmutable(filepath.Join(keysDir, name), data); err != nil {
			return err
		}
	}
	if err := syncDir(keysDir); err != nil {
		return err
	}
	if err := writeImmutable(filepath.Join(dir, f.knownHostsName), f.knownHosts); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}

	if testHookBeforeConfig != nil {
		if err := testHookBeforeConfig(); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(configPath, f.config, 0o600); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}

	keep := referencedFiles(f.config, prevConfig)
	if err := prune(dir, keysDir, keep); err != nil {
		return fmt.Errorf("sshconfig: new config is in place, but removing old files failed: %w", err)
	}
	return nil
}

type files struct {
	config         []byte
	knownHosts     []byte
	knownHostsName string            // known_hosts-<id>
	pubKeys        map[string][]byte // by file name, <id>.pub
}

// contentID names a file after its content: the first 16 hex characters of
// the SHA-256.
func contentID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// checkHosts validates hosts and returns them sorted by alias.
func checkHosts(hosts []Host) ([]Host, error) {
	hosts = slices.Clone(hosts)
	slices.SortFunc(hosts, func(a, b Host) int { return strings.Compare(a.Alias, b.Alias) })
	seen := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if err := h.validate(); err != nil {
			return nil, err
		}
		// Case-insensitive: ssh matches the alias that way, and the
		// pins are keyed by the lower-cased alias.
		lower := strings.ToLower(h.Alias)
		if seen[lower] {
			return nil, fmt.Errorf("sshconfig: duplicate alias %q", h.Alias)
		}
		seen[lower] = true
	}
	return hosts, nil
}

func render(opts Options, hosts []Host) (*files, error) {
	for _, p := range []string{opts.Dir, opts.AgentSocket} {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("sshconfig: path %q is not absolute", p)
		}
	}
	hosts, err := checkHosts(hosts)
	if err != nil {
		return nil, err
	}
	agentSock, err := quotePath(opts.AgentSocket)
	if err != nil {
		return nil, err
	}

	// known_hosts first: the config names it by content.
	var kh bytes.Buffer
	kh.WriteString("# Generated by hop from pinned host keys. Changes are overwritten.\n")
	for _, h := range hosts {
		for _, k := range h.HostKeys {
			fmt.Fprintf(&kh, "%s %s", hostKeyAlias(h), ssh.MarshalAuthorizedKey(k))
		}
	}
	knownHostsName := "known_hosts-" + contentID(kh.Bytes())
	knownHosts, err := quotePath(filepath.Join(opts.Dir, knownHostsName))
	if err != nil {
		return nil, err
	}

	var config bytes.Buffer
	config.WriteString("# Generated by hop. Changes are overwritten.\n")
	pubKeys := make(map[string][]byte, len(hosts))

	for _, h := range hosts {
		port := h.Port
		if port == 0 {
			port = 22
		}
		pub := ssh.MarshalAuthorizedKey(h.PublicKey)
		pubName := contentID(pub) + ".pub"
		pubKeys[pubName] = pub
		pubPath, err := quotePath(filepath.Join(opts.Dir, "keys", pubName))
		if err != nil {
			return nil, err
		}

		fmt.Fprintf(&config, "\nHost %s\n", h.Alias)
		fmt.Fprintf(&config, "  HostName %s\n", h.HostName)
		fmt.Fprintf(&config, "  Port %d\n", port)
		if h.User != "" {
			fmt.Fprintf(&config, "  User %s\n", h.User)
		}
		fmt.Fprintf(&config, "  IdentityAgent %s\n", agentSock)
		fmt.Fprintf(&config, "  IdentityFile %s\n", pubPath)
		config.WriteString("  IdentitiesOnly yes\n")
		config.WriteString("  ForwardAgent no\n")
		// Pins are looked up under the alias, never the address, so they
		// are per alias and not shared with whatever else uses the address.
		fmt.Fprintf(&config, "  HostKeyAlias %s\n", hostKeyAlias(h))
		// Only the pinned file counts: nothing from /etc/ssh.
		config.WriteString("  GlobalKnownHostsFile none\n")
		fmt.Fprintf(&config, "  UserKnownHostsFile %s\n", knownHosts)
		config.WriteString("  StrictHostKeyChecking yes\n")
		// Keep ssh from appending host keys it learns to the pinned file.
		config.WriteString("  UpdateHostKeys no\n")
	}
	return &files{
		config:         config.Bytes(),
		knownHosts:     kh.Bytes(),
		knownHostsName: knownHostsName,
		pubKeys:        pubKeys,
	}, nil
}

// hostKeyAlias is the name ssh looks pins up under. known_hosts matching
// lower-cases the file's patterns but not the name it is given, so the alias
// must already be lower case.
func hostKeyAlias(h Host) string { return strings.ToLower(h.Alias) }

func (h Host) validate() error {
	switch {
	case !aliasRe.MatchString(h.Alias):
		return fmt.Errorf("sshconfig: invalid alias %q", h.Alias)
	case !hostNameRe.MatchString(h.HostName):
		return fmt.Errorf("sshconfig: host %q: invalid host name %q", h.Alias, h.HostName)
	case h.Port < 0 || h.Port > 65535:
		return fmt.Errorf("sshconfig: host %q: invalid port %d", h.Alias, h.Port)
	case h.User != "" && !userRe.MatchString(h.User):
		return fmt.Errorf("sshconfig: host %q: invalid user %q", h.Alias, h.User)
	case h.PublicKey == nil:
		return fmt.Errorf("sshconfig: host %q: no public key", h.Alias)
	}
	return nil
}

// quotePath formats an absolute path as one ssh_config argument. ssh expands
// % tokens, ~ and ${VAR} in these options, so % is doubled and $ is refused.
// Anything beyond a conservative character set is wrapped in double quotes,
// with \ and " escaped.
func quotePath(p string) (string, error) {
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("sshconfig: path %q contains a control character", p)
		}
		if r == '$' {
			return "", fmt.Errorf("sshconfig: path %q contains $", p)
		}
	}
	p = strings.ReplaceAll(p, "%", "%%")
	if !strings.ContainsFunc(p, func(r rune) bool { return !isBareChar(r) }) {
		return p, nil
	}
	p = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p)
	return `"` + p + `"`, nil
}

func isBareChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("/._-+=:@%,", r)
}

// referencedRe finds the generated files a config names. It matches the
// file names, not whole paths, so quoting and escaping in the config do not
// matter.
var referencedRe = regexp.MustCompile(`keys/([0-9a-f]{16}\.pub)|(known_hosts-[0-9a-f]{16})`)

// referencedFiles returns the generated file names that any of the configs
// refer to.
func referencedFiles(configs ...[]byte) map[string]bool {
	keep := make(map[string]bool)
	for _, c := range configs {
		for _, m := range referencedRe.FindAllSubmatch(c, -1) {
			keep[string(m[1])+string(m[2])] = true // one group is empty
		}
	}
	return keep
}

// prune removes <id>.pub files from keysDir and known_hosts files from dir
// that are not in keep.
func prune(dir, keysDir string, keep map[string]bool) error {
	remove := func(d string, match func(name string) bool) error {
		entries, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || keep[name] || !match(name) {
				continue
			}
			if err := os.Remove(filepath.Join(d, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	if err := remove(keysDir, func(n string) bool { return strings.HasSuffix(n, ".pub") }); err != nil {
		return err
	}
	if err := remove(dir, func(n string) bool { return n == "known_hosts" || strings.HasPrefix(n, "known_hosts-") }); err != nil {
		return err
	}
	return syncDir(dir)
}

// writeImmutable writes a content-addressed file. An existing regular file
// with the same bytes and mode is left alone; anything else at that name
// (different bytes, a symlink, a loose mode) is replaced.
func writeImmutable(path string, data []byte) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm() == 0o600 {
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data) {
			return nil
		}
	}
	return writeFileAtomic(path, data, 0o600)
}

// syncDir flushes a directory so renames and unlinks in it survive a crash.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil // directories cannot be opened for sync there
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, syscall.EINVAL) {
		return nil // a filesystem that does not support fsync on directories
	}
	return err
}

// writeFileAtomic writes data to a temp file next to path, then renames it
// into place.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
