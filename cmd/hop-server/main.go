// Command hop-server is the HopKey sync server.
//
//	hop-server serve --listen ADDR --data DIR --origin URL [--tls-cert FILE --tls-key FILE]
//	                 [--insecure-http] [--trusted-proxy CIDR]...
//	hop-server invite EMAIL [--ttl 7d] --data DIR
//	hop-server quota ACCOUNT_ID|EMAIL SIZE --data DIR
//	hop-server backup PATH --data DIR
//	hop-server version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/version"
)

const dbName = "hop-server.db"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hop-server:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hop-server serve|invite|quota|backup|version")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "invite":
		return invite(args[1:], stdout)
	case "quota":
		return quota(args[1:], stdout)
	case "backup":
		return backup(args[1:], stdout)
	case "version":
		fmt.Fprintln(stdout, "hop-server", version.Version)
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// parse parses flags that may come before or after the positional
// arguments, so "invite EMAIL --ttl 7d" works.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func openStore(dir string) (*server.SQLite, error) {
	if dir == "" {
		return nil, errors.New("--data is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(filepath.Join(dir, dbName))
	if err != nil {
		return nil, err
	}
	return server.OpenSQLite(abs)
}

type cidrs []netip.Prefix

func (c *cidrs) String() string { return fmt.Sprint(*c) }

func (c *cidrs) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return err
		}
		*c = append(*c, p.Masked())
	}
	return nil
}

func serve(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8443", "listen address")
	data := fs.String("data", "", "data directory")
	origin := fs.String("origin", "", "external origin clients use, such as https://hop.example.com")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	insecure := fs.Bool("insecure-http", false, "serve plain HTTP on a non-loopback address (TLS terminated in front)")
	quota := fs.Int64("quota-mib", 0, "default account storage quota in MiB (default 256)")
	var proxies cidrs
	fs.Var(&proxies, "trusted-proxy", "CIDR of a proxy whose X-Forwarded-For is trusted (repeatable)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}
	if *origin == "" {
		return errors.New("--origin is required")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("--tls-cert and --tls-key go together")
	}
	useTLS := *tlsCert != ""
	if err := checkListen(*listen, useTLS, *insecure); err != nil {
		return err
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(stderr, nil))
	lim := server.DefaultLimits()
	if *quota > 0 {
		lim.QuotaBytes = *quota * server.MiB
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, server.Config{
		Origin: *origin, Store: st, TrustedProxies: proxies, Logger: log, Limits: &lim,
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		if useTLS {
			errc <- hs.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	log.Info("hop-server listening", "addr", *listen, "tls", useTLS, "version", version.Version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	srv.Close() // wake long-polls before draining
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// checkListen refuses plain HTTP on a non-loopback address unless
// --insecure-http says TLS is terminated in front.
func checkListen(addr string, useTLS, insecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", addr, err)
	}
	if useTLS || insecure || loopback(host) {
		return nil
	}
	return fmt.Errorf("refusing plain HTTP on non-loopback address %q: give --tls-cert/--tls-key, or --insecure-http when TLS is terminated in front", addr)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func invite(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	ttlText := fs.String("ttl", "7d", "how long the code is valid: Nd, or a Go duration such as 36h")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server invite EMAIL [--ttl 7d] --data DIR")
	}
	ttl, err := parseTTL(*ttlText)
	if err != nil {
		return err
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	code, err := server.CreateInvite(context.Background(), st, pos[0], ttl, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, code)
	return nil
}

func parseTTL(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 || n > 3650 {
			return 0, fmt.Errorf("--ttl %q: want a positive number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--ttl %q: want Nd or a positive duration", s)
	}
	return d, nil
}

// quota sets an account's storage quota. Raising it far enough to free the
// whole recovery reserve also ends a capacity-exhausted state (R13).
func quota(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("quota", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: hop-server quota ACCOUNT_ID|EMAIL SIZE --data DIR (SIZE in bytes, or with KiB, MiB, GiB or TiB)")
	}
	size, err := parseSize(pos[1])
	if err != nil {
		return err
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	q, err := server.SetQuota(context.Background(), st, pos[0], size, server.DefaultLimits())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "account %s <%s>: quota %d bytes, used %d bytes, recovery reserve %d bytes, reserve %s\n",
		q.AccountID, q.Email, q.QuotaBytes, q.UsedBytes, q.ReserveBytes, q.Reserve)
	if q.Reserve != server.ReserveIntact {
		fmt.Fprintf(stdout, "the reserve is still spent: a quota of at least %d bytes replenishes it\n", q.UsedBytes+q.ReserveBytes)
	}
	return nil
}

// parseSize parses a byte count, optionally with a binary unit.
func parseSize(s string) (int64, error) {
	num, mult := s, int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40}} {
		if n, ok := strings.CutSuffix(s, u.suffix); ok {
			num, mult = n, u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("size %q: want a positive number of bytes, KiB, MiB, GiB or TiB", s)
	}
	return n * mult, nil
}

func backup(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server backup PATH --data DIR")
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(context.Background(), pos[0]); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "backup written to", pos[0])
	return nil
}
