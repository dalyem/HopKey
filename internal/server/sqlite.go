package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// schemaVersion is stored in meta; Open refuses a database from a newer
// server and moves an older one forward (migrate).
const schemaVersion = "3"

// schema is the multi-tenant SQLite schema. IDs and digests are BLOBs of
// their raw bytes; times are Unix seconds.
const schema = `
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS accounts (
	account_id   BLOB PRIMARY KEY,
	email        TEXT NOT NULL UNIQUE,
	vault_id     BLOB NOT NULL UNIQUE,
	kdf_version  INTEGER NOT NULL,
	salt         BLOB NOT NULL,
	auth_sha256  BLOB NOT NULL,
	rauth_sha256 BLOB NOT NULL,
	cred_gen     INTEGER NOT NULL,
	used_bytes   INTEGER NOT NULL,
	quota_bytes  INTEGER NOT NULL,
	reserve      INTEGER NOT NULL,
	created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS vaults (
	vault_id        BLOB PRIMARY KEY,
	account_id      BLOB NOT NULL UNIQUE REFERENCES accounts (account_id),
	head_seq        INTEGER NOT NULL,
	head_h          BLOB NOT NULL,
	public_state    BLOB NOT NULL,
	last_bootstrap  INTEGER NOT NULL,
	last_checkpoint INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS log (
	vault_id BLOB NOT NULL REFERENCES vaults (vault_id),
	seq      INTEGER NOT NULL,
	h        BLOB NOT NULL,
	kind     TEXT NOT NULL,
	wire     BLOB NOT NULL,
	PRIMARY KEY (vault_id, seq),
	UNIQUE (vault_id, h)
) STRICT;

CREATE TABLE IF NOT EXISTS objects (
	vault_id BLOB NOT NULL REFERENCES vaults (vault_id),
	sha256   BLOB NOT NULL,
	body     BLOB NOT NULL,
	seq      INTEGER NOT NULL,
	PRIMARY KEY (vault_id, sha256)
) STRICT;

CREATE TABLE IF NOT EXISTS devices (
	account_id BLOB NOT NULL REFERENCES accounts (account_id),
	device_id  BLOB NOT NULL,
	sig_pk     BLOB NOT NULL,
	active     INTEGER NOT NULL,
	added_seq  INTEGER NOT NULL,
	PRIMARY KEY (account_id, device_id)
) STRICT;

-- When each device last made an authenticated request. A table of its
-- own, so a database from before it needs no migration.
CREATE TABLE IF NOT EXISTS device_seen (
	account_id BLOB NOT NULL,
	device_id  BLOB NOT NULL,
	seen_at    INTEGER NOT NULL,
	PRIMARY KEY (account_id, device_id)
) STRICT;

CREATE TABLE IF NOT EXISTS receipts (
	account_id BLOB NOT NULL REFERENCES accounts (account_id),
	device_id  BLOB NOT NULL,
	how        TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	h          BLOB NOT NULL,
	PRIMARY KEY (account_id, device_id)
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
	token_hash BLOB PRIMARY KEY,
	account_id BLOB NOT NULL,
	vault_id   BLOB NOT NULL,
	device_id  BLOB NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS sessions_device ON sessions (account_id, device_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS login_tokens (
	token_hash    BLOB PRIMARY KEY,
	kind          TEXT NOT NULL,
	account_id    BLOB NOT NULL,
	vault_id      BLOB NOT NULL,
	cred_gen      INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL,
	bootstrap_seq INTEGER,
	bootstrap_h   BLOB
) STRICT;
CREATE INDEX IF NOT EXISTS login_tokens_expiry ON login_tokens (expires_at);

CREATE TABLE IF NOT EXISTS challenges (
	hash       BLOB PRIMARY KEY,
	kind       TEXT NOT NULL,
	origin     TEXT NOT NULL,
	account_id BLOB NOT NULL,
	device_id  BLOB NOT NULL,
	operation  TEXT NOT NULL,
	email      TEXT NOT NULL,
	cap_hash   BLOB NOT NULL,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS challenges_device ON challenges (account_id, device_id, expires_at);
CREATE INDEX IF NOT EXISTS challenges_cap ON challenges (cap_hash, expires_at);
CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges (expires_at);

CREATE TABLE IF NOT EXISTS registrations (
	cap_hash       BLOB PRIMARY KEY,
	email          TEXT NOT NULL,
	created_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL,
	consumed_at    INTEGER,
	ack_account_id BLOB,
	ack_vault_id   BLOB,
	ack_digest     BLOB,
	ack_seq        INTEGER,
	ack_h          BLOB
) STRICT;

CREATE TABLE IF NOT EXISTS enrollments (
	enroll_id    BLOB PRIMARY KEY,
	routing_code TEXT NOT NULL UNIQUE,
	token_hash   BLOB NOT NULL,
	commit_msg   BLOB NOT NULL,
	ip           TEXT NOT NULL,
	account_id   BLOB,
	device_id    BLOB,
	expires_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS enrollments_ip ON enrollments (ip, expires_at);
CREATE INDEX IF NOT EXISTS enrollments_expiry ON enrollments (expires_at);

CREATE TABLE IF NOT EXISTS enroll_messages (
	enroll_id BLOB NOT NULL REFERENCES enrollments (enroll_id),
	n         INTEGER NOT NULL,
	type      TEXT NOT NULL,
	body      BLOB NOT NULL,
	PRIMARY KEY (enroll_id, n)
) STRICT;
` + schemaV3

// schemaV3 is what version 3 added: the admin audit trail. account_id is
// not a foreign key, so a row outlives its account.
const schemaV3 = `
CREATE TABLE IF NOT EXISTS admin_audit (
	id         INTEGER PRIMARY KEY,
	at         INTEGER NOT NULL,
	actor      TEXT NOT NULL,
	action     TEXT NOT NULL,
	account_id BLOB,
	params     BLOB NOT NULL,
	result     TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS admin_audit_account ON admin_audit (account_id, at);
`

// SQLite is the Store backed by one SQLite database in WAL mode. Writes go
// through a single connection and begin with BEGIN IMMEDIATE, so they are
// serialized; reads use a pool of read-only connections.
type SQLite struct {
	w *sql.DB
	r *sql.DB
}

// OpenSQLite opens (creating if needed) the database file at path.
func OpenSQLite(path string) (*SQLite, error) {
	dsn := func(extra url.Values) string {
		q := url.Values{}
		q.Set("_busy_timeout", "10000")
		q.Set("_journal_mode", "WAL")
		q.Set("_synchronous", "FULL")
		q.Set("_foreign_keys", "1")
		for k, v := range extra {
			q[k] = v
		}
		return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
	}
	w, err := sql.Open("sqlite", dsn(url.Values{"_txlock": {"immediate"}}))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetConnMaxIdleTime(0)
	s := &SQLite{w: w}
	if err := s.migrate(); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(url.Values{"_query_only": {"1"}}))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(16)
	s.r = r
	return s, nil
}

// migrate creates any missing table and records or checks the schema
// version, in one write transaction, so two processes opening the same file
// cannot both migrate it. Every table is CREATE IF NOT EXISTS: a version 2
// database gains admin_audit and moves to version 3, and no existing row
// changes. A database from a newer server is refused before anything is
// created. An older server refuses a migrated file; a hop-server backup
// taken before upgrading is the way back.
func (s *SQLite) migrate() error {
	tx, err := s.w.Begin() // BEGIN IMMEDIATE (_txlock)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		return fmt.Errorf("server: creating schema: %w", err)
	}
	var v []byte
	err = tx.QueryRow(`SELECT v FROM meta WHERE k = 'schema_version'`).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.Exec(`INSERT INTO meta (k, v) VALUES ('schema_version', ?)`, []byte(schemaVersion))
	case err != nil:
	case string(v) == "2":
		_, err = tx.Exec(`UPDATE meta SET v = ? WHERE k = 'schema_version'`, []byte(schemaVersion))
	case string(v) != schemaVersion:
		err = fmt.Errorf("server: database schema version %q is not %q", v, schemaVersion)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

func (s *SQLite) View(ctx context.Context, fn func(Tx) error) error {
	tx, err := s.r.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(&sqliteTx{ctx: ctx, tx: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) Update(ctx context.Context, fn func(Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(&sqliteTx{ctx: ctx, tx: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

// Backup writes a consistent snapshot with VACUUM INTO.
func (s *SQLite) Backup(ctx context.Context, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("server: backup target %s exists", abs)
	}
	_, err = s.w.ExecContext(ctx, `VACUUM INTO ?`, abs)
	return err
}

type sqliteTx struct {
	ctx context.Context
	tx  *sql.Tx
}

func (t *sqliteTx) exec(q string, args ...any) error {
	_, err := t.tx.ExecContext(t.ctx, q, args...)
	return mapErr(err)
}

func (t *sqliteTx) row(q string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(t.ctx, q, args...)
}

// mapErr turns a uniqueness violation into ErrDuplicate and a missing row
// into ErrNotFound.
func mapErr(err error) error {
	var se *sqlite.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY):
		return fmt.Errorf("%w: %v", ErrDuplicate, err)
	}
	return err
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(s int64) time.Time { return time.Unix(s, 0).UTC() }

func scanID(b []byte, id *model.ID) error {
	if len(b) != len(id) {
		return fmt.Errorf("server: stored id has %d bytes", len(b))
	}
	copy(id[:], b)
	return nil
}

func scanHash(b []byte, h *crypto.Hash) error {
	if len(b) != len(h) {
		return fmt.Errorf("server: stored hash has %d bytes", len(b))
	}
	copy(h[:], b)
	return nil
}

func (t *sqliteTx) Meta(key string) ([]byte, error) {
	var v []byte
	err := t.row(`SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	return v, mapErr(err)
}

func (t *sqliteTx) SetMeta(key string, v []byte) error {
	return t.exec(`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`, key, v)
}

const accountCols = `account_id, email, vault_id, kdf_version, salt, auth_sha256, rauth_sha256, cred_gen, used_bytes, quota_bytes, reserve, created_at`

func (t *sqliteTx) scanAccount(r *sql.Row) (*Account, error) {
	var a Account
	var id, vid, auth, rauth []byte
	var created int64
	err := r.Scan(&id, &a.Email, &vid, &a.KDFVersion, &a.Salt, &auth, &rauth, &a.CredGen, &a.UsedBytes, &a.QuotaBytes, &a.Reserve, &created)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := errors.Join(scanID(id, &a.ID), scanID(vid, &a.VaultID), scanHash(auth, &a.AuthSHA256), scanHash(rauth, &a.RAuthSHA256)); err != nil {
		return nil, err
	}
	a.CreatedAt = fromUnix(created)
	return &a, nil
}

func (t *sqliteTx) Account(id model.ID) (*Account, error) {
	return t.scanAccount(t.row(`SELECT `+accountCols+` FROM accounts WHERE account_id = ?`, id[:]))
}

func (t *sqliteTx) AccountByEmail(email string) (*Account, error) {
	return t.scanAccount(t.row(`SELECT `+accountCols+` FROM accounts WHERE email = ?`, email))
}

func (t *sqliteTx) AccountTaken(id model.ID, email string, vaultID model.ID) (bool, error) {
	var n int
	err := t.row(`SELECT
		(SELECT COUNT(*) FROM accounts WHERE account_id = ? OR email = ? OR vault_id = ?) +
		(SELECT COUNT(*) FROM vaults WHERE vault_id = ?)`, id[:], email, vaultID[:], vaultID[:]).Scan(&n)
	return n > 0, mapErr(err)
}

func (t *sqliteTx) InsertAccount(a *Account) error {
	return t.exec(`INSERT INTO accounts (`+accountCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID[:], a.Email, a.VaultID[:], a.KDFVersion, a.Salt, a.AuthSHA256[:], a.RAuthSHA256[:],
		a.CredGen, a.UsedBytes, a.QuotaBytes, a.Reserve, unix(a.CreatedAt))
}

func (t *sqliteTx) UpdateAccount(a *Account) error {
	return t.exec(`UPDATE accounts SET kdf_version = ?, salt = ?, auth_sha256 = ?, rauth_sha256 = ?,
		cred_gen = ?, used_bytes = ?, quota_bytes = ?, reserve = ? WHERE account_id = ?`,
		a.KDFVersion, a.Salt, a.AuthSHA256[:], a.RAuthSHA256[:], a.CredGen, a.UsedBytes, a.QuotaBytes, a.Reserve, a.ID[:])
}

func (t *sqliteTx) Vault(id model.ID) (*Vault, error) {
	var v Vault
	var vid, aid, h []byte
	err := t.row(`SELECT vault_id, account_id, head_seq, head_h, public_state, last_bootstrap, last_checkpoint
		FROM vaults WHERE vault_id = ?`, id[:]).Scan(&vid, &aid, &v.Head.Seq, &h, &v.PublicState, &v.LastBootstrap, &v.LastCheckpoint)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := errors.Join(scanID(vid, &v.ID), scanID(aid, &v.AccountID), scanHash(h, &v.Head.H)); err != nil {
		return nil, err
	}
	return &v, nil
}

func (t *sqliteTx) InsertVault(v *Vault) error {
	return t.exec(`INSERT INTO vaults (vault_id, account_id, head_seq, head_h, public_state, last_bootstrap, last_checkpoint)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, v.ID[:], v.AccountID[:], v.Head.Seq, v.Head.H[:], v.PublicState, v.LastBootstrap, v.LastCheckpoint)
}

func (t *sqliteTx) UpdateVault(v *Vault) error {
	return t.exec(`UPDATE vaults SET head_seq = ?, head_h = ?, public_state = ?, last_bootstrap = ?, last_checkpoint = ?
		WHERE vault_id = ?`, v.Head.Seq, v.Head.H[:], v.PublicState, v.LastBootstrap, v.LastCheckpoint, v.ID[:])
}

func scanEntry(sc interface{ Scan(...any) error }) (*LogEntry, error) {
	var e LogEntry
	var h []byte
	var kind string
	if err := sc.Scan(&e.Seq, &h, &kind, &e.Wire); err != nil {
		return nil, mapErr(err)
	}
	e.Kind = vaultlog.Kind(kind)
	return &e, scanHash(h, &e.H)
}

// Entry and Entries take any u64 seq. SQLite integers are signed 64-bit,
// so no stored seq exceeds math.MaxInt64, and a larger one cannot be bound
// as a parameter.
func (t *sqliteTx) Entry(vaultID model.ID, seq uint64) (*LogEntry, error) {
	if seq > math.MaxInt64 {
		return nil, ErrNotFound
	}
	return scanEntry(t.row(`SELECT seq, h, kind, wire FROM log WHERE vault_id = ? AND seq = ?`, vaultID[:], seq))
}

func (t *sqliteTx) EntryByHash(vaultID model.ID, h crypto.Hash) (*LogEntry, error) {
	return scanEntry(t.row(`SELECT seq, h, kind, wire FROM log WHERE vault_id = ? AND h = ?`, vaultID[:], h[:]))
}

func (t *sqliteTx) Entries(vaultID model.ID, after uint64, fromStart bool, limit int, fn func(*LogEntry) bool) error {
	if !fromStart && after >= math.MaxInt64 {
		return nil
	}
	q := `SELECT seq, h, kind, wire FROM log WHERE vault_id = ? AND seq > ? ORDER BY seq LIMIT ?`
	args := []any{vaultID[:], after, limit}
	if fromStart {
		q = `SELECT seq, h, kind, wire FROM log WHERE vault_id = ? ORDER BY seq LIMIT ?`
		args = []any{vaultID[:], limit}
	}
	rows, err := t.tx.QueryContext(t.ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return err
		}
		if !fn(e) {
			break
		}
	}
	return rows.Err()
}

func (t *sqliteTx) InsertEntry(vaultID model.ID, e *LogEntry) error {
	return t.exec(`INSERT INTO log (vault_id, seq, h, kind, wire) VALUES (?, ?, ?, ?, ?)`,
		vaultID[:], e.Seq, e.H[:], string(e.Kind), e.Wire)
}

func (t *sqliteTx) Object(vaultID model.ID, h crypto.Hash) ([]byte, error) {
	var b []byte
	err := t.row(`SELECT body FROM objects WHERE vault_id = ? AND sha256 = ?`, vaultID[:], h[:]).Scan(&b)
	return b, mapErr(err)
}

func (t *sqliteTx) InsertObject(vaultID model.ID, h crypto.Hash, body []byte, seq uint64) error {
	return t.exec(`INSERT INTO objects (vault_id, sha256, body, seq) VALUES (?, ?, ?, ?)
		ON CONFLICT (vault_id, sha256) DO NOTHING`, vaultID[:], h[:], body, seq)
}

func (t *sqliteTx) Device(accountID, deviceID model.ID) (*Device, error) {
	d := Device{AccountID: accountID, DeviceID: deviceID}
	err := t.row(`SELECT sig_pk, active, added_seq FROM devices WHERE account_id = ? AND device_id = ?`,
		accountID[:], deviceID[:]).Scan(&d.SigPK, &d.Active, &d.AddedSeq)
	if err != nil {
		return nil, mapErr(err)
	}
	return &d, nil
}

func (t *sqliteTx) PutDevice(d *Device) error {
	return t.exec(`INSERT INTO devices (account_id, device_id, sig_pk, active, added_seq) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (account_id, device_id) DO UPDATE SET active = excluded.active`,
		d.AccountID[:], d.DeviceID[:], d.SigPK, d.Active, d.AddedSeq)
}

func (t *sqliteTx) SetDeviceSeen(accountID, deviceID model.ID, at time.Time) error {
	return t.exec(`INSERT INTO device_seen (account_id, device_id, seen_at) VALUES (?, ?, ?)
		ON CONFLICT (account_id, device_id) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at)`,
		accountID[:], deviceID[:], at.Unix())
}

func (t *sqliteTx) DevicesSeen(accountID model.ID) (map[model.ID]time.Time, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT device_id, seen_at FROM device_seen WHERE account_id = ?`, accountID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.ID]time.Time{}
	for rows.Next() {
		var b []byte
		var at int64
		if err := rows.Scan(&b, &at); err != nil {
			return nil, err
		}
		var id model.ID
		if err := scanID(b, &id); err != nil {
			return nil, err
		}
		out[id] = time.Unix(at, 0).UTC()
	}
	return out, rows.Err()
}

func (t *sqliteTx) Receipt(accountID, deviceID model.ID) (*Receipt, error) {
	r := Receipt{AccountID: accountID, DeviceID: deviceID}
	var how string
	var h []byte
	err := t.row(`SELECT how, seq, h FROM receipts WHERE account_id = ? AND device_id = ?`,
		accountID[:], deviceID[:]).Scan(&how, &r.Seq, &h)
	if err != nil {
		return nil, mapErr(err)
	}
	r.How = vaultlog.DepartureKind(how)
	return &r, scanHash(h, &r.H)
}

func (t *sqliteTx) InsertReceipt(r *Receipt) error {
	return t.exec(`INSERT INTO receipts (account_id, device_id, how, seq, h) VALUES (?, ?, ?, ?, ?)`,
		r.AccountID[:], r.DeviceID[:], string(r.How), r.Seq, r.H[:])
}

func (t *sqliteTx) Session(tokenHash crypto.Hash) (*Session, error) {
	s := Session{TokenHash: tokenHash}
	var aid, vid, did []byte
	var exp int64
	err := t.row(`SELECT account_id, vault_id, device_id, expires_at FROM sessions WHERE token_hash = ?`,
		tokenHash[:]).Scan(&aid, &vid, &did, &exp)
	if err != nil {
		return nil, mapErr(err)
	}
	s.ExpiresAt = fromUnix(exp)
	return &s, errors.Join(scanID(aid, &s.AccountID), scanID(vid, &s.VaultID), scanID(did, &s.DeviceID))
}

func (t *sqliteTx) InsertSession(s *Session) error {
	return t.exec(`INSERT INTO sessions (token_hash, account_id, vault_id, device_id, expires_at) VALUES (?, ?, ?, ?, ?)`,
		s.TokenHash[:], s.AccountID[:], s.VaultID[:], s.DeviceID[:], unix(s.ExpiresAt))
}

func (t *sqliteTx) DeleteSessions(accountID model.ID, deviceID *model.ID) error {
	if deviceID == nil {
		return t.exec(`DELETE FROM sessions WHERE account_id = ?`, accountID[:])
	}
	return t.exec(`DELETE FROM sessions WHERE account_id = ? AND device_id = ?`, accountID[:], deviceID[:])
}

func (t *sqliteTx) LoginToken(tokenHash crypto.Hash) (*LoginToken, error) {
	l := LoginToken{TokenHash: tokenHash}
	var kind string
	var aid, vid, bh []byte
	var exp int64
	var bseq sql.NullInt64
	err := t.row(`SELECT kind, account_id, vault_id, cred_gen, expires_at, bootstrap_seq, bootstrap_h
		FROM login_tokens WHERE token_hash = ?`, tokenHash[:]).Scan(&kind, &aid, &vid, &l.CredGen, &exp, &bseq, &bh)
	if err != nil {
		return nil, mapErr(err)
	}
	l.Kind = TokenKind(kind)
	l.ExpiresAt = fromUnix(exp)
	if bseq.Valid {
		l.Bootstrap = &vaultlog.Head{Seq: uint64(bseq.Int64)}
		if err := scanHash(bh, &l.Bootstrap.H); err != nil {
			return nil, err
		}
	}
	return &l, errors.Join(scanID(aid, &l.AccountID), scanID(vid, &l.VaultID))
}

func (t *sqliteTx) InsertLoginToken(l *LoginToken) error {
	return t.exec(`INSERT INTO login_tokens (token_hash, kind, account_id, vault_id, cred_gen, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, l.TokenHash[:], string(l.Kind), l.AccountID[:], l.VaultID[:], l.CredGen, unix(l.ExpiresAt))
}

func (t *sqliteTx) SetLoginTokenBootstrap(tokenHash crypto.Hash, h vaultlog.Head) error {
	return t.exec(`UPDATE login_tokens SET bootstrap_seq = ?, bootstrap_h = ? WHERE token_hash = ?`,
		h.Seq, h.H[:], tokenHash[:])
}

func (t *sqliteTx) Challenge(hash crypto.Hash) (*Challenge, error) {
	c := Challenge{Hash: hash}
	var kind string
	var aid, did, capHash []byte
	var exp int64
	err := t.row(`SELECT kind, origin, account_id, device_id, operation, email, cap_hash, expires_at
		FROM challenges WHERE hash = ?`, hash[:]).Scan(&kind, &c.Origin, &aid, &did, &c.Operation, &c.Email, &capHash, &exp)
	if err != nil {
		return nil, mapErr(err)
	}
	c.Kind = ChallengeKind(kind)
	c.ExpiresAt = fromUnix(exp)
	return &c, errors.Join(scanID(aid, &c.AccountID), scanID(did, &c.DeviceID), scanHash(capHash, &c.CapHash))
}

func (t *sqliteTx) InsertChallenge(c *Challenge) error {
	return t.exec(`INSERT INTO challenges (hash, kind, origin, account_id, device_id, operation, email, cap_hash, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.Hash[:], string(c.Kind), c.Origin, c.AccountID[:], c.DeviceID[:],
		c.Operation, c.Email, c.CapHash[:], unix(c.ExpiresAt))
}

func (t *sqliteTx) DeleteChallenge(hash crypto.Hash) error {
	return t.exec(`DELETE FROM challenges WHERE hash = ?`, hash[:])
}

func (t *sqliteTx) CountChallenges(now time.Time, scope ChallengeScope) (int, error) {
	q := `SELECT COUNT(*) FROM challenges WHERE expires_at > ?`
	args := []any{unix(now)}
	if scope.AccountID != nil && scope.DeviceID != nil {
		q += ` AND account_id = ? AND device_id = ?`
		args = append(args, scope.AccountID[:], scope.DeviceID[:])
	}
	if scope.CapHash != nil {
		q += ` AND cap_hash = ?`
		args = append(args, scope.CapHash[:])
	}
	var n int
	err := t.row(q, args...).Scan(&n)
	return n, mapErr(err)
}

func (t *sqliteTx) Registration(capHash crypto.Hash) (*Registration, error) {
	r := Registration{CapHash: capHash}
	var created, exp int64
	var consumed, ackSeq sql.NullInt64
	var aid, vid, digest, ackH []byte
	err := t.row(`SELECT email, created_at, expires_at, consumed_at, ack_account_id, ack_vault_id, ack_digest, ack_seq, ack_h
		FROM registrations WHERE cap_hash = ?`, capHash[:]).Scan(&r.Email, &created, &exp, &consumed, &aid, &vid, &digest, &ackSeq, &ackH)
	if err != nil {
		return nil, mapErr(err)
	}
	r.CreatedAt, r.ExpiresAt = fromUnix(created), fromUnix(exp)
	if consumed.Valid {
		a := &Ack{Head: vaultlog.Head{Seq: uint64(ackSeq.Int64)}}
		if err := errors.Join(scanID(aid, &a.AccountID), scanID(vid, &a.VaultID), scanHash(digest, &a.Digest), scanHash(ackH, &a.Head.H)); err != nil {
			return nil, err
		}
		r.Ack, r.ConsumedAt = a, fromUnix(consumed.Int64)
	}
	return &r, nil
}

func (t *sqliteTx) InsertRegistration(r *Registration) error {
	return t.exec(`INSERT INTO registrations (cap_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		r.CapHash[:], r.Email, unix(r.CreatedAt), unix(r.ExpiresAt))
}

func (t *sqliteTx) ConsumeRegistration(capHash crypto.Hash, a *Ack, at time.Time) error {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE registrations SET consumed_at = ?, ack_account_id = ?, ack_vault_id = ?,
		ack_digest = ?, ack_seq = ?, ack_h = ? WHERE cap_hash = ? AND consumed_at IS NULL`,
		unix(at), a.AccountID[:], a.VaultID[:], a.Digest[:], a.Head.Seq, a.Head.H[:], capHash[:])
	if err != nil {
		return mapErr(err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("server: registration capability was not consumable (%d rows, %v)", n, err)
	}
	return nil
}

const mailboxCols = `enroll_id, routing_code, token_hash, commit_msg, ip, account_id, device_id, expires_at`

func scanMailbox(r *sql.Row) (*Mailbox, error) {
	var m Mailbox
	var id, tok, aid, did []byte
	var exp int64
	if err := r.Scan(&id, &m.RoutingCode, &tok, &m.Commit, &m.IP, &aid, &did, &exp); err != nil {
		return nil, mapErr(err)
	}
	m.ExpiresAt = fromUnix(exp)
	if err := errors.Join(scanID(id, &m.ID), scanHash(tok, &m.TokenHash)); err != nil {
		return nil, err
	}
	if aid != nil || did != nil {
		m.AccountID, m.DeviceID = new(model.ID), new(model.ID)
		if err := errors.Join(scanID(aid, m.AccountID), scanID(did, m.DeviceID)); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

func (t *sqliteTx) InsertMailbox(m *Mailbox) error {
	var aid, did []byte
	if m.AccountID != nil && m.DeviceID != nil {
		aid, did = m.AccountID[:], m.DeviceID[:]
	}
	return t.exec(`INSERT INTO enrollments (`+mailboxCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID[:], m.RoutingCode, m.TokenHash[:], m.Commit, m.IP, aid, did, unix(m.ExpiresAt))
}

func (t *sqliteTx) Mailbox(id model.ID) (*Mailbox, error) {
	return scanMailbox(t.row(`SELECT `+mailboxCols+` FROM enrollments WHERE enroll_id = ?`, id[:]))
}

func (t *sqliteTx) MailboxByCode(code string) (*Mailbox, error) {
	return scanMailbox(t.row(`SELECT `+mailboxCols+` FROM enrollments WHERE routing_code = ?`, code))
}

func (t *sqliteTx) ClaimMailbox(id, accountID, deviceID model.ID) error {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE enrollments SET account_id = ?, device_id = ?
		WHERE enroll_id = ? AND account_id IS NULL AND device_id IS NULL`, accountID[:], deviceID[:], id[:])
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (t *sqliteTx) CountMailboxes(now time.Time, ip *string) (int, error) {
	q := `SELECT COUNT(*) FROM enrollments WHERE expires_at > ?`
	args := []any{unix(now)}
	if ip != nil {
		q += ` AND ip = ?`
		args = append(args, *ip)
	}
	var n int
	err := t.row(q, args...).Scan(&n)
	return n, mapErr(err)
}

func (t *sqliteTx) MailboxMessages(id model.ID, after uint64) ([]MailboxMessage, error) {
	if after >= math.MaxInt64 {
		return nil, nil
	}
	rows, err := t.tx.QueryContext(t.ctx, `SELECT n, type, body FROM enroll_messages
		WHERE enroll_id = ? AND n > ? ORDER BY n`, id[:], after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MailboxMessage
	for rows.Next() {
		var m MailboxMessage
		if err := rows.Scan(&m.N, &m.Type, &m.Body); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (t *sqliteTx) InsertMailboxMessage(id model.ID, m *MailboxMessage) error {
	return t.exec(`INSERT INTO enroll_messages (enroll_id, n, type, body) VALUES (?, ?, ?, ?)`,
		id[:], m.N, m.Type, m.Body)
}

func (t *sqliteTx) DeleteExpiredMailboxes(now time.Time) error {
	n := unix(now)
	return errors.Join(
		t.exec(`DELETE FROM enroll_messages WHERE enroll_id IN
			(SELECT enroll_id FROM enrollments WHERE expires_at <= ?)`, n),
		t.exec(`DELETE FROM enrollments WHERE expires_at <= ?`, n),
	)
}

func (t *sqliteTx) DeleteExpired(now time.Time) error {
	n := unix(now)
	return errors.Join(
		t.exec(`DELETE FROM sessions WHERE expires_at <= ?`, n),
		t.exec(`DELETE FROM login_tokens WHERE expires_at <= ?`, n),
		t.exec(`DELETE FROM challenges WHERE expires_at <= ?`, n),
		t.DeleteExpiredMailboxes(now),
	)
}

// --- administration (hop-server accounts, invites, audit) ---

func (t *sqliteTx) AccountSummaries(only *model.ID) ([]*AccountSummary, error) {
	where, args := ``, []any{}
	if only != nil {
		where, args = `WHERE a.account_id = ?`, []any{only[:]}
	}
	rows, err := t.tx.QueryContext(t.ctx, `SELECT a.account_id, a.email, a.vault_id, a.used_bytes, a.quota_bytes, a.reserve, a.created_at,
		coalesce(v.head_seq, 0), coalesce(v.last_bootstrap, -1), coalesce(v.last_checkpoint, -1),
		(SELECT COUNT(*) FROM devices d WHERE d.account_id = a.account_id AND d.active = 1),
		(SELECT COUNT(*) FROM devices d WHERE d.account_id = a.account_id),
		(SELECT MAX(seen_at) FROM device_seen s WHERE s.account_id = a.account_id)
		FROM accounts a LEFT JOIN vaults v ON v.vault_id = a.vault_id `+where+`
		ORDER BY a.created_at, a.email`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccountSummary
	for rows.Next() {
		var a AccountSummary
		var id, vid []byte
		var created int64
		var seen sql.NullInt64
		if err := rows.Scan(&id, &a.Email, &vid, &a.UsedBytes, &a.QuotaBytes, &a.Reserve, &created,
			&a.HeadSeq, &a.LastBootstrap, &a.LastCheckpoint, &a.ActiveDevices, &a.AllDevices, &seen); err != nil {
			return nil, err
		}
		if err := errors.Join(scanID(id, &a.ID), scanID(vid, &a.VaultID)); err != nil {
			return nil, err
		}
		a.CreatedAt = fromUnix(created)
		if seen.Valid {
			a.LastSeen = fromUnix(seen.Int64)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (t *sqliteTx) Devices(accountID model.ID) ([]*Device, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT device_id, sig_pk, active, added_seq FROM devices
		WHERE account_id = ? ORDER BY added_seq, device_id`, accountID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d := Device{AccountID: accountID}
		var id []byte
		if err := rows.Scan(&id, &d.SigPK, &d.Active, &d.AddedSeq); err != nil {
			return nil, err
		}
		if err := scanID(id, &d.DeviceID); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, rows.Err()
}

func (t *sqliteTx) LiveSessions(accountID model.ID, now time.Time) (map[model.ID]int, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT device_id, COUNT(*) FROM sessions
		WHERE account_id = ? AND expires_at > ? GROUP BY device_id`, accountID[:], unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.ID]int{}
	for rows.Next() {
		var b []byte
		var n int
		if err := rows.Scan(&b, &n); err != nil {
			return nil, err
		}
		var id model.ID
		if err := scanID(b, &id); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (t *sqliteTx) CountLoginTokens(accountID model.ID, now time.Time) (int, error) {
	var n int
	err := t.row(`SELECT COUNT(*) FROM login_tokens WHERE account_id = ? AND expires_at > ?`, accountID[:], unix(now)).Scan(&n)
	return n, mapErr(err)
}

func (t *sqliteTx) CountAccountMailboxes(accountID model.ID, now time.Time) (int, error) {
	var n int
	err := t.row(`SELECT COUNT(*) FROM enrollments WHERE account_id = ? AND expires_at > ?`, accountID[:], unix(now)).Scan(&n)
	return n, mapErr(err)
}

func (t *sqliteTx) Registrations(email string) ([]*Registration, error) {
	q := `SELECT cap_hash FROM registrations ORDER BY created_at, cap_hash`
	var args []any
	if email != "" {
		q = `SELECT cap_hash FROM registrations WHERE email = ? ORDER BY created_at, cap_hash`
		args = []any{email}
	}
	rows, err := t.tx.QueryContext(t.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var hashes []crypto.Hash
	for rows.Next() {
		var b []byte
		var h crypto.Hash
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return nil, err
		}
		if err := scanHash(b, &h); err != nil {
			rows.Close()
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	out := make([]*Registration, 0, len(hashes))
	for _, h := range hashes {
		r, err := t.Registration(h)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (t *sqliteTx) ExpireRegistration(capHash crypto.Hash, at time.Time) error {
	res, err := t.tx.ExecContext(t.ctx, `UPDATE registrations SET expires_at = ?
		WHERE cap_hash = ? AND consumed_at IS NULL AND expires_at > ?`, unix(at), capHash[:], unix(at))
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (t *sqliteTx) InsertAudit(e *AuditEntry) error {
	var aid []byte
	if e.AccountID != nil {
		aid = e.AccountID[:]
	}
	res, err := t.tx.ExecContext(t.ctx, `INSERT INTO admin_audit (at, actor, action, account_id, params, result)
		VALUES (?, ?, ?, ?, ?, ?)`, unix(e.At), e.Actor, e.Action, aid, e.Params, e.Result)
	if err != nil {
		return mapErr(err)
	}
	e.ID, err = res.LastInsertId()
	return err
}

func (t *sqliteTx) AuditEntries(f AuditFilter) ([]*AuditEntry, error) {
	q := `SELECT id, at, actor, action, account_id, params, result FROM admin_audit WHERE at >= ?`
	args := []any{unix(f.Since)}
	if f.AccountID != nil {
		q += ` AND account_id = ?`
		args = append(args, f.AccountID[:])
	}
	rows, err := t.tx.QueryContext(t.ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		var aid []byte
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &aid, &e.Params, &e.Result); err != nil {
			return nil, err
		}
		e.At = fromUnix(at)
		if aid != nil {
			e.AccountID = new(model.ID)
			if err := scanID(aid, e.AccountID); err != nil {
				return nil, err
			}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
