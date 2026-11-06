-- The schema of version 2 (hop-server at 22a4cf1), verbatim, for the
-- migration test. Do not edit.

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
