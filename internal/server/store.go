package server

import (
	"context"
	"errors"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Store is the server's persistent storage. Every rule lives in the server;
// a Store only reads and writes rows, inside a transaction.
//
// Update runs fn in a write transaction that is serialized with every other
// Update (SQLite's BEGIN IMMEDIATE; SELECT ... FOR UPDATE on the vault head
// for a later Postgres backend). It commits when fn returns nil and rolls
// back otherwise. View runs fn in a read transaction that sees one
// consistent snapshot.
//
// The schema is multi-tenant: every row is keyed by its account or vault,
// and object rows are scoped per vault even when bodies repeat.
type Store interface {
	View(ctx context.Context, fn func(Tx) error) error
	Update(ctx context.Context, fn func(Tx) error) error
	// Backup writes a consistent copy of the database to path, which must
	// not exist.
	Backup(ctx context.Context, path string) error
	Close() error
}

// ErrNotFound is returned by Tx lookups that find no row.
var ErrNotFound = errors.New("server: not found")

// ErrDuplicate is returned by an insert that would violate a uniqueness
// constraint.
var ErrDuplicate = errors.New("server: duplicate")

// Tx is one transaction. Lookups return ErrNotFound when no row matches.
type Tx interface {
	// Meta holds server-wide values such as the prelogin secret.
	Meta(key string) ([]byte, error)
	SetMeta(key string, v []byte) error

	Account(id model.ID) (*Account, error)
	AccountByEmail(email string) (*Account, error)
	// AccountTaken reports whether any account has this ID, email or vault.
	AccountTaken(id model.ID, email string, vaultID model.ID) (bool, error)
	InsertAccount(a *Account) error
	UpdateAccount(a *Account) error

	Vault(id model.ID) (*Vault, error)
	InsertVault(v *Vault) error
	UpdateVault(v *Vault) error

	Entry(vaultID model.ID, seq uint64) (*LogEntry, error)
	EntryByHash(vaultID model.ID, h crypto.Hash) (*LogEntry, error)
	// Entries calls fn for each entry with seq > after (from seq 0 when
	// fromStart), in order, until fn returns false or limit entries were
	// seen.
	Entries(vaultID model.ID, after uint64, fromStart bool, limit int, fn func(*LogEntry) bool) error
	InsertEntry(vaultID model.ID, e *LogEntry) error
	Object(vaultID model.ID, h crypto.Hash) ([]byte, error)
	// InsertObject stores an object for a vault unless the vault already
	// has it.
	InsertObject(vaultID model.ID, h crypto.Hash, body []byte, seq uint64) error

	Device(accountID, deviceID model.ID) (*Device, error)
	// PutDevice inserts a device or updates its active state.
	PutDevice(d *Device) error
	Receipt(accountID, deviceID model.ID) (*Receipt, error)
	InsertReceipt(r *Receipt) error

	Session(tokenHash crypto.Hash) (*Session, error)
	InsertSession(s *Session) error
	// DeleteSessions deletes every session of the account, or only those of
	// one device when deviceID is not nil.
	DeleteSessions(accountID model.ID, deviceID *model.ID) error

	LoginToken(tokenHash crypto.Hash) (*LoginToken, error)
	InsertLoginToken(t *LoginToken) error
	// SetLoginTokenBootstrap records the bootstrap commit a login or
	// recovery token made.
	SetLoginTokenBootstrap(tokenHash crypto.Hash, h vaultlog.Head) error

	Challenge(hash crypto.Hash) (*Challenge, error)
	InsertChallenge(c *Challenge) error
	DeleteChallenge(hash crypto.Hash) error
	// CountChallenges counts unexpired challenges: all of them, a device's
	// (when deviceID is set), or a registration capability's (when capHash
	// is set).
	CountChallenges(now time.Time, scope ChallengeScope) (int, error)

	Registration(capHash crypto.Hash) (*Registration, error)
	InsertRegistration(r *Registration) error
	// ConsumeRegistration marks a capability used and stores its
	// acknowledgment.
	ConsumeRegistration(capHash crypto.Hash, ack *Ack, at time.Time) error

	// DeleteExpired removes sessions, login tokens and challenges that
	// expired before now.
	DeleteExpired(now time.Time) error
}

// Account is one account and the values the server derives from the latest
// creds op of its vault.
type Account struct {
	ID          model.ID
	Email       string // normalized (R4)
	VaultID     model.ID
	KDFVersion  uint32
	Salt        []byte
	AuthSHA256  crypto.Hash
	RAuthSHA256 crypto.Hash
	CredGen     uint32 // creds.gen
	UsedBytes   int64  // R13 accounting
	QuotaBytes  int64  // 0: the server default
	CreatedAt   time.Time
}

// Vault is a vault's head and the public state at that head.
type Vault struct {
	ID          model.ID
	AccountID   model.ID
	Head        vaultlog.Head
	PublicState []byte // vaultlog.PublicState.Marshal
	// The seq of the latest bootstrap and checkpoint (genesis counts as a
	// checkpoint), for the R13 recovery reserve. LastBootstrap is -1 when
	// there was none.
	LastBootstrap  int64
	LastCheckpoint int64
}

// LogEntry is one committed entry. Wire is the canonical wire with only the
// objects the entry names.
type LogEntry struct {
	Seq  uint64
	H    crypto.Hash
	Kind vaultlog.Kind
	Wire []byte
}

// Device is every device an account has ever had, with the verification
// key it was added with. Departed devices stay, inactive, for retirement
// status (R5).
type Device struct {
	AccountID model.ID
	DeviceID  model.ID
	SigPK     []byte
	Active    bool
	AddedSeq  uint64
}

// Receipt is the permanent record of a device leaving the account (§9).
type Receipt struct {
	AccountID model.ID
	DeviceID  model.ID
	How       vaultlog.DepartureKind
	Seq       uint64
	H         crypto.Hash
}

// Session is a device access token (§9), stored by its hash.
type Session struct {
	TokenHash crypto.Hash
	AccountID model.ID
	VaultID   model.ID
	DeviceID  model.ID
	ExpiresAt time.Time
}

// TokenKind distinguishes login and recovery tokens (R6).
type TokenKind string

const (
	TokenLogin    TokenKind = "login"
	TokenRecovery TokenKind = "recovery"
)

// LoginToken is a login or recovery token, stored by its hash. It is bound
// to the credential generation it was issued under.
type LoginToken struct {
	TokenHash crypto.Hash
	Kind      TokenKind
	AccountID model.ID
	VaultID   model.ID
	CredGen   uint32
	ExpiresAt time.Time
	Bootstrap *vaultlog.Head // the bootstrap it committed, if any
}

// ChallengeKind separates device challenges from signup challenges (R3).
type ChallengeKind string

const (
	ChallengeDevice ChallengeKind = "device"
	ChallengeSignup ChallengeKind = "signup"
)

// Challenge is a single-use server challenge, stored by the hash of its
// value, with everything it is bound to.
type Challenge struct {
	Hash      crypto.Hash
	Kind      ChallengeKind
	Origin    string
	AccountID model.ID // device challenges
	DeviceID  model.ID // device challenges
	Operation string   // device: "session" or "retire-status"; signup: "signup"
	Email     string   // signup challenges
	CapHash   crypto.Hash
	ExpiresAt time.Time
}

// ChallengeScope selects the challenges CountChallenges counts.
type ChallengeScope struct {
	AccountID *model.ID
	DeviceID  *model.ID
	CapHash   *crypto.Hash
}

// Registration is a registration capability (an invite) and, once used,
// its publication acknowledgment.
type Registration struct {
	CapHash   crypto.Hash
	Email     string // normalized
	CreatedAt time.Time
	ExpiresAt time.Time
	Ack       *Ack // set when consumed
}

// Ack is a publication acknowledgment (R3): the original upload head and
// the digest of the canonical validated publication.
type Ack struct {
	AccountID model.ID
	VaultID   model.ID
	Digest    crypto.Hash
	Head      vaultlog.Head
}
