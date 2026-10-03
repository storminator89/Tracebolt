// Package enrollmentstate models the isolated enrollment-v2 lifecycle in memory.
// It is not durable storage, an authorization API, an issuer, or an enrollment
// endpoint. No production caller is wired to it. The caller must authenticate
// operator commands; cryptographic client proofs are concrete verified values.
//
// Snapshots are immutable copies. Exported JSON is a strict inspection contract,
// not a backup or restore format. A distinct internal trusted-ledger codec is
// reserved for the transactional storage adapter. Retained records, including terminal tombstones,
// have a hard capacity limit and are never silently evicted. Renewal, migration,
// recovery, interrupted credential delivery, filesystem persistence, signer
// reconciliation and network rate limits are deliberately not implemented.
//
// Production integration must atomically persist the issuance intent, resulting
// certificate DER, lifecycle revision, and delivery/replay metadata before any
// credential is returned. Calling this in-memory Engine and then separately
// writing a database is NOT a safe persistence adapter: a crash or concurrent
// revocation between those steps would lose the required atomic authorization.
// A durable transactional implementation and explicit signer reconciliation are
// separate prerequisites. This package is a lifecycle model and crypto-policy
// test boundary, not deployable enrollment.
//
// Every Now argument, including SigningIntent's time, must come from the trusted
// manager clock. The JSON codecs are strict model/test contracts, not permission
// to use client-supplied timestamps as authorization or expiry authority. Any
// future ingress must obtain time on the manager rather than forward client Now.
package enrollmentstate

import (
	"errors"
	"math"
)

const (
	SnapshotVersion   = "tracebolt.enrollment-state.v2"
	TemplateVersion   = "tracebolt.enrollment.client.v2"
	MaxJSONBytes      = 16 << 10
	MaxRevision       = uint64(math.MaxInt64)
	MaxInvitationTTL  = int64(10 * 60)
	MaxPendingTTL     = int64(30 * 60)
	MaxCertificateTTL = int64(30 * 24 * 60 * 60)
	MaxRecords        = 1000
	MaxInvitations    = 100
	MaxPending        = 100
	// Keep arithmetic and timestamps in a finite, interoperable date domain.
	MaxTimestamp = int64(253402300799)
)

var (
	ErrInvalid        = errors.New("enrollment contract is invalid")
	ErrNotFound       = errors.New("enrollment record does not exist")
	ErrConflict       = errors.New("enrollment revision or idempotency conflict")
	ErrState          = errors.New("enrollment operation is not valid in this state")
	ErrExpired        = errors.New("enrollment authorization has expired")
	ErrCapacity       = errors.New("enrollment capacity is exhausted")
	ErrProof          = errors.New("enrollment proof does not match")
	ErrNotImplemented = errors.New("enrollment operation is not implemented")
)

type State string

const (
	Created        State = "created"
	ClaimedPending State = "claimed_pending"
	Approved       State = "approved"
	IssuanceIntent State = "issuance_intent"
	Issued         State = "issued"
	Activated      State = "activated"
	Expired        State = "expired"
	Canceled       State = "canceled"
	Rejected       State = "rejected"
	Revoked        State = "revoked"
)

// Binding is fixed for the Engine lifetime. CollectionProfile is an opaque
// reviewed profile identifier, not permission to collect or expand any fields.
type Binding struct {
	InstanceID        string `json:"instanceID"`
	Origin            string `json:"origin"`
	Profile           string `json:"profile"`
	CollectionProfile string `json:"collectionProfile"`
	IssuerFingerprint string `json:"issuerFingerprint"`
}

type Config struct {
	Binding         Binding
	InvitationTTL   int64
	PendingTTL      int64
	RecordLimit     int
	InvitationLimit int
	PendingLimit    int
}

type ClaimBinding struct {
	ClaimID        string `json:"claimID"`
	RequestID      string `json:"requestID"`
	KeyFingerprint string `json:"keyFingerprint"`
	CSRHash        string `json:"csrHash"`
	ClaimHash      string `json:"claimHash"`
	ComparisonCode string `json:"comparisonCode"`
	At             int64  `json:"at"`
}

type Approval struct {
	RequestID      string `json:"requestID"`
	DeviceID       string `json:"deviceID"`
	KeyFingerprint string `json:"keyFingerprint"`
	At             int64  `json:"at"`
}

// Intent fixes all issuance authority before any external signer is invoked.
// The in-memory Engine cannot establish durability or signer reconciliation.
type Intent struct {
	IntentID        string `json:"intentID"`
	RequestID       string `json:"requestID"`
	SerialHex       string `json:"serialHex"`
	TemplateVersion string `json:"templateVersion"`
	DeviceID        string `json:"deviceID"`
	KeyFingerprint  string `json:"keyFingerprint"`
	NotBefore       int64  `json:"notBefore"`
	NotAfter        int64  `json:"notAfter"`
	At              int64  `json:"at"`
}

type Issuance struct {
	RequestID       string `json:"requestID"`
	CertificateHash string `json:"certificateHash"`
	At              int64  `json:"at"`
}

type Activation struct {
	RequestID string `json:"requestID"`
	At        int64  `json:"at"`
}

type Termination struct {
	RequestID string `json:"requestID"`
	From      State  `json:"from"`
	At        int64  `json:"at"`
}

// Snapshot contains only values and public metadata; it has no secret, verifier,
// certificate bytes, CSR bytes, pointers, maps or slices shared with the Engine.
type Snapshot struct {
	Version         string       `json:"version"`
	Binding         Binding      `json:"binding"`
	InvitationID    string       `json:"invitationID"`
	CreateRequestID string       `json:"createRequestID"`
	Platform        string       `json:"platform"`
	Revision        uint64       `json:"revision"`
	State           State        `json:"state"`
	CreatedAt       int64        `json:"createdAt"`
	DeadlineAt      int64        `json:"deadlineAt"`
	UpdatedAt       int64        `json:"updatedAt"`
	Claim           ClaimBinding `json:"claim"`
	Approval        Approval     `json:"approval"`
	Intent          Intent       `json:"intent"`
	Issuance        Issuance     `json:"issuance"`
	Activation      Activation   `json:"activation"`
	Termination     Termination  `json:"termination"`
}

type CreateCommand struct {
	InvitationID   string `json:"invitationID"`
	RequestID      string `json:"requestID"`
	InvitationHash string `json:"invitationHash"`
	// Platform is a Go GOOS request token: linux, windows, or darwin. A future
	// UI adapter must explicitly map its macos label to darwin. This declared
	// token does not establish installer availability or verified endpoint OS.
	Platform string `json:"platform"`
	// Now is trusted manager-clock UTC Unix time, never client time authority.
	Now int64 `json:"now"`
}

// Control supplies a per-record compare-and-swap revision. A successful exact
// retry in its original resulting phase ignores the stale revision. It never
// returns a stale authorization after the record advances or terminates.
type Control struct {
	InvitationID     string `json:"invitationID"`
	RequestID        string `json:"requestID"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	// Now is trusted manager-clock UTC Unix time, never client time authority.
	Now int64 `json:"now"`
}

type ClaimCommand struct {
	Control Control `json:"control"`
	ClaimID string  `json:"claimID"`
}

type ApproveCommand struct {
	Control        Control `json:"control"`
	DeviceID       string  `json:"deviceID"`
	KeyFingerprint string  `json:"keyFingerprint"`
}

type IntentCommand struct {
	Control         Control `json:"control"`
	IntentID        string  `json:"intentID"`
	SerialHex       string  `json:"serialHex"`
	TemplateVersion string  `json:"templateVersion"`
	NotBefore       int64   `json:"notBefore"`
	NotAfter        int64   `json:"notAfter"`
}

type TerminalCommand struct {
	Control Control `json:"control"`
	State   State   `json:"state"`
}
