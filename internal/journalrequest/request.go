// Package journalrequest defines bounded journal-query lifecycle metadata.
// It contains no log content, source execution, transport, or local consent.
package journalrequest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalview"
)

const (
	SchemaVersion   = "tracebolt.journal-request.v1"
	SchemaVersionV2 = "tracebolt.journal-request.v2"
	Lifetime        = 15 * time.Minute
	MaxRecordBytes  = 4 << 10
	Pending         = "pending"
	Claimed         = "claimed"
	Accepted        = "accepted"
	Canceled        = "canceled"
	Expired         = "expired"
)

var (
	ErrInvalid  = errors.New("journal_request_invalid")
	ErrNotReady = errors.New("journal_request_not_ready")
	ErrNotFound = errors.New("journal_request_not_found")
	ErrConflict = errors.New("journal_request_conflict")
	ErrConsumed = errors.New("journal_request_consumed")
	ErrExpired  = errors.New("journal_request_expired")
	ErrCanceled = errors.New("journal_request_canceled")
)

// Budgets are fixed v1 reader limits, included in the query digest. A future
// change requires a new schema rather than silently widening an old request.
type Budgets struct {
	MaxRows          int   `json:"maxRows"`
	MaxSnapshotBytes int   `json:"maxSnapshotBytes"`
	MaxMessageBytes  int   `json:"maxMessageBytes"`
	MaxRawBytes      int   `json:"maxRawBytes"`
	MaxLineBytes     int   `json:"maxLineBytes"`
	MaxScannedRows   int   `json:"maxScannedRows"`
	TimeoutMS        int64 `json:"timeoutMs"`
}

func FixedBudgets() Budgets {
	return Budgets{journalview.MaxRows, journalview.MaxSnapshotBytes, journalview.MaxMessageBytes, journalview.MaxRawBytes, journalview.MaxLineBytes, journalview.MaxScannedRows, int64(journalview.CommandTimeout / time.Millisecond)}
}

type Identity struct {
	ID          string `json:"id"`
	Sequence    uint64 `json:"sequence,string"`
	QueryDigest string `json:"queryDigest"`
}

// Description is unclaimed work metadata, never collection permission.
type Description struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	Identity         Identity                `json:"identity"`
	DeviceID         string                  `json:"deviceId"`
	CertificateHash  string                  `json:"certificateHash"`
	Query            journalview.Query       `json:"query"`
	Budgets          Budgets                 `json:"budgets"`
	CreatedAt        time.Time               `json:"createdAt"`
	ExpiresAt        time.Time               `json:"expiresAt"`
	PolicyGeneration journalgeneration.Tuple `json:"policyGeneration,omitzero"`
}
type Claim struct {
	Identity     Identity `json:"identity"`
	PolicyDigest string   `json:"policyDigest"`
}

// Grant may be returned only after the consumed transition commits. A client
// must additionally persist its own durable consumed marker before invoking a
// source helper. A lost response is not permission to claim or collect again.
type Grant struct {
	Description  Description `json:"description"`
	PolicyDigest string      `json:"policyDigest"`
	ClaimedAt    time.Time   `json:"claimedAt"`
}

// Result supplies only the digest of a separately validated bounded snapshot.
// Its source rows and message bytes can never enter this authority record.
type Result struct {
	Claim        Claim  `json:"claim"`
	ResultDigest string `json:"resultDigest"`
}
type Receipt struct {
	Identity     Identity  `json:"identity"`
	PolicyDigest string    `json:"policyDigest"`
	ResultDigest string    `json:"resultDigest"`
	AcceptedAt   time.Time `json:"acceptedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Record retains its sequence forever, including after expiry/cancellation.
// The latest record itself is the durable per-device monotonic sequence floor.
type Record struct {
	Description  Description `json:"description"`
	State        string      `json:"state"`
	PolicyDigest string      `json:"policyDigest"`
	ClaimedAt    *time.Time  `json:"claimedAt"`
	Receipt      *Receipt    `json:"receipt"`
	CanceledAt   *time.Time  `json:"canceledAt"`
	ExpiredAt    *time.Time  `json:"expiredAt,omitempty"`
}

// Status is lifecycle metadata. Accepted never implies content availability.
// This seam has no content cache: ContentStatus remains unavailable, including
// after a restart; it never invents an empty result or recollection permission.
type Status struct {
	Description   Description `json:"description"`
	State         string      `json:"state"`
	ContentStatus string      `json:"contentStatus"`
	Receipt       *Receipt    `json:"receipt"`
}

func ValidDigest(d string) bool {
	return strings.HasPrefix(d, "sha256:") && enrollmentcrypto.ValidHash(strings.TrimPrefix(d, "sha256:"))
}
func validTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999
}
func QueryDigest(q journalview.Query, now time.Time) (string, error) {
	if journalview.ValidateQuery(q, now) != nil {
		return "", ErrInvalid
	}
	b, err := json.Marshal(struct {
		Domain  string            `json:"domain"`
		Query   journalview.Query `json:"query"`
		Budgets Budgets           `json:"budgets"`
	}{SchemaVersion, q, FixedBudgets()})
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// QueryDigestWithGeneration uses a distinct domain and commits every tuple
// field alongside the exact unchanged service query and fixed reader budgets.
func QueryDigestWithGeneration(q journalview.Query, generation journalgeneration.Tuple, now time.Time) (string, error) {
	if journalgeneration.Validate(generation) != nil || journalview.ValidateQuery(q, now) != nil {
		return "", ErrInvalid
	}
	b, err := json.Marshal(struct {
		Domain           string                  `json:"domain"`
		Query            journalview.Query       `json:"query"`
		Budgets          Budgets                 `json:"budgets"`
		PolicyGeneration journalgeneration.Tuple `json:"policyGeneration"`
	}{SchemaVersionV2, q, FixedBudgets(), generation})
	if err != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func New(device, leaf string, sequence uint64, q journalview.Query, now time.Time) (Record, error) {
	return newRecord(device, leaf, sequence, q, journalgeneration.Tuple{}, now)
}

func NewWithGeneration(device, leaf string, sequence uint64, q journalview.Query, generation journalgeneration.Tuple, now time.Time) (Record, error) {
	if journalgeneration.Validate(generation) != nil {
		return Record{}, ErrInvalid
	}
	return newRecord(device, leaf, sequence, q, generation, now)
}

func newRecord(device, leaf string, sequence uint64, q journalview.Query, generation journalgeneration.Tuple, now time.Time) (Record, error) {
	if !validTime(now) || now.Add(Lifetime).Year() > 9999 || !enrollmentcrypto.ValidID(device, "agent_") || !enrollmentcrypto.ValidHash(leaf) || sequence == 0 {
		return Record{}, ErrInvalid
	}
	digest, err := QueryDigest(q, now)
	version := SchemaVersion
	if generation != (journalgeneration.Tuple{}) {
		version = SchemaVersionV2
		digest, err = QueryDigestWithGeneration(q, generation, now)
	}
	if err != nil {
		return Record{}, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Record{}, ErrInvalid
	}
	d := Description{SchemaVersion: version, Identity: Identity{"journal_" + hex.EncodeToString(random[:]), sequence, digest}, DeviceID: device, CertificateHash: leaf, Query: q, Budgets: FixedBudgets(), CreatedAt: now, ExpiresAt: now.Add(Lifetime), PolicyGeneration: generation}
	return Record{Description: d, State: Pending}, nil
}
func Validate(r Record) error {
	d := r.Description
	digest, err := QueryDigest(d.Query, d.CreatedAt)
	switch d.SchemaVersion {
	case SchemaVersion:
		if d.PolicyGeneration != (journalgeneration.Tuple{}) {
			return ErrInvalid
		}
	case SchemaVersionV2:
		digest, err = QueryDigestWithGeneration(d.Query, d.PolicyGeneration, d.CreatedAt)
	default:
		return ErrInvalid
	}
	if err != nil || !validTime(d.CreatedAt) || !validTime(d.ExpiresAt) || !enrollmentcrypto.ValidID(d.Identity.ID, "journal_") || d.Identity.Sequence == 0 || digest != d.Identity.QueryDigest || !enrollmentcrypto.ValidID(d.DeviceID, "agent_") || !enrollmentcrypto.ValidHash(d.CertificateHash) || d.Budgets != FixedBudgets() || !d.ExpiresAt.Equal(d.CreatedAt.Add(Lifetime)) {
		return ErrInvalid
	}
	if r.ClaimedAt != nil && d.SchemaVersion == SchemaVersionV2 && r.PolicyDigest != d.PolicyGeneration.PolicyDigest {
		return ErrInvalid
	}
	if r.ClaimedAt != nil && (!validTime(*r.ClaimedAt) || r.ClaimedAt.Before(d.CreatedAt) || !r.ClaimedAt.Before(d.ExpiresAt) || !ValidDigest(r.PolicyDigest)) {
		return ErrInvalid
	}
	if r.ClaimedAt == nil && r.PolicyDigest != "" {
		return ErrInvalid
	}
	if r.Receipt != nil {
		p := r.Receipt
		if r.ClaimedAt == nil || p.Identity != d.Identity || p.PolicyDigest != r.PolicyDigest || !ValidDigest(p.ResultDigest) || !validTime(p.AcceptedAt) || p.AcceptedAt.Before(*r.ClaimedAt) || !p.AcceptedAt.Before(d.ExpiresAt) || !p.ExpiresAt.Equal(d.ExpiresAt) {
			return ErrInvalid
		}
	}
	if r.CanceledAt != nil && (!validTime(*r.CanceledAt) || r.CanceledAt.Before(d.CreatedAt) || !r.CanceledAt.Before(d.ExpiresAt) || r.ClaimedAt != nil && r.CanceledAt.Before(*r.ClaimedAt) || r.Receipt != nil && r.CanceledAt.Before(r.Receipt.AcceptedAt)) {
		return ErrInvalid
	}
	if r.ExpiredAt != nil && (!validTime(*r.ExpiredAt) || r.ExpiredAt.Before(d.ExpiresAt) || r.State != Expired) {
		return ErrInvalid
	}
	switch r.State {
	case Pending:
		if r.ClaimedAt != nil || r.Receipt != nil || r.CanceledAt != nil {
			return ErrInvalid
		}
	case Claimed:
		if r.ClaimedAt == nil || r.Receipt != nil || r.CanceledAt != nil {
			return ErrInvalid
		}
	case Accepted:
		if r.ClaimedAt == nil || r.Receipt == nil || r.CanceledAt != nil {
			return ErrInvalid
		}
	case Canceled:
		if r.CanceledAt == nil {
			return ErrInvalid
		}
	case Expired:
		if r.ExpiredAt == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxRecordBytes {
		return ErrInvalid
	}
	return nil
}
func LastEvent(r Record) time.Time {
	if r.ExpiredAt != nil {
		return *r.ExpiredAt
	}
	if r.CanceledAt != nil {
		return *r.CanceledAt
	}
	if r.Receipt != nil {
		return r.Receipt.AcceptedAt
	}
	if r.ClaimedAt != nil {
		return *r.ClaimedAt
	}
	return r.Description.CreatedAt
}
func CheckTime(r Record, now time.Time) error {
	if r.State == Expired {
		return ErrExpired
	}
	if !validTime(now) || now.Before(LastEvent(r)) {
		return ErrInvalid
	}
	if !now.Before(r.Description.ExpiresAt) {
		return ErrExpired
	}
	if r.State == Canceled {
		return ErrCanceled
	}
	return nil
}
