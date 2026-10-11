// Package windowsfullservices is the independently consented, caller-visible
// Win32 service generation contract. It grants no native access by itself.
package windowsfullservices

import (
	"errors"
	"time"
)

const (
	Scope           = "windows-complete-services-v1"
	ConsentVersion  = "tracebolt.windows-complete-services-consent.v1"
	ManifestVersion = "tracebolt.windows-complete-services-manifest.v1"
	MessageVersion  = "tracebolt.windows-complete-services-message.v1"
	ReceiptVersion  = "tracebolt.windows-complete-services-receipt.v1"
	PageVersion     = "tracebolt.windows-full-services-page.v1"
	Source          = "scm-enum-services-status-ex-win32"
	Coverage        = "caller_visible_api_complete"
	MaxRows         = 8192
	MaxSourceBytes  = 8 << 20
	MaxPackBytes    = 12 << 20
	MaxChunkBytes   = 64 << 10
	MaxChunkRows    = 128
	MaxChunks       = 256
	MaxPageBytes    = 256 << 10
	MaxPageRows     = 100
	MaxQueryBytes   = 256
	MaxCursorBytes  = 4096
	MaxSequence     = uint64(1<<53 - 1)
	CaptureTimeout  = 15 * time.Second
	BurstTimeout    = 20 * time.Second
	MaxOperations   = 64
	CaptureInterval = time.Minute
	Retention       = 24 * time.Hour
	CursorLifetime  = 15 * time.Minute
	Privacy         = "Read and send all caller-visible Win32 service names, display names, current states and process IDs through resumed EnumServicesStatusEx under the existing LocalService identity, at most once per minute. Drivers are excluded. SCM may silently omit services whose status this identity cannot read; successful enumeration is not whole-machine coverage or an atomic snapshot. Up to 8192 rows and 8 MiB of canonical rows, 256 API pages / 64 MiB native-buffer work and a 15-second cooperative deadline; exhausted limits fail the attempt, never promote a truncated prefix. Original captured generations are retained for up to 24 hours for authenticated operator-only search and paging. No executable paths, accounts, configuration, security descriptors, service controls, elevation, user profiles, AI or provider export. A new explicit local grant is required; old observation grants do not authorize this scope."
	HTTPPrivacy     = "WARNING: HTTP-test sends complete caller-visible Win32 service metadata in plaintext. Network observers can read it. Signatures do not encrypt it or authenticate manager responses. Production requires HTTPS."
)

var (
	ErrInvalid     = errors.New("windows_full_services_invalid")
	ErrConflict    = errors.New("windows_full_services_restart_required")
	ErrExpired     = errors.New("windows_full_services_expired")
	ErrBudget      = errors.New("windows_full_services_resource_limit")
	ErrUnavailable = errors.New("windows_full_services_unavailable")
	ErrState       = errors.New("windows_full_services_state_invalid")
	ErrTransport   = errors.New("windows_full_services_transport")
)

// Consent revisions order local enable/disable/reenable separately from capture
// sequences. Disabling retains the grant and all sequence floors. Reenabling
// creates a new grant/revision; no dormant generation acquires a new lifetime.
type Consent struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	SenderBinding string    `json:"senderBinding"`
	GrantID       string    `json:"grantId"`
	Revision      uint64    `json:"revision"`
	Enabled       bool      `json:"enabled"`
	ChangedAt     time.Time `json:"changedAt"`
}

type Row struct {
	Name               string  `json:"name"`
	DisplayName        *string `json:"displayName"`
	DisplayNameQuality string  `json:"displayNameQuality"`
	State              *string `json:"state"`
	StateQuality       string  `json:"stateQuality"`
	PID                *uint32 `json:"pid"`
	PIDQuality         string  `json:"pidQuality"`
}

type Capture struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Rows       []Row
	// Only an exhausted API enumeration permits Complete. Field unavailability
	// does not remove identifiable rows or imply a failed whole enumeration.
	Complete bool
	Reason   string
}

type Manifest struct {
	SchemaVersion     string    `json:"schemaVersion"`
	Scope             string    `json:"scope"`
	Source            string    `json:"source"`
	Coverage          string    `json:"coverage"`
	DeviceID          string    `json:"deviceId"`
	SenderBinding     string    `json:"senderBinding"`
	GrantID           string    `json:"grantId"`
	GrantRevision     uint64    `json:"grantRevision"`
	Sequence          uint64    `json:"sequence"`
	GenerationID      string    `json:"generationId"`
	CaptureStartedAt  time.Time `json:"captureStartedAt"`
	CaptureFinishedAt time.Time `json:"captureFinishedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	RowCount          int       `json:"rowCount"`
	RowsBytes         int       `json:"rowsBytes"`
	RowsSHA256        string    `json:"rowsSha256"`
	ChunkCount        int       `json:"chunkCount"`
}

type Message struct {
	SchemaVersion  string     `json:"schemaVersion"`
	Operation      string     `json:"operation"`
	DeviceID       string     `json:"deviceId"`
	Consent        Consent    `json:"consent"`
	Sequence       uint64     `json:"sequence"`
	Manifest       *Manifest  `json:"manifest,omitempty"`
	ManifestSHA256 string     `json:"manifestSha256,omitempty"`
	Index          int        `json:"index"`
	Offset         int        `json:"offset"`
	Rows           []Row      `json:"rows,omitempty"`
	AttemptedAt    *time.Time `json:"attemptedAt,omitempty"`
	Reason         string     `json:"reason,omitempty"`
}

type Receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	Operation     string    `json:"operation"`
	DeviceID      string    `json:"deviceId"`
	GrantID       string    `json:"grantId"`
	GrantRevision uint64    `json:"grantRevision"`
	Sequence      uint64    `json:"sequence"`
	RequestSHA256 string    `json:"requestSha256"`
	Index         int       `json:"index"`
	Status        string    `json:"status"`
	ReceivedAt    time.Time `json:"receivedAt"`
}

// Query is sent in a protected read-only POST body, never a URL or access log.
type Query struct {
	Search string `json:"search"`
	Sort   string `json:"sort"`
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`
}

type Complete struct {
	Manifest       Manifest  `json:"manifest"`
	ManifestSHA256 string    `json:"manifestSha256"`
	ReceivedAt     time.Time `json:"receivedAt"`
}
type Attempt struct {
	Sequence    uint64    `json:"sequence"`
	AttemptedAt time.Time `json:"attemptedAt"`
	Status      string    `json:"status"` // pending, complete, source_failed, expired
	Reason      string    `json:"reason"` // empty except a finite failed-capture reason
}

type Page struct {
	SchemaVersion   string     `json:"schemaVersion"`
	DeviceID        string     `json:"deviceId"`
	ServerNow       time.Time  `json:"serverNow"`
	Status          string     `json:"status"` // not_configured, disabled, awaiting, ready, unavailable
	AuthorityUntil  *time.Time `json:"authorityUntil"`
	GrantID         *string    `json:"grantId"`
	GrantRevision   *uint64    `json:"grantRevision"`
	Complete        *Complete  `json:"complete"`
	LatestAttempt   *Attempt   `json:"latestAttempt"`
	Search          string     `json:"search"`
	Sort            string     `json:"sort"`
	Limit           int        `json:"limit"`
	Offset          int        `json:"offset"` // offset in the matching sorted set
	MatchingCount   int        `json:"matchingCount"`
	Rows            []Row      `json:"rows"`
	NextCursor      string     `json:"nextCursor"`
	CursorExpiresAt *time.Time `json:"cursorExpiresAt"`
}
