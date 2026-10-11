// Package windowsusersoftware defines separately consented foreground selected-account
// software generations. It grants no native access or machine-software authority.
package windowsusersoftware

import (
	"errors"
	"time"
)

const (
	Scope           = "windows-selected-user-software-v1"
	ConsentVersion  = "tracebolt.windows-selected-user-software-consent.v1"
	ManifestVersion = "tracebolt.windows-selected-user-software-manifest.v1"
	MessageVersion  = "tracebolt.windows-selected-user-software-message.v1"
	ReceiptVersion  = "tracebolt.windows-selected-user-software-receipt.v1"
	PageVersion     = "tracebolt.windows-selected-user-software-page.v1"
	Source          = "selected-account-hkcu-msix"
	Coverage        = "selected_account_complete"
	PartialCoverage = "selected_account_partial"
	MaxRows         = 4096
	MaxSourceBytes  = 4 << 20
	MaxPackBytes    = 6 << 20
	MaxChunkBytes   = 64 << 10
	MaxChunkRows    = 128
	MaxChunks       = 128
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
	MaxFieldUTF16   = 512
	MaxFieldBytes   = 2048
	Privacy         = "Accept one explicitly approved foreground capture for the verified normal-user account on this device. Read that account's HKCU uninstall registrations and current-user MSIX registrations in that user's own foreground process, without elevation, profile loading or other-user enumeration. The service briefly obtains an identification-only pipe token, verifies revert before any work, and never reads sources as the user. The agent binds an opaque account context and label to the OS-verified local peer; account SID is never sent to the manager. At most 4096 rows, 4 MiB canonical rows and 15 seconds. Failed sources expose no prefixes; complete-source rows may be shown with explicit partial coverage. Original retention is 24 hours for authenticated operator-only paging. No installation paths, uninstall commands, licenses, credentials, history comparison, software actions, AI or provider export. Service acceptance is default off and does not authorize an automatic capture. Each foreground capture needs separate local consent."
	HTTPPrivacy     = "WARNING: HTTP-test sends selected-account software names, versions, publishers and account context in plaintext. Network observers can read it. Signatures do not encrypt it or authenticate manager responses. Production requires HTTPS."
)

var (
	ErrInvalid     = errors.New("windows_user_software_invalid")
	ErrConflict    = errors.New("windows_user_software_restart_required")
	ErrExpired     = errors.New("windows_user_software_expired")
	ErrBudget      = errors.New("windows_user_software_resource_limit")
	ErrUnavailable = errors.New("windows_user_software_unavailable")
	ErrState       = errors.New("windows_user_software_state_invalid")
	ErrUnsupported = errors.New("windows_user_software_unsupported")
	ErrDenied      = errors.New("windows_user_software_access_denied")
	ErrTransport   = errors.New("windows_user_software_transport")
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
	RegistrationID   string  `json:"registrationId"`
	Source           string  `json:"source"`
	Name             *string `json:"name"`
	NameQuality      string  `json:"nameQuality"`
	Version          *string `json:"version"`
	VersionQuality   string  `json:"versionQuality"`
	Publisher        *string `json:"publisher"`
	PublisherQuality string  `json:"publisherQuality"`
}

type Capture struct {
	AccountContextID string
	AccountLabel     string
	CaptureNonce     string
	HKCUStatus       string
	MSIXStatus       string
	StartedAt        time.Time
	FinishedAt       time.Time
	Rows             []Row
	// Complete means a bounded submitted capture, not complete coverage. Each
	// source status controls coverage; failed-source prefixes are forbidden.
	Complete bool
	Reason   string
}

type Manifest struct {
	AccountContextID  string    `json:"accountContextId"`
	AccountLabel      string    `json:"accountLabel"`
	CaptureNonce      string    `json:"captureNonce"`
	HKCUStatus        string    `json:"hkcuStatus"`
	MSIXStatus        string    `json:"msixStatus"`
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
	AccountContextID string     `json:"accountContextId,omitempty"`
	AccountLabel     string     `json:"accountLabel,omitempty"`
	CaptureNonce     string     `json:"captureNonce,omitempty"`
	SchemaVersion    string     `json:"schemaVersion"`
	Operation        string     `json:"operation"`
	DeviceID         string     `json:"deviceId"`
	Consent          Consent    `json:"consent"`
	Sequence         uint64     `json:"sequence"`
	Manifest         *Manifest  `json:"manifest,omitempty"`
	ManifestSHA256   string     `json:"manifestSha256,omitempty"`
	Index            int        `json:"index"`
	Offset           int        `json:"offset"`
	Rows             []Row      `json:"rows,omitempty"`
	AttemptedAt      *time.Time `json:"attemptedAt,omitempty"`
	Reason           string     `json:"reason,omitempty"`
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
	AccountContextID string `json:"accountContextId"`
	Source           string `json:"source"`
	Search           string `json:"search"`
	Sort             string `json:"sort"`
	Limit            int    `json:"limit"`
	Cursor           string `json:"cursor"`
}

type Complete struct {
	Manifest       Manifest  `json:"manifest"`
	ManifestSHA256 string    `json:"manifestSha256"`
	ReceivedAt     time.Time `json:"receivedAt"`
}
type Attempt struct {
	AccountContextID string    `json:"accountContextId"`
	AccountLabel     string    `json:"accountLabel"`
	CaptureNonce     string    `json:"captureNonce"`
	Sequence         uint64    `json:"sequence"`
	AttemptedAt      time.Time `json:"attemptedAt"`
	Status           string    `json:"status"` // pending, complete, source_failed, expired
	Reason           string    `json:"reason"` // empty except a finite failed-capture reason
}

type Page struct {
	AccountContextID string     `json:"accountContextId"`
	Source           string     `json:"source"`
	SchemaVersion    string     `json:"schemaVersion"`
	DeviceID         string     `json:"deviceId"`
	ServerNow        time.Time  `json:"serverNow"`
	Status           string     `json:"status"` // not_configured, disabled, awaiting, ready, unavailable
	AuthorityUntil   *time.Time `json:"authorityUntil"`
	GrantID          *string    `json:"grantId"`
	GrantRevision    *uint64    `json:"grantRevision"`
	Complete         *Complete  `json:"complete"`
	LatestAttempt    *Attempt   `json:"latestAttempt"`
	Search           string     `json:"search"`
	Sort             string     `json:"sort"`
	Limit            int        `json:"limit"`
	Offset           int        `json:"offset"` // offset in the matching sorted set
	MatchingCount    int        `json:"matchingCount"`
	Rows             []Row      `json:"rows"`
	NextCursor       string     `json:"nextCursor"`
	CursorExpiresAt  *time.Time `json:"cursorExpiresAt"`
}
