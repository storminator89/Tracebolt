// Package windowsnetworkcontext is the independently consented, caller-visible
// route and raw-counter generation contract. It grants no native access by itself.
package windowsnetworkcontext

import (
	"errors"
	"time"
)

const (
	Scope           = "windows-network-context-v1"
	ConsentVersion  = "tracebolt.windows-network-context-consent.v1"
	ManifestVersion = "tracebolt.windows-network-context-manifest.v1"
	MessageVersion  = "tracebolt.windows-network-context-message.v1"
	ReceiptVersion  = "tracebolt.windows-network-context-receipt.v1"
	PageVersion     = "tracebolt.windows-network-context-page.v1"
	Source          = "ip-helper-routes-and-raw-interface-counters"
	Coverage        = "caller_visible_tables_complete_nonatomic"
	MaxRoutes       = 4096
	MaxInterfaces   = 256
	MaxRows         = MaxRoutes + MaxInterfaces
	MaxSourceBytes  = 2 << 20
	MaxPackBytes    = 3 << 20
	MaxChunkBytes   = 64 << 10
	MaxChunkRows    = 128
	MaxChunks       = 64
	MaxPageBytes    = 256 << 10
	MaxPageRows     = 100
	MaxQueryBytes   = 256
	MaxCursorBytes  = 4096
	MaxSequence     = uint64(1<<53 - 1)
	CaptureTimeout  = 5 * time.Second
	BurstTimeout    = 20 * time.Second
	MaxOperations   = 64
	CaptureInterval = time.Minute
	Retention       = 24 * time.Hour
	CursorLifetime  = 15 * time.Minute
	MaxFieldUTF16   = 256
	MaxFieldBytes   = 1024
	Privacy         = "Read and send caller-visible local IPv4/IPv6 routing table metadata and raw interface counters under the existing LocalService identity, at most once per minute: numeric destination prefixes/scopes and next-hop addresses, capture-time interface indices, route metric/protocol/origin, interface aliases, and exact input/output octet, error and discard counters. Up to 4096 routes and 256 interfaces, 2 MiB canonical rows and a five-second cooperative deadline; a cutoff fails the whole attempt, never promotes a prefix. Windows allocates the native tables and in-flight native calls cannot be hard-canceled. The two source tables are not atomic or joined to one another or retained adapters. Counters may reset and are not rates, since-boot totals or safe to sum across interfaces. Up to 24-hour original capture retention for private authenticated operator search/paging. No MAC addresses, GUIDs, descriptions, packets, probes, DNS resolution, sockets/process joins, remote queries, privileges, modifications, AI or provider export. Requires a new explicit local grant; old inventory, adapter and endpoint grants do not authorize these reads."
	HTTPPrivacy     = "WARNING: HTTP-test sends local route metadata, interface aliases and raw traffic/error/discard counters in plaintext. Network observers can read it. Signatures do not encrypt it or authenticate manager responses. Production requires HTTPS."
)

var (
	ErrInvalid     = errors.New("windows_network_context_invalid")
	ErrConflict    = errors.New("windows_network_context_restart_required")
	ErrExpired     = errors.New("windows_network_context_expired")
	ErrBudget      = errors.New("windows_network_context_resource_limit")
	ErrUnavailable = errors.New("windows_network_context_unavailable")
	ErrState       = errors.New("windows_network_context_state_invalid")
	ErrTransport   = errors.New("windows_network_context_transport")
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

// Row IDs order only this combined capture. Interface indices and aliases are
// source-local snapshot labels, never a cross-table or retained-adapter join.
type Row struct {
	ID             uint32    `json:"id"`
	Kind           string    `json:"kind"`
	InterfaceIndex uint32    `json:"interfaceIndex"`
	Route          *Route    `json:"route,omitempty"`
	Counters       *Counters `json:"counters,omitempty"`
}
type Route struct {
	Destination        string `json:"destination"`
	DestinationScopeID uint32 `json:"destinationScopeId"`
	NextHop            string `json:"nextHop"`
	Metric             uint32 `json:"metric"`
	Protocol           uint32 `json:"protocol"`
	Origin             uint32 `json:"origin"`
}
type Counters struct {
	Alias        *string `json:"alias"`
	AliasQuality string  `json:"aliasQuality"`
	InOctets     string  `json:"inOctets"`
	OutOctets    string  `json:"outOctets"`
	InErrors     string  `json:"inErrors"`
	OutErrors    string  `json:"outErrors"`
	InDiscards   string  `json:"inDiscards"`
	OutDiscards  string  `json:"outDiscards"`
}

type Capture struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Rows       []Row
	// Both source tables must finish without a cutoff to permit Complete.
	// An unavailable alias stays on its identifiable interface row.
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
	Kind   string `json:"kind"`
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
	Kind            string     `json:"kind"`
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
