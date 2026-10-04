// Package offlinecatalog holds a single bounded, operator-uploaded normalized
// Debian catalog in memory. Parsing validates interchange shape and release, not
// vendor authorship, freshness, applicability, or an endpoint's CVE status.
package offlinecatalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"localrmm/internal/assessment"
)

const (
	SchemaVersion = "tracebolt.offline-catalog.v1"
	MaxBytes      = assessment.MaxSnapshotBytes
	MaxRules      = assessment.MaxSnapshotRules
	MaxInFlight   = 1 // Request/body admission is the API owner's responsibility.
)

var (
	ErrInvalid            = errors.New("invalid_catalog")
	ErrUnsupportedRelease = errors.New("unsupported_catalog_release")
	ErrTooLarge           = errors.New("catalog_too_large")
	ErrChanged            = errors.New("catalog_changed")
	ErrUnavailable        = errors.New("catalog_unavailable")
)

// Metadata contains only server-derived identity and validated format/count
// facts. Provider is the interchange provider label, never authenticated origin.
type Metadata struct {
	ID                 string     `json:"id"`
	SHA256             string     `json:"sha256"`
	Format             string     `json:"format"`
	Provider           string     `json:"provider"`
	DeclaredRelease    string     `json:"declaredRelease"`
	ImportedAt         time.Time  `json:"importedAt"`
	PublishedAt        *time.Time `json:"publishedAt"`
	Freshness          string     `json:"freshness"`
	OriginAssurance    string     `json:"originAssurance"`
	Synthetic          bool       `json:"synthetic"`
	ByteCount          int        `json:"byteCount"`
	RuleCount          int        `json:"ruleCount"`
	CoveredSourceCount int        `json:"coveredSourceCount"`
}

type Limits struct {
	MaxBytes    int `json:"maxBytes"`
	MaxRules    int `json:"maxRules"`
	MaxInFlight int `json:"maxInFlight"`
}

type View struct {
	SchemaVersion   string    `json:"schemaVersion"`
	Enabled         bool      `json:"enabled"`
	ServerNow       time.Time `json:"serverNow"`
	Revision        string    `json:"revision"`
	Storage         string    `json:"storage"`
	ResetsOnRestart bool      `json:"resetsOnRestart"`
	Catalog         *Metadata `json:"catalog"`
	Limits          Limits    `json:"limits"`
}

// Candidate is opaque and immutable after Parse. Its zero value is invalid.
// Value copies share immutable data; neither raw bytes nor rules are exported.
type Candidate struct{ data *candidateData }

type candidateData struct {
	document normalizedDocument
	metadata Metadata
}

// Store value copies share one state and mutex. Construct with New; nil and
// zero-value stores are unavailable. No state is persisted across a restart.
type Store struct{ state *storeState }

type storeState struct {
	mu       sync.RWMutex
	revision string
	catalog  *candidateData
}

func New() *Store {
	return &Store{state: &storeState{revision: newID("revision_")}}
}

// String/Format and JSON serialization never reveal retained imported content,
// for either pointer or value diagnostics (including fmt's %#v and %+v).
func (Candidate) String() string               { return "offlinecatalog.Candidate{opaque}" }
func (c Candidate) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }
func (Candidate) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
func (Store) String() string                   { return "offlinecatalog.Store{opaque}" }
func (s Store) Format(f fmt.State, _ rune)     { _, _ = io.WriteString(f, s.String()) }
func (Store) MarshalJSON() ([]byte, error)     { return []byte("null"), nil }

func DisabledView(now time.Time) View { return baseView(now, false) }

func baseView(now time.Time, enabled bool) View {
	return View{
		SchemaVersion: SchemaVersion, Enabled: enabled, ServerNow: now.UTC(),
		Storage: "memory-only", ResetsOnRestart: true,
		Limits: Limits{MaxBytes: MaxBytes, MaxRules: MaxRules, MaxInFlight: MaxInFlight},
	}
}

func (s *Store) View(now time.Time) View {
	if s == nil || s.state == nil {
		return DisabledView(now)
	}
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	return s.state.view(now)
}

func (s *storeState) view(now time.Time) View {
	view := baseView(now, true)
	view.Revision = s.revision
	if s.catalog != nil {
		metadata := s.catalog.metadata
		view.Catalog = &metadata
	}
	return view
}

// Replace atomically promotes a parsed candidate only if the caller's revision
// still matches. Failed/canceled operations preserve the prior catalog. The
// import timestamp is the supplied server commit time, not a publication time.
func (s *Store) Replace(ctx context.Context, expectedRevision string, candidate Candidate, now time.Time) (View, error) {
	if s == nil || s.state == nil {
		return View{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	if candidate.data == nil {
		return View{}, ErrInvalid
	}
	revision := newID("revision_")
	// Only metadata is copied: the private document is already immutable and
	// cannot be accessed by Candidate or Store consumers.
	promoted := *candidate.data
	promoted.metadata.ImportedAt = now.UTC()
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	if expectedRevision == "" || expectedRevision != s.state.revision {
		return View{}, ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	s.state.catalog, s.state.revision = &promoted, revision
	return s.state.view(now), nil
}

// Clear is also a compare-and-swap, including when the catalog is already empty.
// A fresh revision invalidates other in-flight edits after every successful clear.
func (s *Store) Clear(ctx context.Context, expectedRevision string, now time.Time) (View, error) {
	if s == nil || s.state == nil {
		return View{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	revision := newID("revision_")
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	if expectedRevision == "" || expectedRevision != s.state.revision {
		return View{}, ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return View{}, err
	}
	s.state.catalog, s.state.revision = nil, revision
	return s.state.view(now), nil
}

func newID(prefix string) string {
	var raw [16]byte
	// crypto/rand.Read is guaranteed to fill the slice; an unavailable OS
	// entropy source is a fatal runtime failure, never a weak-ID fallback.
	_, _ = rand.Read(raw[:])
	return prefix + hex.EncodeToString(raw[:])
}
