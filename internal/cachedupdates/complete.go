package cachedupdates

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"
)

const (
	CompleteConsentVersion = "tracebolt.complete-cached-apt-updates-local-consent.v1"
	CompleteSchemaVersion  = "tracebolt.complete-cached-apt-updates.v1"
	CompleteScope          = "agent-visible-complete-known-cached-apt-candidate-rows"
)

// CompleteLocalConsent is a distinct full-row grant. Preview consent can never
// be supplied accidentally or reinterpreted as permission to export all rows.
type CompleteLocalConsent LocalConsent

func DecodeCompleteLocalConsent(raw []byte, binding string) (CompleteLocalConsent, error) {
	c, e := decodeLocalConsent(raw, binding, CompleteConsentVersion, CompleteSchemaVersion, CompleteScope)
	return CompleteLocalConsent(c), e
}
func EncodeCompleteLocalConsent(c CompleteLocalConsent, binding string) ([]byte, error) {
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalidInput
	}
	if _, e = DecodeCompleteLocalConsent(raw, binding); e != nil {
		return nil, e
	}
	return raw, nil
}

// CompleteSource is local pre-trim input for the typed generation adapter.
// It is not a public wire DTO and grants no transmission authority.
// Snapshot is the same bounded preview; Rows contains the complete ordered set
// from that exact finished attempt. Unknown comparisons stay explicit.
type CompleteSource struct {
	Snapshot Snapshot
	Rows     []Candidate
	Complete bool
}

func CollectComplete(ctx context.Context, generation string, at time.Time, consent CompleteLocalConsent, binding string) (CompleteSource, error) {
	return collectCompleteWith(ctx, generation, at, consent, binding, &admitted, newNativeSource)
}
func collectCompleteWith(ctx context.Context, generation string, at time.Time, consent CompleteLocalConsent, binding string, slot *atomic.Bool, factory func() (nativeSource, error)) (CompleteSource, error) {
	if _, e := EncodeCompleteLocalConsent(consent, binding); e != nil {
		return CompleteSource{}, ErrInvalidInput
	}
	var rows []Candidate
	s, e := collectCore(ctx, generation, at, slot, factory, &rows)
	if e != nil {
		return CompleteSource{}, e
	}
	out := CompleteSource{Snapshot: s}
	if s.Coverage == "unavailable" {
		return out, sourceFailure(s.Reason)
	}
	if rows == nil {
		return out, ErrInvalidSnapshot
	}
	out.Rows, out.Complete = rows, true
	return out, nil
}
