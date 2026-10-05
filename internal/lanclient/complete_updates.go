package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/inventorystate"
	"localrmm/internal/updategeneration"
	"time"
)

var errCompleteUpdatesDisabled = errors.New("complete_cached_updates_disabled")

type completeUpdatesSource func(context.Context, string, time.Time, cachedupdates.CompleteLocalConsent, string) (cachedupdates.CompleteSource, error)

func openCompleteUpdatesSender(m Material) (*inventorySender, error) {
	return openCompleteUpdatesSenderWithSource(m, func() time.Time { return time.Now().UTC() }, cachedupdates.CollectComplete)
}
func openCompleteUpdatesSenderWithSource(m Material, now func() time.Time, collect completeUpdatesSource) (*inventorySender, error) {
	if !m.valid() || !m.config.complete() || now == nil || collect == nil {
		return nil, ErrConfiguration
	}
	// Default off includes no opening, creating or repairing the bulk spool.
	if _, ok := readCompleteUpdatesConsent(m); !ok {
		return nil, nil
	}
	state, e := inventorystate.OpenCachedUpdatesExisting(completeUpdatesStateDirectory(m.config), completeUpdatesStateBinding(m), m.config.AgentID)
	if e != nil {
		return nil, ErrState
	}
	return &inventorySender{material: m, state: state, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now, completeUpdates: true, collectUpdates: collect}, nil
}

func (s *inventorySender) captureCompleteUpdates(ctx context.Context, a inventorystate.Allocation) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	consent, ok := readCompleteUpdatesConsent(s.material)
	if !ok {
		return errCompleteUpdatesDisabled
	}
	source, sourceErr := s.collectUpdates(ctx, a.GenerationID, a.AttemptedAt, consent, s.material.binding)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, ok = readCompleteUpdatesConsent(s.material); !ok {
		return errCompleteUpdatesDisabled
	}
	manifest, chunks, buildErr := updategeneration.Build(ctx, updategeneration.SourceInventory{Snapshot: source.Snapshot, Rows: source.Rows, Complete: source.Complete}, sourceErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if source.Snapshot.GenerationID != a.GenerationID || !source.Snapshot.CollectedAt.Equal(a.AttemptedAt) {
		if sourceErr == nil {
			buildErr = updategeneration.ErrInvalid
		}
	}
	if buildErr != nil {
		reason := "collection_failed"
		switch source.Snapshot.Reason {
		case cachedupdates.ReasonSourceMissing, cachedupdates.ReasonCacheMissing:
			reason = "source_missing"
		case cachedupdates.ReasonInvalidSource:
			reason = "source_invalid"
		case cachedupdates.ReasonNotSupported:
			reason = "not_supported"
		case cachedupdates.ReasonSourceChanged:
			reason = "source_changed"
		case cachedupdates.ReasonByteLimit, cachedupdates.ReasonWorkLimit:
			reason = "resource_limit"
		}
		if errors.Is(buildErr, updategeneration.ErrLimit) {
			reason = "resource_limit"
		}
		if errors.Is(buildErr, updategeneration.ErrInvalid) {
			reason = "source_invalid"
		}
		if s.state.StageFailure(ctx, a, reason) != nil {
			return inventoryStateError(ctx)
		}
		return nil
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		return ErrState
	}
	rawChunks := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rawChunks[i], e = json.Marshal(chunk)
		if e != nil {
			return ErrState
		}
	}
	if s.state.Stage(ctx, a, raw, rawChunks) != nil {
		return inventoryStateError(ctx)
	}
	return nil
}

// The optional update stage shares the existing fixed transfer machine. Its
// transport failures retain exact bytes without delaying other extensions or
// causing a successful metrics attempt to enter exponential backoff.
func runCompleteUpdatesAttempt(ctx context.Context, s *inventorySender, report *Report) error {
	if s == nil {
		return nil
	}
	burst, cancel := context.WithTimeout(ctx, inventoryBurstTimeout)
	defer cancel()
	status, e := s.Burst(burst)
	report.CachedUpdatesStatus, report.CachedUpdatesSequence, report.CachedUpdatesOperations = status.Status, status.Sequence, uint8(status.Operations)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch e {
	case nil, ErrInventoryPending, ErrInventoryTransport, ErrInventoryReceipt, ErrInventoryConflict, errCompleteUpdatesDisabled, context.DeadlineExceeded:
		return nil
	default:
		return e
	}
}
