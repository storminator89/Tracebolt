package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorystate"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/packagecollector"
	"net/http"
	"sync"
	"time"
)

const (
	inventoryMaxOperations   = 64
	inventoryCaptureInterval = 6 * time.Hour
	inventoryBurstTimeout    = 20 * time.Second
)

var (
	ErrInventoryTransport = errors.New("complete inventory delivery was not acknowledged; pending work retained")
	ErrInventoryReceipt   = errors.New("complete inventory receipt was invalid; pending work retained")
	ErrInventoryConflict  = errors.New("complete inventory state conflict remains unresolved; pending work retained")
	ErrInventoryPending   = errors.New("complete inventory burst limit reached; pending work retained")
)

// inventoryReport contains bounded operational metadata only. A successful
// HTTP-test acknowledgment is not server authentication or proof of revocation.
type inventoryReport struct {
	Status         string
	Sequence       uint64
	RetriedPending bool
	Captured       bool
	Operations     int
}

type inventorySource func(context.Context, string, time.Time) (fullinventory.SourceInventory, error)

// inventorySender owns an exclusive existing ledger for its whole lifetime.
// It creates no directory, identity, background job, retry timer or credential.
// Its caller serializes telemetry and Burst and supplies a cooperative deadline.
type inventorySender struct {
	mu              sync.Mutex
	material        Material
	state           *inventorystate.State
	client          *http.Client
	now             func() time.Time
	collect         inventorySource
	completeUpdates bool
	collectUpdates  completeUpdatesSource
	closed          bool
}

func (*inventorySender) String() string               { return "complete inventory sender (contents redacted)" }
func (*inventorySender) GoString() string             { return "lanclient.inventorySender{redacted}" }
func (s *inventorySender) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (*inventorySender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}

func openInventorySender(m Material) (*inventorySender, error) {
	return openInventorySenderWithSource(m, func() time.Time { return time.Now().UTC() }, packagecollector.CollectComplete)
}

func openInventorySenderWithSource(m Material, now func() time.Time, collect inventorySource) (*inventorySender, error) {
	if !m.valid() || !m.config.complete() || now == nil || collect == nil {
		return nil, ErrConfiguration
	}
	s, err := inventorystate.OpenExisting(inventoryStateDirectory(m.config), m.binding, m.config.AgentID)
	if err != nil {
		return nil, ErrState
	}
	return &inventorySender{material: m, state: s, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now, collect: collect}, nil
}

func (s *inventorySender) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	if s.state != nil && s.state.Close() != nil {
		return ErrState
	}
	return nil
}

// Burst resumes the current immutable operation first. A completed pending
// generation ends this burst; another collection never follows it immediately.
// Even a caller with a longer deadline gets at most 20 cooperative seconds and
// 64 purpose operations, including conflict status/recovery operations. Ordinary
// synchronous OS I/O still needs an external supervisor for a hard deadline.
func (s *inventorySender) Burst(ctx context.Context) (inventoryReport, error) {
	r := inventoryReport{Status: "pending_retained"}
	if s == nil || ctx == nil {
		return r, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return r, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryBurstTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil {
		return r, ErrState
	}
	if !s.material.valid() || !s.material.config.complete() || s.now == nil || (!s.completeUpdates && s.collect == nil) || (s.completeUpdates && s.collectUpdates == nil) || s.client == nil {
		return r, ErrConfiguration
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if s.completeUpdates {
		if _, ok := readCompleteUpdatesConsent(s.material); !ok {
			r.Status = "disabled"
			return r, nil
		}
	}
	w, pending, err := s.state.NextWork()
	if err != nil {
		return r, ErrState
	}
	r.RetriedPending = pending
	if !pending {
		last, err := s.state.LastAttemptedAt()
		if err != nil {
			return r, ErrState
		}
		now := s.now().UTC()
		if !last.IsZero() && now.Before(last.Add(inventoryCaptureInterval)) {
			r.Status = "not_due"
			return r, nil
		}
		a, err := s.state.Allocate(ctx, now)
		if err != nil {
			return r, inventoryStateError(ctx)
		}
		r.Sequence, r.Captured = a.Sequence, true
		if err := s.capture(ctx, a); err != nil {
			if errors.Is(err, errCompleteUpdatesDisabled) {
				r.Status = "disabled"
				return r, nil
			}
			return r, err
		}
		w, pending, err = s.state.NextWork()
		if err != nil || !pending {
			return r, ErrState
		}
	}
	r.Sequence = w.Sequence
	// A complete status can justify one exact finalize retry; never a cursor
	// skip, local retirement, collection-time refresh or repeated conflict loop.
	finalizeRetried := false
	for r.Operations < inventoryMaxOperations {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		r.Operations++
		raw, conflict, err := s.deliver(ctx, w)
		if err != nil {
			if errors.Is(err, errCompleteUpdatesDisabled) {
				r.Status = "disabled"
				return r, nil
			}
			return r, err
		}
		if conflict {
			if finalizeRetried || w.Operation == "failure" || w.Operation == "abort" {
				return r, ErrInventoryConflict
			}
			if r.Operations == inventoryMaxOperations {
				return r, ErrInventoryPending
			}
			status, err := s.state.StatusWork()
			if err != nil {
				return r, ErrState
			}
			r.Operations++
			statusRaw, statusConflict, err := s.deliver(ctx, status)
			if err != nil {
				if errors.Is(err, errCompleteUpdatesDisabled) {
					r.Status = "disabled"
					return r, nil
				}
				return r, err
			}
			if statusConflict {
				return r, ErrInventoryConflict
			}
			receipt, err := s.state.ValidateStatus(status, statusRaw)
			if err != nil {
				return r, ErrInventoryReceipt
			}
			if !receipt.CompletedAt.IsZero() {
				if w.Operation != "finalize" {
					return r, ErrInventoryConflict
				}
				finalizeRetried = true
				continue
			}
			if receipt.State != "expired" && receipt.State != "failed" {
				return r, ErrInventoryConflict
			}
			if receipt.State == "expired" && receipt.ExpiresAt.After(s.now().UTC()) {
				return r, ErrInventoryReceipt
			}
			if err := s.state.RequestAbortAfterStatus(status, statusRaw); err != nil {
				return r, ErrInventoryReceipt
			}
			w, pending, err = s.state.NextWork()
			if err != nil || !pending || w.Operation != "abort" {
				return r, ErrState
			}
			continue
		}
		if err := s.state.Acknowledge(w, raw); err != nil {
			if errors.Is(err, inventorystate.ErrAcknowledgment) {
				return r, ErrInventoryReceipt
			}
			return r, ErrState
		}
		completedOp := w.Operation
		w, pending, err = s.state.NextWork()
		if err != nil {
			return r, ErrState
		}
		if !pending {
			switch completedOp {
			case "finalize":
				r.Status = "acknowledged"
			case "failure":
				r.Status = "failure_acknowledged"
			case "abort":
				r.Status = "aborted"
			default:
				return r, ErrState
			}
			return r, nil
		}
	}
	return r, ErrInventoryPending
}

func inventoryStateError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrState
}

func (s *inventorySender) capture(ctx context.Context, a inventorystate.Allocation) error {
	if s.completeUpdates {
		return s.captureCompleteUpdates(ctx, a)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	source, sourceErr := s.collect(ctx, a.GenerationID, a.AttemptedAt)
	// Always propagate the source operation's error to Build. A prefix returned
	// with an error is never turned into a successful generation.
	manifest, chunks, buildErr := fullinventory.Build(ctx, source, sourceErr)
	if ctx.Err() != nil {
		return ctx.Err()
	} // allocated fallback survives restart
	if source.GenerationID != a.GenerationID || !source.CollectedAt.Equal(a.AttemptedAt) {
		if sourceErr == nil {
			buildErr = fullinventory.ErrInvalid
		}
	}
	if buildErr != nil {
		reason := inventoryFailureReason(sourceErr, buildErr)
		if s.state.StageFailure(ctx, a, reason) != nil {
			return inventoryStateError(ctx)
		}
		return nil
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return ErrState
	}
	rawChunks := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rawChunks[i], err = json.Marshal(chunk)
		if err != nil {
			return ErrState
		}
	}
	if s.state.Stage(ctx, a, manifestRaw, rawChunks) != nil {
		return inventoryStateError(ctx)
	}
	return nil
}

func inventoryFailureReason(sourceErr, buildErr error) string {
	if sourceErr != nil {
		switch packagecollector.CompleteFailureReason(sourceErr) {
		case linuxpackages.ReasonSourceMissing:
			return "source_missing"
		case linuxpackages.ReasonInvalidSource:
			return "source_invalid"
		case linuxpackages.ReasonSourceChanged:
			return "source_changed"
		case linuxpackages.ReasonItemLimit, linuxpackages.ReasonByteLimit:
			return "resource_limit"
		default:
			return "collection_failed"
		}
	}
	if errors.Is(buildErr, fullinventory.ErrLimit) {
		return "resource_limit"
	}
	if errors.Is(buildErr, fullinventory.ErrInvalid) {
		return "source_invalid"
	}
	return "collection_failed"
}
