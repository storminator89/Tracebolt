package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewstate"
	"localrmm/internal/overviewwire"
	"net/http"
	"sync"
	"time"
)

const (
	overviewMaxOperations   = 64
	overviewCaptureInterval = time.Minute
	overviewBurstTimeout    = 20 * time.Second
)

var (
	ErrOverviewTransport = errors.New("complete overview delivery was not acknowledged; pending work retained")
	ErrOverviewReceipt   = errors.New("complete overview receipt was invalid; pending work retained")
	ErrOverviewConflict  = errors.New("complete overview state conflict remains unresolved; pending work retained")
	ErrOverviewPending   = errors.New("complete overview burst limit reached; pending work retained")
)

// overviewReport contains bounded operational metadata only. A successful
// HTTP-test acknowledgment is not server authentication or proof of revocation.
type overviewReport struct {
	Status         string
	Sequence       uint64
	RetriedPending bool
	Captured       bool
	Operations     int
}

type overviewSource func(context.Context, string, time.Time) (completeoverview.Snapshot, error)

// overviewSectionSender owns an exclusive existing ledger for its whole lifetime.
// It creates no directory, identity, background job, retry timer or credential.
// Its caller serializes telemetry and Burst and supplies a cooperative deadline.
type overviewSectionSender struct {
	mu       sync.Mutex
	material Material
	state    *overviewstate.State
	section  string
	client   *http.Client
	now      func() time.Time
	collect  overviewSource
	closed   bool
}

func (*overviewSectionSender) String() string               { return "complete overview sender (contents redacted)" }
func (*overviewSectionSender) GoString() string             { return "lanclient.overviewSectionSender{redacted}" }
func (s *overviewSectionSender) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (*overviewSectionSender) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}

func openOverviewSectionSenderWithSource(m Material, section string, now func() time.Time, collect overviewSource) (*overviewSectionSender, error) {
	if !m.valid() || !m.config.complete() || now == nil || collect == nil {
		return nil, ErrConfiguration
	}
	s, err := overviewstate.OpenExisting(overviewStateDirectory(m.config, section), m.binding, m.config.AgentID, section)
	if err != nil {
		return nil, ErrState
	}
	return &overviewSectionSender{material: m, section: section, state: s, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: now, collect: collect}, nil
}

func (s *overviewSectionSender) Close() error {
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
func (s *overviewSectionSender) Burst(ctx context.Context, maxOperations int) (overviewReport, error) {
	r := overviewReport{Status: "pending_retained"}
	if s == nil || ctx == nil || maxOperations < 1 || maxOperations > overviewMaxOperations {
		return r, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return r, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, overviewBurstTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil {
		return r, ErrState
	}
	if !s.material.valid() || !s.material.config.complete() || s.now == nil || s.collect == nil || s.client == nil {
		return r, ErrConfiguration
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	w, pending, err := s.state.NextWork()
	if err != nil {
		return r, ErrState
	}
	if !pending {
		r.Status = "not_due"
		return r, nil
	}
	r.RetriedPending = true
	r.Sequence = w.Sequence
	// A complete status can justify one exact finalize retry; never a cursor
	// skip, local retirement, collection-time refresh or repeated conflict loop.
	finalizeRetried := false
	for r.Operations < maxOperations {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		r.Operations++
		raw, conflict, err := s.deliver(ctx, w)
		if err != nil {
			return r, err
		}
		if conflict {
			if finalizeRetried || w.Operation == "failure" || w.Operation == "abort" {
				return r, ErrOverviewConflict
			}
			if r.Operations == maxOperations {
				return r, ErrOverviewPending
			}
			status, err := s.state.StatusWork()
			if err != nil {
				return r, ErrState
			}
			r.Operations++
			statusRaw, statusConflict, err := s.deliver(ctx, status)
			if err != nil {
				return r, err
			}
			if statusConflict {
				return r, ErrOverviewConflict
			}
			receipt, err := s.state.ValidateStatus(status, statusRaw)
			if err != nil {
				return r, ErrOverviewReceipt
			}
			if !receipt.CompletedAt.IsZero() {
				if w.Operation != "finalize" {
					return r, ErrOverviewConflict
				}
				finalizeRetried = true
				continue
			}
			if receipt.State != "expired" && receipt.State != "failed" {
				return r, ErrOverviewConflict
			}
			if receipt.State == "expired" && receipt.ExpiresAt.After(s.now().UTC()) {
				return r, ErrOverviewReceipt
			}
			if err := s.state.RequestAbortAfterStatus(status, statusRaw); err != nil {
				return r, ErrOverviewReceipt
			}
			w, pending, err = s.state.NextWork()
			if err != nil || !pending || w.Operation != "abort" {
				return r, ErrState
			}
			continue
		}
		if err := s.state.Acknowledge(w, raw); err != nil {
			if errors.Is(err, overviewstate.ErrAcknowledgment) {
				return r, ErrOverviewReceipt
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
	return r, ErrOverviewPending
}

func (s *overviewSectionSender) prepare(ctx context.Context, allowCapture bool) (overviewReport, error) {
	r := overviewReport{Status: "pending_retained"}
	w, pending, err := s.state.NextWork()
	if err != nil {
		return r, ErrState
	}
	r.RetriedPending = pending
	if !pending && !allowCapture {
		r.Status = "not_due"
		return r, nil
	}
	if !pending {
		last, err := s.state.LastAttemptedAt()
		if err != nil {
			return r, ErrState
		}
		now := s.now().UTC()
		if !last.IsZero() && now.Before(last.Add(overviewCaptureInterval)) {
			r.Status = "not_due"
			return r, nil
		}
		a, err := s.state.Allocate(ctx, now)
		if err != nil {
			return r, overviewStateError(ctx, err)
		}
		r.Sequence, r.Captured = a.Sequence, true
		if err := s.capture(ctx, a); err != nil {
			return r, err
		}
		w, pending, err = s.state.NextWork()
		if err != nil || !pending {
			return r, ErrState
		}
	}
	r.Sequence = w.Sequence
	return r, nil
}

func overviewStateError(ctx context.Context, err error) error {
	if errors.Is(err, overviewstate.ErrCanceled) && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrState
}

func (s *overviewSectionSender) capture(ctx context.Context, a overviewstate.Allocation) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	source, sourceErr := s.collect(ctx, a.GenerationID, a.AttemptedAt)
	// Always propagate the source operation's error to Build. A prefix returned
	// with an error is never turned into a successful generation.
	manifest, chunks, buildErr := overviewgeneration.Build(ctx, source, s.section, a.GenerationID, sourceErr)
	if ctx.Err() != nil {
		return ctx.Err()
	} // allocated fallback survives restart
	if !source.CaptureStartedAt.Equal(a.AttemptedAt) {
		if sourceErr == nil {
			buildErr = overviewgeneration.ErrInvalid
		}
	}
	if buildErr != nil {
		reason := overviewFailureReason(source, s.section, sourceErr, buildErr)
		if err := s.state.StageFailure(ctx, a, reason); err != nil {
			return overviewStateError(ctx, err)
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
	if err := s.state.Stage(ctx, a, manifestRaw, rawChunks); err != nil {
		return overviewStateError(ctx, err)
	}
	return nil
}

func overviewFailureReason(source completeoverview.Snapshot, section string, sourceErr, buildErr error) string {
	if sourceErr == nil {
		meta := source.Processes.Meta
		if section == "volumes" {
			meta = source.Volumes.Meta
		}
		if meta.Coverage == completeoverview.Failed && overviewwire.ValidFailureReason(string(meta.Reason)) {
			return string(meta.Reason)
		}
	}
	var se completeoverview.SourceError
	if errors.As(sourceErr, &se) && overviewwire.ValidFailureReason(string(se.Reason)) {
		return string(se.Reason)
	}
	if errors.Is(sourceErr, context.Canceled) || errors.Is(sourceErr, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(buildErr, overviewgeneration.ErrLimit) {
		return "resource_limit"
	}
	if errors.Is(buildErr, overviewgeneration.ErrInvalid) {
		return "source_invalid"
	}
	return "collection_failed"
}
