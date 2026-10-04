package lanclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/completeoverview"
	"sync"
	"time"
)

var errOverviewDisabled = errors.New("complete_overview_disabled")

type overviewBurstReport struct{ Processes, Volumes overviewReport }

// overviewSender has exactly two section domains. It is not a generic job
// scheduler. Collection, staging and delivery stay synchronous and serialized.
type overviewSender struct {
	mu                 sync.Mutex
	material           Material
	processes, volumes *overviewSectionSender
	now                func() time.Time
	collect            overviewSource
	volumesFirst       bool
	closed             bool
}

func (*overviewSender) String() string               { return "complete overview sender (contents redacted)" }
func (*overviewSender) GoString() string             { return "lanclient.overviewSender{redacted}" }
func (s *overviewSender) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (*overviewSender) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

func openOverviewSender(m Material) (*overviewSender, error) {
	return openOverviewSenderWithSource(m, func() time.Time { return time.Now().UTC() }, completeoverview.Collect)
}
func openOverviewSenderWithSource(m Material, now func() time.Time, collect overviewSource) (*overviewSender, error) {
	if !m.valid() || !m.config.complete() || now == nil || collect == nil {
		return nil, ErrConfiguration
	}
	// Default-off: neither source collection nor a state directory open/create.
	if !readOverviewConsent(m) {
		return nil, nil
	}
	p, e := openOverviewSectionSenderWithSource(m, "processes", now, collect)
	if e != nil {
		return nil, e
	}
	v, e := openOverviewSectionSenderWithSource(m, "volumes", now, collect)
	if e != nil {
		p.Close()
		return nil, e
	}
	return &overviewSender{material: m, processes: p, volumes: v, now: now, collect: collect}, nil
}
func (s *overviewSender) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	a, b := s.processes.Close(), s.volumes.Close()
	if a != nil || b != nil {
		return ErrState
	}
	return nil
}
func (s *overviewSender) Burst(ctx context.Context) (overviewBurstReport, error) {
	out := overviewBurstReport{Processes: overviewReport{Status: "disabled"}, Volumes: overviewReport{Status: "disabled"}}
	if s == nil {
		return out, nil
	}
	if ctx == nil {
		return out, ErrConfiguration
	}
	if _, ok := ctx.Deadline(); !ok {
		return out, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, overviewBurstTimeout)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return out, ErrState
	}
	if !readOverviewConsent(s.material) {
		return out, nil
	}
	out.Processes.Status, out.Volumes.Status = "pending_retained", "pending_retained"
	at := s.now().UTC()
	// A single full capture feeds whichever fixed domains are due. Captures are
	// never cached across bursts; every staged transfer keeps its original time.
	captured := false
	var source completeoverview.Snapshot
	var sourceErr error
	shared := func(ctx context.Context, id string, when time.Time) (completeoverview.Snapshot, error) {
		if !readOverviewConsent(s.material) {
			return completeoverview.Snapshot{}, errOverviewDisabled
		}
		if !captured {
			captured = true
			source, sourceErr = s.collect(ctx, id, when)
		}
		return source, sourceErr
	}
	ps, vs := s.processes, s.volumes
	for _, section := range []*overviewSectionSender{ps, vs} {
		section.now = func() time.Time { return at }
		section.collect = shared
	}
	defer func() {
		for _, section := range []*overviewSectionSender{ps, vs} {
			section.now = s.now
			section.collect = s.collect
		}
	}()
	sections := []*overviewSectionSender{ps, vs}
	reports := []*overviewReport{&out.Processes, &out.Volumes}
	if s.volumesFirst {
		sections[0], sections[1] = sections[1], sections[0]
		reports[0], reports[1] = reports[1], reports[0]
	}
	s.volumesFirst = !s.volumesFirst
	// Drain retained immutable work before admitting any new capture, including
	// when only the sibling section is idle. Completion ends this burst's capture
	// opportunity; a retry never refreshes either section's original age.
	allowCapture := true
	for _, section := range sections {
		if _, pending, e := section.state.NextWork(); e != nil {
			return out, ErrState
		} else if pending {
			allowCapture = false
		}
	}
	var result error
	prepared := [2]bool{}
	for i, section := range sections {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if !readOverviewConsent(s.material) {
			return overviewBurstReport{Processes: overviewReport{Status: "disabled"}, Volumes: overviewReport{Status: "disabled"}}, nil
		}
		status, e := section.prepare(ctx, allowCapture)
		*reports[i] = status
		if e != nil {
			if !overviewIsolatedFailure(e) {
				return out, e
			}
			result = overviewBurstError(result, e)
			continue
		}
		prepared[i] = true
	}
	remaining := overviewMaxOperations
	for i, section := range sections {
		if !prepared[i] || reports[i].Status == "not_due" {
			continue
		}
		if remaining == 0 {
			if result == nil {
				result = ErrOverviewPending
			}
			continue
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		status, e := section.Burst(ctx, remaining)
		status.Captured = reports[i].Captured
		status.RetriedPending = reports[i].RetriedPending
		*reports[i] = status
		remaining -= status.Operations
		if errors.Is(e, errOverviewDisabled) {
			reports[i].Status = "disabled"
			e = nil
		}
		if e != nil {
			if !overviewIsolatedFailure(e) {
				return out, e
			}
			result = overviewBurstError(result, e)
		}
	}
	return out, result
}
func runOverviewAttempt(ctx context.Context, s *overviewSender, report *Report) error {
	if s == nil {
		return nil
	}
	burst, cancel := context.WithTimeout(ctx, overviewBurstTimeout)
	defer cancel()
	status, e := s.Burst(burst)
	report.ProcessesStatus, report.ProcessesSequence = status.Processes.Status, status.Processes.Sequence
	report.VolumesStatus, report.VolumesSequence = status.Volumes.Status, status.Volumes.Sequence
	report.OverviewOperations = uint8(status.Processes.Operations + status.Volumes.Operations)
	return overviewSchedulingError(ctx, e)
}

// Overview-specific delivery failures leave fixed status metadata and exact
// pending bytes, but do not change successful metrics' cadence or block journal
// progression. A remote rejection alone cannot prove enrollment revocation.
// Trusted local configuration/state failures, parent cancellation and unknown
// errors still propagate; only this extension's own deadline is isolated.
func overviewSchedulingError(parent context.Context, err error) error {
	if parent == nil {
		return ErrConfiguration
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	if overviewIsolatedFailure(err) {
		return nil
	}
	return err
}

// This fixed completion order is shared by the one-shot and foreground paths.
// The callback is the journal stage only, not a general task scheduling hook.
func runOverviewAndJournal(ctx context.Context, s *overviewSender, report *Report, journal func(context.Context) string) error {
	if err := runOverviewAttempt(ctx, s, report); err != nil {
		return err
	}
	if journal != nil {
		report.JournalStatus = journal(ctx)
	}
	return nil
}

// Only exact errors from this adapter are isolated. Joined/wrapped unexpected
// authority or trusted-boundary failures must not inherit a weaker class.
func overviewIsolatedFailure(err error) bool {
	switch err {
	case nil, ErrOverviewPending, ErrOverviewTransport, ErrOverviewReceipt, ErrOverviewConflict, errOverviewDisabled, context.DeadlineExceeded:
		return true
	default:
		return false
	}
}
func overviewBurstError(current, next error) error {
	if next != nil && (current == nil || !overviewIsolatedFailure(next)) {
		return next
	}
	return current
}
