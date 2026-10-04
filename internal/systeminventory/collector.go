package systeminventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"sync/atomic"
	"time"
)

// Provider is an explicit synchronous source seam. Implementations must honor
// contexts cooperatively, cap reads/work and close resources before returning.
// A provider never receives paths, commands, environment or operator input.
type Provider interface {
	OpenServices(context.Context, ServiceSource) (io.ReadCloser, error)
	OpenSockets(context.Context, SocketSource) (io.ReadCloser, error)
	Attribute(context.Context, []uint64) (map[uint64]AttributionResult, error)
	Close() error
}

// SourceError carries a fixed taxonomy, never raw tool output or host paths.
type SourceError struct{ Reason Reason }

func (e SourceError) Error() string {
	if !validFailureReason(e.Reason) && !validAttributionFailure(e.Reason) {
		return "system_inventory_source_read_failed"
	}
	return "system_inventory_source_" + string(e.Reason)
}

var admitted atomic.Bool

// Collect is defined for source-boundary review. Runtime must separately require
// fresh managed-operations-v3 consent before calling it. No source execution is
// performed by package initialization. Actual Linux collection refuses UID 0.
func Collect(ctx context.Context, id string, at time.Time) (Snapshot, error) {
	return collectWith(ctx, id, at, &admitted, newSystemProvider)
}

// CollectWithProvider never constructs or invokes the real host provider. This
// isolated injection API shares single-flight admission with Collect.
func CollectWithProvider(ctx context.Context, id string, at time.Time, p Provider) (Snapshot, error) {
	if p == nil {
		return Snapshot{}, ErrInvalidInput
	}
	return collectWith(ctx, id, at, &admitted, func() (Provider, error) { return p, nil })
}
func collectWith(ctx context.Context, id string, at time.Time, slot *atomic.Bool, factory func() (Provider, error)) (Snapshot, error) {
	start := time.Now()
	s := Empty(id, at, ReasonNotCollected)
	if ctx == nil || slot == nil || factory == nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Empty(id, at, ReasonTimeout), nil
	}
	if !slot.CompareAndSwap(false, true) {
		return Empty(id, at, ReasonCollectorBusy), nil
	}
	defer slot.Store(false)
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	p, e := factory()
	if e != nil {
		return finish(Empty(id, at, failureReason(e)), start)
	}
	if p == nil {
		return finish(Empty(id, at, ReasonInvalidSource), start)
	}
	// No abandoned worker goroutines: the admission slot remains held across all
	// synchronous calls, including cooperative/uninterruptible filesystem work.
	s.Services = collectServices(ctx, p, id, at)
	s.Sockets = collectSockets(ctx, p, id, at)
	if err := p.Close(); err != nil {
		s = Empty(id, at, ReasonReadFailed)
	}
	return finish(s, start)
}
func collectServices(ctx context.Context, p Provider, id string, at time.Time) ServiceSection {
	if ctx.Err() != nil {
		return failedSection[Service](id, at, ReasonTimeout)
	}
	a, e := p.OpenServices(ctx, RuntimeSource)
	if e != nil {
		return failedSection[Service](id, at, failureReason(e))
	}
	if a == nil {
		return failedSection[Service](id, at, ReasonInvalidSource)
	}
	// Read and close one source at a time; only bounded bytes survive the call.
	ab, e := readBounded(ctx, a)
	ce := a.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return failedSection[Service](id, at, failureReason(e))
	}
	b, e := p.OpenServices(ctx, UnitFilesSource)
	if e != nil {
		return failedSection[Service](id, at, failureReason(e))
	}
	if b == nil {
		return failedSection[Service](id, at, ReasonInvalidSource)
	}
	bb, e := readBounded(ctx, b)
	ce = b.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return failedSection[Service](id, at, failureReason(e))
	}
	rows, e := ParseServices(ctx, bytes.NewReader(ab), bytes.NewReader(bb))
	if e != nil {
		return failedSection[Service](id, at, failureReason(e))
	}
	return completeSection(id, at, rows)
}
func collectSockets(ctx context.Context, p Provider, id string, at time.Time) SocketSection {
	all := []ObservedSocket{}
	for _, kind := range []SocketSource{TCP4Source, TCP6Source, UDP4Source, UDP6Source} {
		if ctx.Err() != nil {
			return failedSection[Socket](id, at, ReasonTimeout)
		}
		r, e := p.OpenSockets(ctx, kind)
		if e != nil {
			return failedSection[Socket](id, at, failureReason(e))
		}
		if r == nil {
			return failedSection[Socket](id, at, ReasonInvalidSource)
		}
		rows, e := ParseSockets(ctx, kind, r)
		ce := r.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return failedSection[Socket](id, at, failureReason(e))
		}
		if len(all)+len(rows) > MaxSocketRows {
			return failedSection[Socket](id, at, ReasonItemLimit)
		}
		all = append(all, rows...)
	}
	unique := map[uint64]bool{}
	inodes := []uint64{}
	for _, r := range all {
		if r.Inode != 0 && !unique[r.Inode] {
			unique[r.Inode] = true
			inodes = append(inodes, r.Inode)
		}
	}
	var associations map[uint64]AttributionResult
	var attrErr error
	if len(inodes) > 0 {
		actx, cancel := context.WithTimeout(ctx, AttributionTimeout)
		associations, attrErr = p.Attribute(actx, inodes)
		if actx.Err() != nil && attrErr == nil {
			if associations == nil {
				associations = make(map[uint64]AttributionResult, len(inodes))
			}
			for _, inode := range inodes {
				a := associations[inode]
				if a.Owners == nil {
					a.Owners = []Owner{}
				}
				a.Attribution = Attribution{AttributionPartial, ReasonTimeout}
				associations[inode] = a
			}
		}
		cancel()
		if len(associations) > len(inodes) {
			associations = nil
			attrErr = ErrInvalidSource
		}
	}
	for inode := range associations {
		if !unique[inode] {
			associations = nil
			attrErr = ErrInvalidSource
			break
		}
	}
	rows := make([]Socket, 0, len(all))
	for _, observation := range all {
		row := observation.Row
		if attrErr != nil {
			r := failureReason(attrErr)
			if !validAttributionFailure(r) {
				r = ReasonReadFailed
			}
			row.Attribution = Attribution{AttributionUnavailable, r}
		} else if a, ok := associations[observation.Inode]; ok {
			row.Owners = a.Owners
			row.Attribution = a.Attribution
			if row.Owners == nil {
				row.Owners = []Owner{}
			}
			if len(row.Owners) > MaxOwnersPerSocket {
				row.Owners = append([]Owner(nil), row.Owners[:MaxOwnersPerSocket]...)
				row.Attribution = Attribution{AttributionPartial, ReasonOwnerLimit}
			}
			sort.Slice(row.Owners, func(i, j int) bool { return row.Owners[i].PID < row.Owners[j].PID })
			if !validSocket(row) {
				row = observation.Row
				row.Attribution = Attribution{AttributionUnavailable, ReasonInvalidSource}
			}
		}
		rows = append(rows, row)
	}
	// Stable canonical order retains duplicate observations rather than deduping
	// sockets that happen to have the same endpoints and state.
	sort.SliceStable(rows, func(i, j int) bool { return socketLess(rows[i], rows[j]) })
	return completeSection(id, at, rows)
}
func socketLess(a, b Socket) bool {
	for _, p := range [][2]string{{a.Protocol, b.Protocol}, {a.Family, b.Family}, {a.Local.Address, b.Local.Address}} {
		if p[0] != p[1] {
			return p[0] < p[1]
		}
	}
	if a.Local.Port != b.Local.Port {
		return a.Local.Port < b.Local.Port
	}
	if a.Remote.Address != b.Remote.Address {
		return a.Remote.Address < b.Remote.Address
	}
	if a.Remote.Port != b.Remote.Port {
		return a.Remote.Port < b.Remote.Port
	}
	return a.State < b.State
}
func finish(s Snapshot, start time.Time) (Snapshot, error) {
	s.DurationMS = time.Since(start).Milliseconds()
	if b, e := json.Marshal(s.Services); e != nil || len(b) > MaxSectionBytes {
		s.Services = failedSection[Service](s.GenerationID, s.CollectedAt, ReasonByteLimit)
	}
	if b, e := json.Marshal(s.Sockets); e != nil || len(b) > MaxSectionBytes {
		s.Sockets = failedSection[Socket](s.GenerationID, s.CollectedAt, ReasonByteLimit)
	}
	s.DurationMS = time.Since(start).Milliseconds()
	if b, e := json.Marshal(s); e != nil || len(b) > MaxSnapshotBytes {
		s.Services = failedSection[Service](s.GenerationID, s.CollectedAt, ReasonByteLimit)
		s.Sockets = failedSection[Socket](s.GenerationID, s.CollectedAt, ReasonByteLimit)
	}
	if e := Validate(s); e != nil {
		return Snapshot{}, e
	}
	return s, nil
}
func failureReason(err error) Reason {
	var se SourceError
	if errors.As(err, &se) && validFailureReason(se.Reason) {
		return se.Reason
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(err, ErrInvalidSource):
		return ReasonInvalidSource
	case errors.Is(err, ErrSourceLimit):
		return ReasonByteLimit
	case errors.Is(err, ErrItemLimit):
		return ReasonItemLimit
	default:
		return ReasonReadFailed
	}
}
