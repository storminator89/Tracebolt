package completeoverview

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"sync/atomic"
	"time"
)

// Provider is synchronous, bounded and cooperative. The production provider
// accepts only fixed proc sources and numeric/kernel-enumerated identities.
// No provider method is invoked during package initialization.
type Provider interface {
	EnumeratePIDs(context.Context, func(uint32) error) error
	ProcessUnits(context.Context) (pageBytes, ticksPerSecond uint64, err error)
	OpenProcessStat(context.Context, uint32) (io.ReadCloser, error)
	OpenMountInfo(context.Context) (io.ReadCloser, error)
	MeasureMounts(context.Context, []MountRecord) ([]MountMeasurement, error)
	Close() error
}
type SourceError struct{ Reason Reason }

func (e SourceError) Error() string {
	if !validFailureReason(e.Reason) && e.Reason != ReasonProcessGone && e.Reason != ReasonMountChanged {
		return "complete_overview_source_read_failed"
	}
	return "complete_overview_source_" + string(e.Reason)
}

var admitted atomic.Bool

// Collect is an inert candidate entry point, not an authorization decision.
// It must not be wired to existing managed-v3 consent: fresh explicit local
// complete-overview opt-in and a separately recognized wire version are required.
// The actual Linux provider refuses root and performs no subprocess execution.
func Collect(ctx context.Context, id string, at time.Time) (Snapshot, error) {
	return collectWith(ctx, id, at, &admitted, newProvider)
}
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
	// Admission remains held through every syscall and Close. Never detach a timed
	// out goroutine; a blocked kernel syscall can exceed the cooperative budget.
	s.Processes = collectProcesses(ctx, p, id)
	s.Volumes = collectVolumes(ctx, p, id)
	if e = p.Close(); e != nil {
		s = Empty(id, at, ReasonReadFailed)
	}
	return finish(s, start)
}
func collectProcesses(ctx context.Context, p Provider, id string) ProcessSection {
	fail := func(e error) ProcessSection { return failedSection[Process](id, failureReason(e)) }
	pids := []uint32{}
	seen := map[uint32]bool{}
	var callbackErr error
	e := p.EnumeratePIDs(ctx, func(pid uint32) error {
		if callbackErr != nil {
			return callbackErr
		}
		callbackErr = acceptPID(ctx, pid, seen, len(pids))
		if callbackErr != nil {
			return callbackErr
		}
		seen[pid] = true
		pids = append(pids, pid)
		return nil
	})
	if callbackErr != nil {
		return fail(callbackErr)
	}
	if e != nil {
		return fail(e)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	page, ticks, unitsErr := p.ProcessUnits(ctx)
	if r := failureReason(unitsErr); unitsErr != nil && (r == ReasonItemLimit || r == ReasonByteLimit) {
		return fail(unitsErr)
	}
	rows := make([]Process, 0, len(pids))
	bytesRead := 0
	for _, pid := range pids {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		row := Process{PID: pid}
		if unitsErr != nil {
			row.Observation = missingObservation(unitsErr, true)
			rows = append(rows, row)
			continue
		}
		r, e := p.OpenProcessStat(ctx, pid)
		if e == nil && r == nil {
			e = ErrInvalidSource
		}
		if e == nil {
			var raw []byte
			raw, e = readBounded(ctx, r, MaxProcessStatBytes)
			ce := r.Close()
			if e == nil {
				e = ce
			}
			bytesRead += len(raw)
			if bytesRead > MaxSourceBytes {
				return fail(ErrSourceLimit)
			}
			if e == nil {
				row, e = ParseProcessStat(raw, pid, page, ticks)
			}
		}
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		if failureReason(e) == ReasonByteLimit || failureReason(e) == ReasonItemLimit {
			return fail(e)
		}
		if e != nil {
			row = Process{PID: pid, Observation: missingObservation(e, true)}
		}
		rows = append(rows, row)
	}
	return completeSection(id, rows)
}
func collectVolumes(ctx context.Context, p Provider, id string) VolumeSection {
	fail := func(e error) VolumeSection { return failedSection[Volume](id, failureReason(e)) }
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	r, e := p.OpenMountInfo(ctx)
	if e != nil {
		return fail(e)
	}
	if r == nil {
		return fail(ErrInvalidSource)
	}
	mounts, e := ParseMountInfo(ctx, r)
	ce := r.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return fail(e)
	}
	measured, e := p.MeasureMounts(ctx, mounts)
	if e != nil {
		return fail(e)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	measurements := map[uint32]MountMeasurement{}
	expected := map[uint32]bool{}
	for _, m := range mounts {
		if k := mountKind(m.Filesystem); k == "local" || k == "memory" {
			expected[m.MountID] = true
		}
	}
	for _, m := range measured {
		if !expected[m.MountID] {
			return fail(ErrInvalidSource)
		}
		if _, ok := measurements[m.MountID]; ok {
			return fail(ErrInvalidSource)
		}
		measurements[m.MountID] = m
	}
	if len(measurements) != len(expected) {
		return fail(ErrInvalidSource)
	}
	rows := make([]Volume, 0, len(mounts))
	for _, m := range mounts {
		v := volumeFor(m)
		if mm, ok := measurements[m.MountID]; ok {
			v.Measurement = mm.Observation
			if mm.Capacity != nil {
				v.TotalBytes = ptr(mm.Capacity.TotalBytes)
				v.AvailableBytes = ptr(mm.Capacity.AvailableBytes)
				if mm.Capacity.TotalBytes > 0 && mm.Capacity.AvailableBytes <= mm.Capacity.TotalBytes {
					v.UsedPercent = ptr(float64(mm.Capacity.TotalBytes-mm.Capacity.AvailableBytes) * 100 / float64(mm.Capacity.TotalBytes))
				}
			}
		}
		if !validVolume(v) {
			return fail(ErrInvalidSource)
		}
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool { return volumeLess(rows[i], rows[j]) })
	return completeSection(id, rows)
}
func finish(s Snapshot, start time.Time) (Snapshot, error) {
	s.CaptureFinishedAt = s.CaptureStartedAt.Add(time.Since(start))
	if b, e := json.Marshal(s.Processes); e != nil || len(b) > MaxSectionBytes {
		s.Processes = failedSection[Process](s.GenerationID, ReasonByteLimit)
	}
	if b, e := json.Marshal(s.Volumes); e != nil || len(b) > MaxSectionBytes {
		s.Volumes = failedSection[Volume](s.GenerationID, ReasonByteLimit)
	}
	if b, e := json.Marshal(s); e != nil || len(b) > MaxSnapshotBytes {
		s.Processes = failedSection[Process](s.GenerationID, ReasonByteLimit)
		s.Volumes = failedSection[Volume](s.GenerationID, ReasonByteLimit)
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
func missingObservation(err error, process bool) Observation {
	var se SourceError
	if errors.As(err, &se) {
		if process && (se.Reason == ReasonProcessGone || se.Reason == ReasonSourceMissing) {
			return Observation{Exited, ReasonProcessGone}
		}
		if !process && se.Reason == ReasonMountChanged {
			return Observation{Invalid, ReasonMountChanged}
		}
	}
	switch r := failureReason(err); r {
	case ReasonPermissionDenied:
		return Observation{Denied, r}
	case ReasonNotSupported:
		return Observation{Unsupported, r}
	case ReasonInvalidSource:
		return Observation{Invalid, r}
	case ReasonSourceMissing:
		return Observation{Unavailable, r}
	default:
		return Observation{Unavailable, ReasonReadFailed}
	}
}
func readBounded(ctx context.Context, r io.Reader, limit int) ([]byte, error) {
	if ctx == nil || r == nil || limit < 0 {
		return nil, ErrInvalidInput
	}
	b := make([]byte, 0, min(limit, 4096))
	var chunk [4096]byte
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, e := r.Read(chunk[:min(len(chunk), limit-len(b)+1)])
		if n < 0 || n > min(len(chunk), limit-len(b)+1) {
			return nil, ErrInvalidSource
		}
		b = append(b, chunk[:n]...)
		if len(b) > limit {
			return nil, ErrSourceLimit
		}
		if e == io.EOF {
			return b, nil
		}
		if e != nil {
			return nil, e
		}
		if n == 0 {
			return nil, ErrInvalidSource
		}
	}
}

func acceptPID(ctx context.Context, pid uint32, seen map[uint32]bool, count int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if pid == 0 || pid > 2147483647 || seen[pid] {
		return ErrInvalidSource
	}
	if count >= MaxProcessRows {
		return ErrItemLimit
	}
	return nil
}
