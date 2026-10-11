package windowsadapters

import (
	"context"
	"errors"
	"sort"
	"time"
)

type Result struct {
	Rows     []Adapter
	Complete bool
	Err      error
}

func Collect(ctx context.Context, generation, grant string, capturedAt time.Time) (Snapshot, error) {
	return collectUsing(ctx, generation, grant, capturedAt, readNative)
}
func collectUsing(ctx context.Context, generation, grant string, capturedAt time.Time, read func(context.Context) Result) (Snapshot, error) {
	if ctx == nil || read == nil || !validGeneration(generation) || !hex(grant, 32) || !validTime(capturedAt) {
		return Snapshot{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := read(bounded)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: grant, GenerationID: generation, CollectedAt: capturedAt, Quality: "observed", CountExact: r.Complete, Rows: append([]Adapter{}, r.Rows...)}
	if len(s.Rows) > MaxObservedRows {
		return Snapshot{}, ErrInvalid
	}
	s.ObservedCount = uint32(len(s.Rows))
	if !r.Complete {
		s.Quality = "partial"
		if len(r.Rows) == 0 {
			s.Quality = "unavailable"
			if errors.Is(r.Err, ErrDenied) {
				s.Quality = "denied"
			}
			if errors.Is(r.Err, ErrUnsupported) {
				s.Quality = "unsupported"
			}
		}
	}
	sort.Slice(s.Rows, func(i, j int) bool { return compareRows(s.Rows[i], s.Rows[j]) < 0 })
	if len(s.Rows) > MaxRows {
		s.Rows = s.Rows[:MaxRows]
	}
	s.Truncated = int(s.ObservedCount) > len(s.Rows)
	return fit(s, MaxBytes)
}
