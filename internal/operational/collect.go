package operational

import (
	"context"
	"encoding/json"
	"time"
)

// At most one collection runs at a time. Filesystem calls cooperate with the
// context between reads; Go cannot interrupt an in-progress kernel syscall.
// No background worker is abandoned on timeout or accumulated by repeat calls.
var collectionSlot = make(chan struct{}, 1)

// Collect reads this process's Linux visibility scope. The supplied observation
// timestamp is trusted. Duration is measured rather than a cancellation promise.
// The caller must not stage/send a result after its own deadline has elapsed.
func Collect(ctx context.Context, now time.Time) Snapshot {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case collectionSlot <- struct{}{}:
	case <-ctx.Done():
		s := Empty(now, ReasonTimeout)
		s.DurationMS = time.Since(started).Milliseconds()
		return s
	}
	defer func() { <-collectionSlot }()
	s := collectPlatform(ctx, now)
	s.DurationMS = time.Since(started).Milliseconds()
	stampGeneration(&s)
	trimSnapshot(&s)
	if Validate(s) != nil {
		fallback := Empty(now, ReasonInvalidSource)
		fallback.DurationMS = s.DurationMS
		return fallback
	}
	return s
}
func limitItems[T any](s *Section[T]) {
	if len(s.Items) > s.Meta.ItemLimit {
		s.Items = s.Items[:s.Meta.ItemLimit]
		partial(&s.Meta, ReasonItemLimit, true)
	}
}

// Drop low-value inventory first, preserving all failed services and severe
// events until ordinary records and lower-RSS processes have been exhausted.
// Ordering inside each provider is deterministic, so tail trimming is stable.
func trimSnapshot(s *Snapshot) {
	for {
		b, err := json.Marshal(s)
		if err == nil && len(b) <= MaxSnapshotBytes {
			return
		}
		v := &s.Sections
		switch {
		case len(v.Software.Items) > 0:
			dropLast(&v.Software)
		case len(v.Services.Items) > 0 && v.Services.Items[len(v.Services.Items)-1].ActiveState != "failed":
			dropLast(&v.Services)
		case len(v.Events.Items) > 0 && v.Events.Items[len(v.Events.Items)-1].Priority > 3:
			dropLast(&v.Events)
		case len(v.Processes.Items) > 0:
			dropLast(&v.Processes)
		case len(v.Network.Items) > 0:
			dropLast(&v.Network)
		case len(v.Volumes.Items) > 0:
			dropLast(&v.Volumes)
		case len(v.Events.Items) > 0:
			dropLast(&v.Events)
		case len(v.Services.Items) > 0:
			dropLast(&v.Services)
		default:
			return
		}
	}
}
func dropLast[T any](s *Section[T]) {
	s.Items = s.Items[:len(s.Items)-1]
	partial(&s.Meta, ReasonByteLimit, true)
	if len(s.Items) == 0 {
		s.Meta.Quality = Unknown
	}
}
