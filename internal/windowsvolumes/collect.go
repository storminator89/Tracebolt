package windowsvolumes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"time"
)

const collectionBudget = 5 * time.Second

// cursor owns a native enumeration handle. All calls are synchronous; context
// cancellation and the budget are checked between calls, never by abandoning a
// goroutine/handle. Windows volume APIs cannot preempt an in-flight OS call.
type cursor interface {
	Next(context.Context) (string, error)
	DriveType(context.Context, string) (string, error)
	Capacity(context.Context, string) (uint64, uint64, uint64, error)
	Close() error
}
type opener func(context.Context) (cursor, error)

func reason(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(err, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(err, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(err, ErrDriveType):
		return ErrDriveType.Error()
	case errors.Is(err, context.Canceled):
		return context.Canceled.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded.Error()
	default:
		return ErrUnavailable.Error()
	}
}
func collectUsing(ctx context.Context, generation string, c Consent, binding string, open opener, now func() time.Time) (Snapshot, error) {
	if ctx == nil || open == nil || now == nil || !validGeneration(generation) {
		return Snapshot{}, ErrInvalid
	}
	if _, err := EncodeConsent(c, binding); err != nil || !c.Enabled {
		return Snapshot{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: c.GrantID, GenerationID: generation, CollectedAt: now().UTC(), Quality: "observed", Complete: true, CountExact: true, Rows: []Volume{}}
	bounded, cancel := context.WithTimeout(ctx, collectionBudget)
	defer cancel()
	fail := func(err error) {
		s.Complete = false
		s.CountExact = false
		s.Reason = reason(err)
		s.Quality = "partial"
		if len(s.Rows) == 0 {
			s.Quality = "unavailable"
			if errors.Is(err, ErrDenied) {
				s.Quality = "denied"
			}
		}
	}
	r, err := open(bounded)
	if err != nil {
		fail(err)
	} else if r == nil {
		fail(ErrUnavailable)
	} else {
		defer r.Close()
		seen := map[string]bool{}
		for len(s.Rows) < MaxNativeRows {
			if err = bounded.Err(); err != nil {
				fail(err)
				break
			}
			var id string
			id, err = r.Next(bounded)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				fail(err)
				break
			}
			if !validVolumeID(id) || seen[id] {
				fail(ErrMetadata)
				break
			}
			seen[id] = true
			v := Volume{VolumeID: id, DriveType: "unknown", Quality: "unavailable", Reason: ErrUnavailable.Error()}
			if err = bounded.Err(); err == nil {
				v.DriveType, err = r.DriveType(bounded, id)
				switch v.DriveType {
				case "fixed", "removable", "cdrom", "ramdisk", "unknown":
				default:
					v.DriveType = "unknown"
					err = ErrDriveType
				}
			}
			if err == nil {
				err = bounded.Err()
			}
			if err == nil {
				var total, free, available uint64
				total, free, available, err = r.Capacity(bounded, id)
				if err == nil {
					if available > total || available > free {
						err = ErrMetadata
					} else {
						v.Capacity = &Capacity{strconv.FormatUint(total, 10), strconv.FormatUint(free, 10), strconv.FormatUint(available, 10)}
						v.Quality = "observed"
						v.Reason = ""
					}
				}
			}
			if err != nil {
				v.Reason = reason(err)
				if errors.Is(err, ErrDenied) {
					v.Quality = "denied"
				}
			}
			s.Rows = append(s.Rows, v)
			if err = bounded.Err(); err != nil {
				fail(err)
				break
			}
			if len(s.Rows) == MaxNativeRows {
				s.Complete = false
				s.CountExact = false
				s.Truncated = true
				s.Quality = "bounded"
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.ObservedCount = uint32(len(s.Rows))
	sort.Slice(s.Rows, func(i, j int) bool { return s.Rows[i].VolumeID < s.Rows[j].VolumeID })
	trim := func() {
		s.Rows = s.Rows[:len(s.Rows)-1]
		s.Complete = false
		s.Truncated = true
		if s.Reason == "" {
			s.Quality = "bounded"
		}
	}
	for len(s.Rows) > MaxRows {
		trim()
	}
	for {
		b, e := json.Marshal(s)
		if e != nil {
			return Snapshot{}, ErrInvalid
		}
		if len(b) <= MaxBytes {
			break
		}
		if len(s.Rows) == 0 {
			return Snapshot{}, ErrInvalid
		}
		trim()
	}
	if err = Validate(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
