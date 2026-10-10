package windowsprocessmetrics

import (
	"context"
	"errors"
	"math"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

const collectionBudget = 5 * time.Second

// reader is injectable. Its implementation opens only this PID, closes its
// handle synchronously, and checks context between native calls.
// Reading is a single PID observation; times are native FILETIME 100ns ticks.
// It is exported solely for synthetic source/pipeline tests and adapters.
type Reading struct {
	Creation, Kernel, User, Memory uint64
	CPUErr, MemoryErr              error
}
type reading = Reading
type reader func(context.Context, uint32) reading
type baseline struct {
	creation, kernel, user uint64
	at                     time.Time
}
type Sampler struct {
	mu       sync.Mutex
	read     reader
	now      func() time.Time
	cores    uint32
	previous map[uint32]baseline
	grant    string
	captured time.Time
}

func NewSampler() *Sampler {
	return &Sampler{read: readNative, now: time.Now, cores: uint32(runtime.NumCPU()), previous: map[uint32]baseline{}}
}

// NewSamplerWithReader permits deterministic fixtures without native reads.
func NewSamplerWithReader(read func(context.Context, uint32) Reading, now func() time.Time, cores uint32) *Sampler {
	return &Sampler{read: read, now: now, cores: cores, previous: map[uint32]baseline{}}
}

// Reset discards interval identity and counters on consent disable/replacement.
// It does not query processes or change any external state.
func (s *Sampler) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previous = map[uint32]baseline{}
	s.grant = ""
	s.captured = time.Time{}
}

func quality(e error) string {
	if errors.Is(e, ErrDenied) {
		return "denied"
	}
	return "unavailable"
}

// inventoryAt is the original inventory capture, not the metric sample time.
// Sample requires an active grant already checked by the caller. It never
// enumerates PIDs. Callers must discard this sampler when scope is disabled.
// A first sample is null CPU; later values divide CPU time by elapsed wall time,
// never by processor count. No goroutine abandons an in-flight native call.
func (s *Sampler) Sample(ctx context.Context, pids []uint32, generation, grant string, inventoryAt time.Time) (Snapshot, error) {
	return s.sample(ctx, pids, generation, grant, inventoryAt, 0)
}

// SampleWithSelfPID samples an already-inventoried local self PID first, within
// the same cooperative budget, and protects that row from byte trimming. It
// never adds a PID, read or right; absent self keeps the ordinary sampling order.
// Like Sample, it requires the caller to have validated active process consent.
func (s *Sampler) SampleWithSelfPID(ctx context.Context, pids []uint32, generation, grant string, inventoryAt time.Time, selfPID uint32) (Snapshot, error) {
	return s.sample(ctx, pids, generation, grant, inventoryAt, selfPID)
}

func (s *Sampler) sample(ctx context.Context, pids []uint32, generation, grant string, inventoryAt time.Time, selfPID uint32) (Snapshot, error) {
	if s == nil || ctx == nil || len(pids) > MaxRows || !validGeneration(generation) || !hex(grant, 32) || inventoryAt.IsZero() || inventoryAt.Location() != time.UTC || inventoryAt.Year() < 1970 || inventoryAt.Year() > 9999 {
		return Snapshot{}, ErrInvalid
	}
	ids := append([]uint32{}, pids...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return Snapshot{}, ErrInvalid
		}
	}
	if selfPID != 0 {
		for i, pid := range ids {
			if pid == selfPID {
				copy(ids[1:i+1], ids[:i])
				ids[0] = selfPID
				break
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.read == nil || s.now == nil || s.cores == 0 {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if s.grant != grant {
		s.previous = map[uint32]baseline{}
		s.captured = time.Time{}
	}
	reset := !s.captured.IsZero() && !inventoryAt.After(s.captured)
	sampleAt := s.now().UTC()
	out := Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: grant, GenerationID: generation, CollectedAt: sampleAt, ObservedCount: uint32(len(ids)), Rows: []Process{}}
	next := map[uint32]baseline{}
	bounded, cancel := context.WithTimeout(ctx, collectionBudget)
	defer cancel()
	for _, pid := range ids {
		r := Process{PID: pid, CPUQuality: "unavailable", MemoryQuality: "unavailable"}
		if bounded.Err() == nil {
			n := s.read(bounded, pid)
			at := s.now()
			// Creation cannot postdate the inventory capture: PID could have been
			// reused after metadata enumeration. A failed identity read also blocks RAM.
			inventoryTicks := uint64(inventoryAt.Unix())*10000000 + 116444736000000000 + uint64(inventoryAt.Nanosecond()/100)
			if n.CPUErr != nil || n.Creation == 0 || n.Creation > inventoryTicks {
				e := n.CPUErr
				if e == nil {
					e = ErrUnavailable
				}
				n.CPUErr = e
				n.MemoryErr = e
			}
			if n.CPUErr != nil {
				r.CPUQuality = quality(n.CPUErr)
			} else if n.Creation != 0 {
				r.CPUQuality = "first-sample"
				prev, ok := s.previous[pid]
				if reset || ok && (prev.creation != n.Creation || n.Kernel < prev.kernel || n.User < prev.user || !at.After(prev.at)) {
					r.CPUQuality = "reset"
				} else if ok {
					elapsed := at.Sub(prev.at).Seconds()
					cpu := (float64(n.Kernel-prev.kernel) + float64(n.User-prev.user)) / 1e7 / elapsed * 100
					if !math.IsNaN(cpu) && !math.IsInf(cpu, 0) && cpu >= 0 && cpu <= float64(s.cores)*100 {
						cpu = math.Round(cpu*100) / 100
						r.CPUPercent = &cpu
						r.CPUQuality = "observed"
					} else {
						r.CPUQuality = "reset"
					}
				}
				next[pid] = baseline{n.Creation, n.Kernel, n.User, at}
			}
			if n.MemoryErr != nil {
				r.MemoryQuality = quality(n.MemoryErr)
			} else {
				v := strconv.FormatUint(n.Memory, 10)
				r.MemoryBytes = &v
				r.MemoryQuality = "observed"
			}
		}
		out.Rows = append(out.Rows, r)
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	// Read priority is local only; the wire remains strictly PID-sorted.
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].PID < out.Rows[j].PID })
	result, e := fitWithSelfPID(out, MaxBytes, selfPID)
	if e != nil {
		return Snapshot{}, e
	}
	s.previous = next
	s.grant = grant
	s.captured = inventoryAt
	return result, nil
}
