package windowsresourcecontext

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
)

type ProcessorsSource func(context.Context) (Processors, error)
type InstalledMemorySource func(context.Context) (InstalledMemory, error)
type MemorySource func(context.Context) (Memory, error)
type PagefilesSource func(context.Context) (Pagefiles, error)

func CollectWithSources(ctx context.Context, r Request, processors ProcessorsSource, installed InstalledMemorySource, memory MemorySource, pagefiles PagefilesSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if processors != nil {
		v, e := processors(ctx)
		if e != nil {
			v = EmptyProcessors(SafeReason(e))
		}
		if !validProcessors(v) {
			v = EmptyProcessors(ErrMetadata.Error())
		}
		s.Processors = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if installed != nil {
		v, e := installed(ctx)
		if e != nil {
			v = EmptyInstalledMemory(SafeReason(e))
		}
		if !validInstalledMemory(v) {
			v = EmptyInstalledMemory(ErrMetadata.Error())
		}
		s.InstalledMemory = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if memory != nil {
		v, e := memory(ctx)
		if e != nil {
			v = EmptyMemory(SafeReason(e))
		}
		if !validMemory(v) {
			v = EmptyMemory(ErrMetadata.Error())
		}
		s.Memory = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if pagefiles != nil {
		v, e := pagefiles(ctx)
		if e != nil {
			v = EmptyPagefiles(SafeReason(e))
		}
		if !validPagefiles(v) {
			v = EmptyPagefiles(ErrMetadata.Error())
		}
		s.Pagefiles = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	// The row and UTF-16 limits are not substitutes for the escaped JSON bound.
	// Discard the whole CPU source if necessary; never publish a prefix as complete.
	if raw, e := json.Marshal(s); e != nil {
		return Snapshot{}, ErrInvalid
	} else if len(raw) > MaxBytes {
		s.Processors = EmptyProcessors(ErrBounds.Error())
	}
	return s, Validate(s)
}
func SafeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}
func emptyField(reason string) Field { return Field{Quality: unavailableQuality(reason)} }
func observedField(value string, e error) Field {
	if e != nil {
		return emptyField(SafeReason(e))
	}
	if value == "" {
		return Field{Quality: "empty"}
	}
	if !validLabel(value, MaxStringUnits) {
		return emptyField(ErrMetadata.Error())
	}
	return Field{&value, "observed"}
}
func countField(value uint32, e error) CountField {
	if e != nil {
		return CountField{Quality: unavailableQuality(SafeReason(e))}
	}
	if value == 0 || value > MaxProcessorCount {
		return CountField{Quality: "unavailable"}
	}
	return CountField{&value, "observed"}
}
func architectureField(value uint32, e error) Field {
	if e != nil {
		return emptyField(SafeReason(e))
	}
	var s string
	switch value {
	case 0:
		s = "x86"
	case 1:
		s = "MIPS"
	case 2:
		s = "Alpha"
	case 3:
		s = "PowerPC"
	case 5:
		s = "ARM"
	case 6:
		s = "ia64"
	case 9:
		s = "x64"
	case 12:
		s = "ARM64"
	default:
		return emptyField(ErrMetadata.Error())
	}
	return Field{&s, "observed"}
}
func finishProcessors(rows []Processor) (Processors, error) {
	if len(rows) == 0 {
		return Processors{}, ErrUnavailable
	}
	if len(rows) > MaxProcessors {
		return Processors{}, ErrBounds
	}
	p := Processors{Quality: "observed", Source: "Win32_Processor", Rows: rows}
	var cores, logical uint32
	complete := true
	for _, r := range rows {
		if r.Name.Quality == "denied" || r.Name.Quality == "unavailable" || r.Architecture.Quality != "observed" || r.Cores.Quality != "observed" || r.LogicalProcessors.Quality != "observed" {
			p.Quality = "partial"
			p.Reason = ErrPartial.Error()
		}
		if r.Cores.Value == nil || r.LogicalProcessors.Value == nil {
			complete = false
		} else {
			cores += *r.Cores.Value
			logical += *r.LogicalProcessors.Value
		}
	}
	if complete {
		p.TotalCores = &cores
		p.TotalLogicalProcessors = &logical
	}
	if !validProcessors(p) {
		return Processors{}, ErrMetadata
	}
	return p, nil
}
func bytesValue(n uint64) *string { s := strconv.FormatUint(n, 10); return &s }
func multiply(a, b uint64) (uint64, error) {
	if b == 0 || a > ^uint64(0)/b {
		return 0, ErrMetadata
	}
	return a * b, nil
}
func installedMemoryFromKB(kb uint64) (InstalledMemory, error) {
	n, e := multiply(kb, 1024)
	if e != nil || n == 0 {
		return InstalledMemory{}, ErrMetadata
	}
	return InstalledMemory{Quality: "observed", Source: "GetPhysicallyInstalledSystemMemory", InstalledBytes: bytesValue(n)}, nil
}
func memoryFromPages(commitTotal, commitLimit, physicalTotal, physicalAvailable, pageSize uint64) (Memory, error) {
	if !validPageSize(pageSize) {
		return Memory{}, ErrMetadata
	}
	values := []uint64{commitTotal, commitLimit, physicalTotal, physicalAvailable}
	var result [4]*string
	for i, n := range values {
		v, e := multiply(n, pageSize)
		if e != nil {
			return Memory{}, e
		}
		result[i] = bytesValue(v)
	}
	m := Memory{Quality: "observed", Source: "K32GetPerformanceInfo", CommitTotalBytes: result[0], CommitLimitBytes: result[1], PhysicalTotalBytes: result[2], PhysicalAvailableBytes: result[3], PageSizeBytes: bytesValue(pageSize)}
	if !validMemory(m) {
		return Memory{}, ErrMetadata
	}
	return m, nil
}

// Only three non-identifying scalars enter this portable aggregation seam.
// Partial enumeration, overflow and callback cutoff discard all totals.
type pagefileAccumulator struct {
	count       uint32
	total, used uint64
	err         error
}

func (a *pagefileAccumulator) add(total, used uint64) bool {
	if a.err != nil {
		return false
	}
	if a.count >= MaxPagefiles {
		a.err = ErrBounds
		return false
	}
	if total == 0 || used > total || a.total > ^uint64(0)-total || a.used > ^uint64(0)-used {
		a.err = ErrMetadata
		return false
	}
	a.count++
	a.total += total
	a.used += used
	return true
}
func (a *pagefileAccumulator) finish(complete bool, pageSize uint64) (Pagefiles, error) {
	if a.err != nil {
		return Pagefiles{}, a.err
	}
	if !complete {
		return Pagefiles{}, ErrPartial
	}
	if !validPageSize(pageSize) {
		return Pagefiles{}, ErrMetadata
	}
	total, e := multiply(a.total, pageSize)
	if e != nil {
		return Pagefiles{}, e
	}
	used, e := multiply(a.used, pageSize)
	if e != nil {
		return Pagefiles{}, e
	}
	count := a.count
	p := Pagefiles{Quality: "observed", Source: "EnumPageFilesW", Count: &count, TotalBytes: bytesValue(total), TotalInUseBytes: bytesValue(used)}
	if !validPagefiles(p) {
		return Pagefiles{}, ErrMetadata
	}
	return p, nil
}
