package windowsstorageio

import (
	"context"
	"math"
	"time"
)

// Exact allowlist; no machine prefix, wildcard, per-device instance, dynamic
// input, enumeration or counter-enable path is accepted.
var counterPaths = [8]string{
	`\PhysicalDisk(_Total)\Disk Read Bytes/sec`,
	`\PhysicalDisk(_Total)\Disk Write Bytes/sec`,
	`\PhysicalDisk(_Total)\Disk Reads/sec`,
	`\PhysicalDisk(_Total)\Disk Writes/sec`,
	`\PhysicalDisk(_Total)\Avg. Disk sec/Read`,
	`\PhysicalDisk(_Total)\Avg. Disk sec/Write`,
	`\PhysicalDisk(_Total)\Avg. Disk Queue Length`,
	`\PhysicalDisk(_Total)\Current Disk Queue Length`,
}

// Constants/typedefs independently checked against Microsoft SDK Pdh.h:
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Pdh.h
const pdhFmtDouble uint32 = 0x200
const pdhFmtNoScale uint32 = 0x1000
const pdhFmtNoCap100 uint32 = 0x8000
const pdhFormat = pdhFmtDouble | pdhFmtNoScale | pdhFmtNoCap100
const pdhValidData uint32 = 0
const pdhNewData uint32 = 1
const pdhNoInstance uint32 = 0x800007D1
const pdhNoData uint32 = 0x800007D5
const pdhNegativeDenominator uint32 = 0x800007D6
const pdhNegativeTimebase uint32 = 0x800007D7
const pdhNegativeValue uint32 = 0x800007D8
const pdhNoObject uint32 = 0xC0000BB8
const pdhNoCounter uint32 = 0xC0000BB9
const pdhInvalidData uint32 = 0xC0000BC6
const pdhCounterInvalidData uint32 = 0xC0000BBA
const pdhAccessDenied uint32 = 0xC0000BDB

// PDH_FMT_COUNTERVALUE: DWORD CStatus, four padding bytes, then the 8-byte
// union holding a DOUBLE. Explicit padding preserves the Windows ABI on386 too.
// Never interpret the union as a pointer/string. Assert offsets in native tests.
// https://learn.microsoft.com/en-us/windows/win32/api/pdh/ns-pdh-pdh_fmt_countervalue
type formattedValue struct {
	CStatus     uint32
	_           uint32
	DoubleValue float64
}

// Portable fake seam for deterministic algorithm/status/deadline testing.
// Only the native implementation owns handles, and this interface is private.
type pdhQuery interface {
	add(index int) uint32
	collect() uint32
	formatted(index int) (uint32, formattedValue)
	close()
}
type sampleClock interface {
	now() time.Time
	wait(context.Context, time.Duration) error
}
type realClock struct{}

func (realClock) now() time.Time { return time.Now() }
func (realClock) wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// PDH function status and counter CStatus are distinct. Native return values are
// DWORD status codes, not GetLastError. Missing/reset/timebase are not zeros.
// https://learn.microsoft.com/en-us/windows/win32/perfctrs/pdh-error-codes
func pdhError(status uint32) error {
	switch status {
	case 0:
		return nil
	case 5, pdhAccessDenied:
		return ErrDenied
	case pdhNoInstance, pdhNoObject, pdhNoCounter, pdhNoData:
		return ErrMissing
	case pdhNegativeValue, pdhNegativeDenominator:
		return ErrReset
	case pdhNegativeTimebase:
		return ErrTimebase
	case pdhCounterInvalidData, pdhInvalidData:
		return ErrMetadata
	case 0x800007DB, 0xC0000BFE:
		return ErrBudget
	default:
		return ErrUnavailable
	}
}
func formattedMetric(status uint32, v formattedValue) Metric {
	// PDH_INVALID_DATA can accompany the more specific NO_INSTANCE CStatus.
	// For any other failed function do not trust possibly untouched output data.
	if status != 0 {
		if status == pdhInvalidData && v.CStatus != pdhValidData && v.CStatus != pdhNewData {
			return EmptyMetric(SafeReason(pdhError(v.CStatus)))
		}
		return EmptyMetric(SafeReason(pdhError(status)))
	}
	if v.CStatus != pdhValidData && v.CStatus != pdhNewData {
		return EmptyMetric(SafeReason(pdhError(v.CStatus)))
	}
	if math.IsNaN(v.DoubleValue) || math.IsInf(v.DoubleValue, 0) {
		return EmptyMetric(ErrMetadata.Error())
	}
	if v.DoubleValue < 0 {
		return EmptyMetric(ErrReset.Error())
	}
	value := v.DoubleValue
	if value == 0 {
		value = 0
	} // Normalize native negative zero; wire accepts canonical zero.
	return Metric{Value: &value, Quality: "observed"}
}
func normalizeLatency(p *PerfDisk) {
	for _, pair := range [][2]*Metric{{&p.ReadOperationsPerSecond, &p.ReadLatencySeconds}, {&p.WriteOperationsPerSecond, &p.WriteLatencySeconds}} {
		ops, latency := pair[0], pair[1]
		if ops.Quality == "observed" && *ops.Value == 0 {
			*latency = EmptyMetric(ErrIdle.Error())
		} else if ops.Quality != "observed" && latency.Quality == "observed" {
			*latency = EmptyMetric(ErrUnavailable.Error())
		}
	}
}

// Two query collections with at least one full second after first completion.
// Times are local call-completion timestamps, not an atomic provider capture or
// proof that PhysicalDisk(_Total) contains the same disks at both samples.
// A material monotonic-vs-wall discrepancy is rejected instead of inventing an
// interval; sub-millisecond clock-read skew and ordinary slew are tolerated.
// https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data
func collectPDH(ctx context.Context, q pdhQuery, clock sampleClock) (PerfDisk, error) {
	if ctx == nil || q == nil || clock == nil {
		return PerfDisk{}, ErrInvalid
	}
	defer q.close()
	if e := ctx.Err(); e != nil {
		return PerfDisk{}, e
	}
	p := EmptyPerfDisk(ErrUnavailable.Error())
	fields := metricPointers(&p)
	var added [8]bool
	count := 0
	for i := range counterPaths {
		if e := ctx.Err(); e != nil {
			return PerfDisk{}, e
		}
		if e := pdhError(q.add(i)); e != nil {
			*fields[i] = EmptyMetric(SafeReason(e))
		} else {
			added[i] = true
			count++
		}
	}
	if count == 0 {
		summarize(&p)
		return p, nil
	}
	// Never start a knowingly too-short interval, even if process startup or
	// counter binding consumed part of the parent's clipped budget.
	if deadline, ok := ctx.Deadline(); ok && deadline.Sub(clock.now()) <= MinSampleInterval {
		return PerfDisk{}, ErrBudget
	}
	if e := pdhError(q.collect()); e != nil {
		return PerfDisk{}, e
	}
	started := clock.now()
	if deadline, ok := ctx.Deadline(); ok && deadline.Sub(started) <= MinSampleInterval {
		return PerfDisk{}, ErrBudget
	}
	if e := clock.wait(ctx, MinSampleInterval); e != nil {
		return PerfDisk{}, e
	}
	if e := ctx.Err(); e != nil {
		return PerfDisk{}, e
	}
	if e := pdhError(q.collect()); e != nil {
		return PerfDisk{}, e
	}
	ended := clock.now()
	elapsed := ended.Sub(started)
	wallStarted, wallEnded := started.UTC(), ended.UTC()
	wallElapsed := wallEnded.Sub(wallStarted)
	skew := wallElapsed - elapsed
	if elapsed < MinSampleInterval || elapsed > ProviderBudget || wallElapsed < MinSampleInterval || wallElapsed > ProviderBudget || skew > 10*time.Millisecond || skew < -10*time.Millisecond {
		return PerfDisk{}, ErrTimebase
	}
	ms := uint64(wallElapsed.Milliseconds())
	p.SampleStartedAt = &wallStarted
	p.SampleEndedAt = &wallEnded
	p.IntervalMilliseconds = &ms
	for i := range counterPaths {
		if e := ctx.Err(); e != nil {
			return PerfDisk{}, e
		}
		if added[i] {
			status, v := q.formatted(i)
			*fields[i] = formattedMetric(status, v)
		}
	}
	normalizeLatency(&p)
	summarize(&p)
	if !validPerfDisk(p) {
		return PerfDisk{}, ErrMetadata
	}
	return p, nil
}
