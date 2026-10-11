package windowsstorageio

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

type fakeClock struct {
	at        time.Time
	waits     []time.Duration
	shorten   bool
	afterWait func()
}

func (c *fakeClock) now() time.Time { return c.at }
func (c *fakeClock) wait(ctx context.Context, d time.Duration) error {
	c.waits = append(c.waits, d)
	if c.shorten {
		d = time.Millisecond
	}
	c.at = c.at.Add(d)
	if c.afterWait != nil {
		c.afterWait()
	}
	return ctx.Err()
}

type fakeQuery struct {
	adds                      []int
	collects, formats, closes int
	addStatus                 [8]uint32
	collectStatus             [2]uint32
	formatStatus              [8]uint32
	values                    [8]formattedValue
	onCollect                 func(int)
}

func (q *fakeQuery) add(i int) uint32 { q.adds = append(q.adds, i); return q.addStatus[i] }
func (q *fakeQuery) collect() uint32 {
	n := q.collects
	q.collects++
	if q.onCollect != nil {
		q.onCollect(n)
	}
	return q.collectStatus[n]
}
func (q *fakeQuery) formatted(i int) (uint32, formattedValue) {
	q.formats++
	return q.formatStatus[i], q.values[i]
}
func (q *fakeQuery) close() { q.closes++ }
func fakeSources() (*fakeQuery, *fakeClock) {
	q := &fakeQuery{}
	for i := range q.values {
		q.values[i] = formattedValue{CStatus: pdhValidData, DoubleValue: float64(i + 1)}
	}
	return q, &fakeClock{at: requestFixture().CollectedAt}
}
func TestFixedEnglishPathsAndABI(t *testing.T) {
	want := [8]string{`\PhysicalDisk(_Total)\Disk Read Bytes/sec`, `\PhysicalDisk(_Total)\Disk Write Bytes/sec`, `\PhysicalDisk(_Total)\Disk Reads/sec`, `\PhysicalDisk(_Total)\Disk Writes/sec`, `\PhysicalDisk(_Total)\Avg. Disk sec/Read`, `\PhysicalDisk(_Total)\Avg. Disk sec/Write`, `\PhysicalDisk(_Total)\Avg. Disk Queue Length`, `\PhysicalDisk(_Total)\Current Disk Queue Length`}
	if counterPaths != want || pdhFormat != 0x9200 {
		t.Fatal("allowlist/format flags changed")
	}
	for _, p := range counterPaths {
		if strings.Contains(p, "*") || strings.HasPrefix(p, `\\`) {
			t.Fatal("wildcard or remote source")
		}
	}
	var v formattedValue
	if unsafe.Sizeof(v) != 16 || unsafe.Offsetof(v.CStatus) != 0 || unsafe.Offsetof(v.DoubleValue) != 8 {
		t.Fatal("PDH_FMT_COUNTERVALUE ABI")
	}
}
func TestTwoSampleFixedReadAndClose(t *testing.T) {
	q, c := fakeSources()
	p, e := collectPDH(context.Background(), q, c)
	if e != nil || !validPerfDisk(p) || p.Quality != "observed" || q.collects != 2 || q.formats != 8 || q.closes != 1 || !reflect.DeepEqual(q.adds, []int{0, 1, 2, 3, 4, 5, 6, 7}) || !reflect.DeepEqual(c.waits, []time.Duration{time.Second}) || *p.IntervalMilliseconds != 1000 {
		t.Fatalf("wrong collection: %+v %v", p, e)
	}
}
func TestFunctionAndCounterStatusBothRequired(t *testing.T) {
	for _, tc := range []struct {
		name            string
		status, cstatus uint32
		value           float64
		reason          string
	}{
		{"denied", pdhAccessDenied, 0, 9, ErrDenied.Error()},
		{"win32 denied", 5, 0, 9, ErrDenied.Error()},
		{"missing object", pdhNoObject, 0, 9, ErrMissing.Error()},
		{"missing instance output", pdhInvalidData, pdhNoInstance, 9, ErrMissing.Error()},
		{"success missing", 0, pdhNoInstance, 9, ErrMissing.Error()},
		{"reset status", pdhNegativeValue, 0, 9, ErrReset.Error()},
		{"reset output", 0, pdhNegativeDenominator, 9, ErrReset.Error()},
		{"timebase", 0, pdhNegativeTimebase, 9, ErrTimebase.Error()},
		{"bad generic output", pdhInvalidData, 0, 9, ErrMetadata.Error()},
		{"bad function valid output", 0xffffffff, pdhNewData, 9, ErrUnavailable.Error()},
		{"unvalidated", 0, 0x800007D3, 9, ErrUnavailable.Error()},
		{"unknown", 0, 0xffffffff, 9, ErrUnavailable.Error()},
		{"nan", 0, 0, math.NaN(), ErrMetadata.Error()},
		{"infinity", 0, 0, math.Inf(1), ErrMetadata.Error()},
		{"negative", 0, 0, -1, ErrReset.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := formattedMetric(tc.status, formattedValue{CStatus: tc.cstatus, DoubleValue: tc.value})
			if m.Value != nil || m.Reason != tc.reason || m.Quality != unavailableQuality(tc.reason) {
				t.Fatalf("bad status %+v", m)
			}
		})
	}
	for _, status := range []uint32{pdhValidData, pdhNewData} {
		m := formattedMetric(0, formattedValue{CStatus: status, DoubleValue: 12345.67})
		if m.Value == nil || *m.Value != 12345.67 || m.Quality != "observed" {
			t.Fatal("valid uncapped value lost")
		}
	}
	zero := formattedMetric(0, formattedValue{DoubleValue: math.Copysign(0, -1)})
	if zero.Value == nil || math.Signbit(*zero.Value) {
		t.Fatal("zero not normalized")
	}
}
func TestPartialStatusAndIdleLatencies(t *testing.T) {
	q, c := fakeSources()
	q.addStatus[0] = pdhAccessDenied
	q.values[1].CStatus = pdhNoInstance
	q.values[2].DoubleValue = 0
	q.values[3].CStatus = pdhNoCounter
	p, e := collectPDH(context.Background(), q, c)
	if e != nil || p.Quality != "partial" || p.ReadBytesPerSecond.Reason != ErrDenied.Error() || p.WriteBytesPerSecond.Reason != ErrMissing.Error() || p.ReadLatencySeconds.Reason != ErrIdle.Error() || p.ReadLatencySeconds.Value != nil || p.WriteLatencySeconds.Reason != ErrUnavailable.Error() || p.WriteLatencySeconds.Value != nil || p.CurrentQueueLength.Value == nil || q.formats != 7 || q.closes != 1 {
		t.Fatalf("partial meanings: %+v %v", p, e)
	}
}
func TestAllCounterAddFailuresSkipSampling(t *testing.T) {
	q, c := fakeSources()
	for i := range q.addStatus {
		q.addStatus[i] = pdhNoObject
	}
	p, e := collectPDH(context.Background(), q, c)
	if e != nil || p.Quality != "unavailable" || p.Reason != ErrMissing.Error() || p.SampleStartedAt != nil || q.collects != 0 || q.formats != 0 || q.closes != 1 || len(c.waits) != 0 {
		t.Fatal("missing counter sampling")
	}
}
func TestCollectFailuresAreExplicitAndAlwaysClose(t *testing.T) {
	for index := 0; index < 2; index++ {
		for _, status := range []uint32{pdhNoData, pdhAccessDenied, pdhNegativeTimebase} {
			q, c := fakeSources()
			q.collectStatus[index] = status
			_, e := collectPDH(context.Background(), q, c)
			if e != pdhError(status) || q.formats != 0 || q.closes != 1 {
				t.Fatal("query failure not closed")
			}
		}
	}
}
func TestTooShortOrUnusableIntervalsNeverYieldValues(t *testing.T) {
	q, c := fakeSources()
	c.at = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, e := collectPDH(ctx, q, c)
	if e != ErrBudget || q.collects != 0 || q.closes != 1 {
		t.Fatal("short budget sampled")
	}
	q, c = fakeSources()
	c.shorten = true
	_, e = collectPDH(context.Background(), q, c)
	if e != ErrTimebase || q.formats != 0 || q.closes != 1 {
		t.Fatal("short interval formatted")
	}
	q, c = fakeSources()
	q.onCollect = func(n int) {
		if n == 1 {
			c.at = c.at.Add(2 * time.Second)
		}
	}
	_, e = collectPDH(context.Background(), q, c)
	if e != ErrTimebase || q.formats != 0 || q.closes != 1 {
		t.Fatal("over-budget interval formatted")
	}
	q, c = fakeSources()
	ctx, cancel = context.WithCancel(context.Background())
	c.afterWait = cancel
	_, e = collectPDH(ctx, q, c)
	if e != context.Canceled || q.collects != 1 || q.formats != 0 || q.closes != 1 {
		t.Fatal("canceled wait sampled")
	}
	q, c = fakeSources()
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, e = collectPDH(ctx, q, c)
	if e != context.Canceled || len(q.adds) != 0 || q.closes != 1 {
		t.Fatal("canceled collection leaked query")
	}
}
