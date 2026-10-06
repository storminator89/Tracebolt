package completeoverview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testID = "sample_0123456789abcdef0123456789abcdef"

var testAt = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// All provider bytes below are generated fixtures. No test calls Collect or the
// production provider, reads procfs, runs a command or contacts a host/network.
type fixtureProvider struct {
	count        int
	enumErr      error
	statErr      map[uint32]error
	statData     map[uint32]string
	mountData    string
	measurements func([]MountRecord) ([]MountMeasurement, error)
	started      chan struct{}
	release      chan struct{}
	closed       atomic.Bool
	statCalls    atomic.Int32
}

func (p *fixtureProvider) EnumeratePIDs(ctx context.Context, visit func(uint32) error) error {
	if p.started != nil {
		close(p.started)
		<-p.release
	}
	for i := 1; i <= p.count; i++ {
		if e := visit(uint32(i)); e != nil {
			return e
		}
	}
	return p.enumErr
}
func (p *fixtureProvider) ProcessUnits(context.Context) (uint64, uint64, error) {
	return 4096, 100, nil
}
func (p *fixtureProvider) OpenProcessStat(_ context.Context, pid uint32) (io.ReadCloser, error) {
	p.statCalls.Add(1)
	if e := p.statErr[pid]; e != nil {
		return nil, e
	}
	raw, ok := p.statData[pid]
	if !ok {
		raw = statFixture(pid, "fixture worker")
	}
	return io.NopCloser(strings.NewReader(raw)), nil
}
func (p *fixtureProvider) OpenMountInfo(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(p.mountData)), nil
}
func (p *fixtureProvider) MeasureMounts(_ context.Context, m []MountRecord) ([]MountMeasurement, error) {
	if p.measurements != nil {
		return p.measurements(m)
	}
	rows := []MountMeasurement{}
	for _, r := range m {
		if k := mountKind(r.Filesystem); k == "local" || k == "memory" {
			rows = append(rows, MountMeasurement{MountID: r.MountID, Capacity: &Capacity{1000, 250}, Observation: Observation{Observed, ReasonNone}})
		}
	}
	return rows, nil
}
func (p *fixtureProvider) Close() error { p.closed.Store(true); return nil }
func statFixture(pid uint32, name string) string {
	fields := make([]string, 50)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = "1"
	fields[11] = "123"
	fields[12] = "77"
	fields[17] = "3"
	fields[21] = "8"
	return fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))
}
func mountFixture(n int, fs string) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "%d 999 0:%d / /fixture/%05d rw - %s none rw\n", i, i, i, fs)
	}
	return b.String()
}
func runFixture(t *testing.T, p *fixtureProvider) Snapshot {
	t.Helper()
	s, e := CollectWithProvider(context.Background(), testID, testAt, p)
	if e != nil {
		t.Fatal(e)
	}
	if e = Validate(s); e != nil {
		t.Fatal(e)
	}
	if !p.closed.Load() {
		t.Fatal("provider was not closed")
	}
	return s
}
func assertFailed[T any](t *testing.T, s Section[T], reason Reason) {
	t.Helper()
	if s.Meta.Coverage != Failed || s.Meta.Reason != reason || len(s.Items) != 0 || s.Meta.CountExact || s.Meta.ObservedCount != nil || s.Meta.FieldCoverage != (FieldCoverage{}) {
		t.Fatalf("failed capture retained a prefix: %+v", s.Meta)
	}
}

func TestCompleteBeyondPreviewLimitsAndRootLast(t *testing.T) {
	p := &fixtureProvider{count: 97, mountData: mountFixture(32, "proc") + "100 999 8:1 / / rw - ext4 /dev/fixture rw\n"}
	s := runFixture(t, p)
	if s.Processes.Meta.Coverage != Complete || len(s.Processes.Items) != 97 || *s.Processes.Meta.ObservedCount != 97 || s.Processes.Meta.FieldCoverage.Observed != 97 {
		t.Fatal("process preview truncation")
	}
	if s.Volumes.Meta.Coverage != Complete || len(s.Volumes.Items) != 33 || *s.Volumes.Meta.ObservedCount != 33 || s.Volumes.Items[0].MountPoint != "/" || s.Volumes.Items[0].Measurement.Status != Observed || s.Volumes.Meta.FieldCoverage.NotApplicable != 32 {
		t.Fatal("virtual rows displaced root or were truncated")
	}
	for _, v := range s.Volumes.Items[1:] {
		if v.TotalBytes != nil || v.AvailableBytes != nil || v.UsedPercent != nil || v.Measurement.Status != NotApplicable {
			t.Fatal("pseudo capacity fabricated")
		}
	}
	if s.CaptureStartedAt != testAt || s.CaptureFinishedAt.Before(testAt) || s.Scope != SnapshotScope {
		t.Fatal("interval or namespace lost")
	}
}
func TestCompleteEnumerationSeparatesRowFailures(t *testing.T) {
	unknown := strings.Replace(statFixture(5, "fixture"), ") S ", ") ? ", 1)
	p := &fixtureProvider{count: 6, statErr: map[uint32]error{2: SourceError{ReasonPermissionDenied}, 3: SourceError{ReasonProcessGone}, 6: SourceError{ReasonReadFailed}}, statData: map[uint32]string{4: "invalid", 5: unknown}}
	s := runFixture(t, p)
	m := s.Processes.Meta
	if m.Coverage != Complete || m.Reason != ReasonNone || !m.CountExact || *m.ObservedCount != 6 || m.FieldCoverage != (FieldCoverage{Observed: 1, Denied: 1, Exited: 1, Invalid: 1, Unsupported: 1, Unavailable: 1}) {
		t.Fatalf("row coverage hidden: %+v", m)
	}
	for i, row := range s.Processes.Items {
		if row.PID != uint32(i+1) {
			t.Fatal("PID dropped")
		}
		if i > 0 && (row.Name != nil || row.RSSBytes != nil || row.CPUTimeSeconds != nil) {
			t.Fatal("stale details after failure")
		}
	}
}
func TestAllMountClassesAndBindGrouping(t *testing.T) {
	p := &fixtureProvider{mountData: "1 9 8:1 / / rw - ext4 dev rw\n2 9 8:1 /sub /bind rw - ext4 dev rw\n3 9 0:3 / /mem rw - tmpfs none rw\n4 9 0:4 / /net rw - nfs host:/share rw\n5 9 0:5 / /unknown rw - mystery none rw\n6 9 0:6 / /proc rw - proc none rw\n"}
	s := runFixture(t, p)
	v := s.Volumes.Items
	if len(v) != 6 || v[0].FilesystemGroup != v[1].FilesystemGroup || v[2].Kind != "memory" || v[2].CapacityScope != "agent-mount-namespace" || v[3].Measurement.Reason != ReasonRemoteFilesystemSkipped || v[4].Kind != "unknown" || v[5].Measurement.Status != NotApplicable {
		t.Fatal("capacity kinds or bind groups lost")
	}
}
func TestRejectEnumerationErrorsAndSourceCeilingsWithoutPrefixes(t *testing.T) {
	s := runFixture(t, &fixtureProvider{count: 3, enumErr: SourceError{ReasonPermissionDenied}})
	assertFailed(t, s.Processes, ReasonPermissionDenied)
	s = runFixture(t, &fixtureProvider{count: MaxProcessRows + 1})
	assertFailed(t, s.Processes, ReasonItemLimit)
	s = runFixture(t, &fixtureProvider{mountData: mountFixture(MaxVolumeRows+1, "proc")})
	assertFailed(t, s.Volumes, ReasonItemLimit)
	s = runFixture(t, &fixtureProvider{mountData: mountFixture(33, "proc") + "broken\n"})
	assertFailed(t, s.Volumes, ReasonInvalidSource)
	s = runFixture(t, &fixtureProvider{count: 2, statData: map[uint32]string{2: strings.Repeat("x", MaxProcessStatBytes+1)}})
	assertFailed(t, s.Processes, ReasonByteLimit)
	s = runFixture(t, &fixtureProvider{count: 2, statErr: map[uint32]error{2: SourceError{ReasonItemLimit}}})
	assertFailed(t, s.Processes, ReasonItemLimit)
	s = runFixture(t, &fixtureProvider{mountData: mountFixture(33, "ext4"), measurements: func([]MountRecord) ([]MountMeasurement, error) { return nil, ErrItemLimit }})
	assertFailed(t, s.Volumes, ReasonItemLimit)
}
func TestExactHighProcessCeilingCompletes(t *testing.T) {
	s := runFixture(t, &fixtureProvider{count: MaxProcessRows})
	if len(s.Processes.Items) != MaxProcessRows || s.Processes.Meta.Coverage != Complete {
		t.Fatal("ceiling treated as truncation")
	}
}
func TestStrictContractRoundTripAndForbiddenFields(t *testing.T) {
	s := runFixture(t, &fixtureProvider{count: 2, mountData: mountFixture(33, "proc")})
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeStrict(b)
	if e != nil || Validate(decoded) != nil {
		t.Fatalf("roundtrip: %v", e)
	}
	for _, raw := range []string{
		strings.Replace(string(b), `"schemaVersion":`, `"schemaVersion":"duplicate","schemaVersion":`, 1),
		strings.Replace(string(b), `"pid":1`, `"pid":1,"cmdline":"not allowed"`, 1),
		strings.Replace(string(b), `"pid":1`, `"pid":1.0`, 1),
		strings.Replace(string(b), `"parentPid":1,`, ``, 1),
		strings.Replace(string(b), `"name":"fixture worker"`, `"name":null`, 1),
		strings.Replace(string(b), `"countExact":true`, `"countExact":false`, 1),
		strings.Replace(string(b), `"observed":2`, `"observed":1`, 1),
		string(b) + `{}`,
	} {
		if _, e := DecodeStrict([]byte(raw)); e == nil {
			t.Fatal("accepted nonexact JSON")
		}
	}
	if _, e := DecodeStrict(append([]byte{0xff}, b...)); e == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	s.Processes.Items[0].Observation = Observation{Denied, ReasonPermissionDenied}
	if Validate(s) == nil {
		t.Fatal("denied row retained observed fields")
	}
}
func TestCancellationKeepsAdmissionUntilSynchronousProviderReturns(t *testing.T) {
	p := &fixtureProvider{started: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Snapshot, 1)
	go func() {
		s, e := CollectWithProvider(ctx, testID, testAt, p)
		if e != nil {
			done <- Snapshot{}
			return
		}
		done <- s
	}()
	<-p.started
	cancel()
	busy, e := CollectWithProvider(context.Background(), testID, testAt, &fixtureProvider{})
	if e != nil {
		t.Fatal(e)
	}
	assertFailed(t, busy.Processes, ReasonCollectorBusy)
	select {
	case <-done:
		t.Fatal("collector abandoned its provider")
	default:
	}
	close(p.release)
	s := <-done
	assertFailed(t, s.Processes, ReasonTimeout)
	assertFailed(t, s.Volumes, ReasonTimeout)
	if !p.closed.Load() {
		t.Fatal("close before admission release missing")
	}
	s = runFixture(t, &fixtureProvider{})
	if s.Processes.Meta.Coverage != Complete {
		t.Fatal("admission not released")
	}
}
func TestParsersPreserveAllowedMetricsAndRejectUnsafeValues(t *testing.T) {
	p, e := ParseProcessStat([]byte(statFixture(42, "name with ) paren")), 42, 4096, 100)
	if e != nil || *p.RSSBytes != 32768 || *p.CPUTimeSeconds != 2 || *p.Threads != 3 {
		t.Fatal("stat metrics")
	}
	for _, raw := range []string{statFixture(41, "other pid"), statFixture(42, "bad\nname"), strings.Replace(statFixture(42, "bad rss"), "0 8 ", "0 -8 ", 1)} {
		if _, e := ParseProcessStat([]byte(raw), 42, 4096, 100); e == nil {
			t.Fatal("unsafe stat accepted")
		}
	}
	raw := "1 9 8:1 / /home/fixture/private rw - ext4 none rw\n"
	m, e := ParseMountInfo(context.Background(), strings.NewReader(raw))
	if e != nil || volumeFor(m[0]).MountPoint != "/home/[redacted]/private" {
		t.Fatal("mount redaction failed")
	}
	for _, raw := range []string{"1 9 8:1 / /x rw - proc none rw\n1 9 8:2 / /y rw - proc none rw\n", "01 9 8:1 / /x rw - proc none rw\n", "1 9 8:1 / /x/../y rw - proc none rw\n", "1 9 8:1 / /x\\012y rw - proc none rw\n"} {
		if _, e := ParseMountInfo(context.Background(), strings.NewReader(raw)); e == nil {
			t.Fatal("unsafe mount accepted")
		}
	}
}
func TestReadBoundedDistinguishesExactEOFAndExceeded(t *testing.T) {
	for _, n := range []int{0, 1, 4096} {
		b, e := readBounded(context.Background(), bytes.NewReader(bytes.Repeat([]byte{'a'}, n)), n)
		if e != nil || len(b) != n {
			t.Fatal("exact EOF rejected")
		}
		if _, e = readBounded(context.Background(), bytes.NewReader(bytes.Repeat([]byte{'a'}, n+1)), n); !errors.Is(e, ErrSourceLimit) {
			t.Fatal("prefix accepted")
		}
	}
}
func TestSectionByteRejectionDropsAllRows(t *testing.T) {
	rows := make([]Volume, 4500)
	point := "/" + strings.Repeat("a", 4000)
	for i := range rows {
		rows[i] = volumeFor(MountRecord{MountID: uint32(i + 1), ParentID: 999, Major: 0, Minor: uint32(i + 1), Root: "/", MountPoint: point, Filesystem: "proc"})
	}
	// Canonical ordering is irrelevant after rejection; the oversized section
	// must be replaced entirely before validation, not clipped until it fits.
	s := Empty(testID, testAt, ReasonNotCollected)
	s.Volumes = completeSection(testID, rows)
	s, e := finish(s, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	assertFailed(t, s.Volumes, ReasonByteLimit)
}
