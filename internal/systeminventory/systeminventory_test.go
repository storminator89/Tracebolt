package systeminventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testID = "sample_0123456789abcdef0123456789abcdef"

var testAt = time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)

const netHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func procRow(local, remote, state string, inode uint64) string {
	return fmt.Sprintf(" 0: %s %s %s 00000000:00000000 00:00000000 00000000 999 0 %d 1 0000000000000000 100 0 0 10 0\n", local, remote, state, inode)
}
func ipv4Hex(a [4]byte) string { return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(a[:])) }
func ipv6Hex(a [16]byte) string {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&b, "%08X", binary.NativeEndian.Uint32(a[i*4:i*4+4]))
	}
	return b.String()
}
func validTestSnapshot() Snapshot {
	s := Empty(testID, testAt, ReasonNotCollected)
	runtime := &ServiceRuntime{"loaded", "active", "running"}
	enabled := "enabled"
	s.Services = completeSection(testID, testAt, []Service{{"example.service", runtime, &enabled, nil}})
	s.Sockets = completeSection(testID, testAt, []Socket{{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: Endpoint{"0.0.0.0", 80}, Remote: Endpoint{"0.0.0.0", 0}, State: "listen", Owners: []Owner{}, Attribution: Attribution{AttributionUnavailable, ReasonNoMatch}}})
	return s
}
func TestStrictRoundTrip(t *testing.T) {
	s := validTestSnapshot()
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeStrict(b)
	if e != nil {
		t.Fatal(e)
	}
	again, _ := Encode(got)
	if !bytes.Equal(b, again) {
		t.Fatal("roundtrip changed typed payload")
	}
}
func TestStrictRejectsJSONAmbiguity(t *testing.T) {
	b, _ := Encode(validTestSnapshot())
	text := string(b)
	cases := map[string]string{
		"duplicate root":        strings.Replace(text, `"scope":`, `"scope":"agent-visible-linux-system","scope":`, 1),
		"duplicate nested":      strings.Replace(text, `"port":80`, `"port":80,"port":80`, 1),
		"unknown":               strings.Replace(text, `"schemaVersion":`, `"private":true,"schemaVersion":`, 1),
		"missing required null": strings.Replace(text, `,"mainPid":null`, "", 1),
		"missing false":         strings.Replace(text, `,"countExact":true`, "", 1),
		"null object":           strings.Replace(text, `"local":{"address":"0.0.0.0","port":80}`, `"local":null`, 1),
		"null rows":             strings.Replace(text, `"owners":[]`, `"owners":null`, 1),
		"null number":           strings.Replace(text, `"port":80`, `"port":null`, 1),
		"case alias":            strings.Replace(text, `"mainPid"`, `"MainPid"`, 1),
		"negative":              strings.Replace(text, `"durationMs":0`, `"durationMs":-1`, 1),
		"negative zero":         strings.Replace(text, `"durationMs":0`, `"durationMs":-0`, 1),
		"float":                 strings.Replace(text, `"durationMs":0`, `"durationMs":0.0`, 1),
		"exponent":              strings.Replace(text, `"durationMs":0`, `"durationMs":0e0`, 1),
		"overflow":              strings.Replace(text, `"port":80`, `"port":65536`, 1),
		"offset time":           strings.ReplaceAll(text, `2026-10-04T10:00:00Z`, `2026-10-04T10:00:00+00:00`),
		"trailing":              text + "{}",
		"invalid utf8":          text[:len(text)-1] + "\xff}",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeStrict([]byte(input)); e == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}
func TestTypedShapeRejectsFalseCompleteness(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"failed rows":          func(s *Snapshot) { s.Services.Meta.Coverage = Failed; s.Services.Meta.Reason = ReasonReadFailed },
		"count mismatch":       func(s *Snapshot) { *s.Services.Meta.ObservedCount = 2 },
		"unproven main pid":    func(s *Snapshot) { pid := uint32(1); s.Services.Items[0].MainPID = &pid },
		"both absent":          func(s *Snapshot) { s.Services.Items[0].Runtime = nil; s.Services.Items[0].Enablement = nil },
		"relabeled generation": func(s *Snapshot) { s.Services.Meta.GenerationID = "sample_1123456789abcdef0123456789abcdef" },
		"relabel time":         func(s *Snapshot) { s.Sockets.Meta.ObservedAt = s.CollectedAt.Add(time.Second) },
		"duration unsafe":      func(s *Snapshot) { s.DurationMS = MaxSafeInteger + 1 },
		"address dns":          func(s *Snapshot) { s.Sockets.Items[0].Local.Address = "example.com" },
		"address noncanonical": func(s *Snapshot) {
			s.Sockets.Items[0].Family = "ipv6"
			s.Sockets.Items[0].Local.Address = "0:0:0:0:0:0:0:0"
		},
		"udp listen":          func(s *Snapshot) { s.Sockets.Items[0].Protocol = "udp" },
		"family relabel":      func(s *Snapshot) { s.Sockets.Items[0].Local.Address = "::ffff:127.0.0.1" },
		"unknown enum":        func(s *Snapshot) { s.Sockets.Items[0].Attribution.Coverage = "complete" },
		"false observed":      func(s *Snapshot) { s.Sockets.Items[0].Attribution = Attribution{AttributionObserved, ReasonNone} },
		"nil rows":            func(s *Snapshot) { s.Sockets.Items = nil },
		"unsafe service name": func(s *Snapshot) { s.Services.Items[0].Name = "../../bad.service" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := validTestSnapshot()
			edit(&s)
			if Validate(s) == nil {
				t.Fatal("accepted invalid typed snapshot")
			}
		})
	}
}
func TestServiceJoinCompleteLists(t *testing.T) {
	runtime := "running.service loaded active running Private description must be discarded\nfailed.service loaded failed failed Hidden account information\ntransient.service loaded inactive dead transient\n"
	files := "running.service enabled enabled\nfailed.service disabled enabled\ntemplate@.service static -\n"
	rows, e := ParseServices(context.Background(), strings.NewReader(runtime), strings.NewReader(files))
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 4 {
		t.Fatal(len(rows))
	}
	if rows[2].Name != "template@.service" || rows[2].Runtime != nil || rows[3].Enablement != nil {
		t.Fatalf("incorrect nullable join: %+v", rows)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), "Private") || strings.Contains(string(b), "Hidden") {
		t.Fatal("description escaped")
	}
	for _, r := range rows {
		if r.MainPID != nil {
			t.Fatal("invented pid")
		}
	}
}
func TestServiceParserFailsWholeSource(t *testing.T) {
	for _, input := range []string{"bad", "bad.service loaded active running\nbad.service loaded inactive dead\n", "bad.service loaded active bad/state\n", "● bad.service loaded failed failed description\n", "/tmp/bad.service loaded active running\n"} {
		rows, e := ParseServices(context.Background(), strings.NewReader(input), strings.NewReader(""))
		if e == nil || rows != nil {
			t.Fatalf("accepted %q", input)
		}
	}
	var huge strings.Builder
	for i := 0; i < MaxServiceRows+1; i++ {
		fmt.Fprintf(&huge, "unit-%d.service loaded inactive dead\n", i)
	}
	if rows, e := ParseServices(context.Background(), strings.NewReader(huge.String()), strings.NewReader("")); !errors.Is(e, ErrItemLimit) || rows != nil {
		t.Fatal("did not fail full service row cap")
	}
}
func TestProcSocketFamiliesStatesAndPrivacy(t *testing.T) {
	v4 := ipv4Hex([4]byte{127, 0, 0, 1})
	v6 := ipv6Hex([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1})
	cases := []struct {
		kind                                             SocketSource
		address, state, wantState, wantKind, wantAddress string
	}{
		{TCP4Source, v4, "0A", "listen", "listener", "127.0.0.1"}, {TCP6Source, v6, "01", "established", "connection", "::ffff:127.0.0.1"}, {UDP4Source, v4, "07", "bound", "bound", "127.0.0.1"}, {UDP6Source, v6, "01", "connected", "connection", "::ffff:127.0.0.1"}}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			rows, e := ParseSockets(context.Background(), c.kind, strings.NewReader(netHeader+procRow(c.address+":1F90", c.address+":0035", c.state, 123)))
			if e != nil {
				t.Fatal(e)
			}
			r := rows[0]
			if r.Row.Local.Address != c.wantAddress || r.Row.Local.Port != 8080 || r.Row.Remote.Port != 53 || r.Row.State != c.wantState || r.Row.Kind != c.wantKind || r.Inode != 123 {
				t.Fatalf("bad row: %+v", r)
			}
			b, _ := json.Marshal(r.Row)
			if strings.Contains(string(b), "999") || strings.Contains(string(b), "inode") || strings.Contains(string(b), "uid") {
				t.Fatal("forbidden source field exported")
			}
		})
	}
}
func TestSocketsRetainDuplicateEndpointsAndZeroInode(t *testing.T) {
	line := procRow("00000000:0050", "00000000:0000", "0A", 0)
	rows, e := ParseSockets(context.Background(), TCP4Source, strings.NewReader(netHeader+line+line))
	if e != nil || len(rows) != 2 {
		t.Fatal("dropped duplicate socket", e)
	}
}
func TestUDPZeroEndpointsExplicit(t *testing.T) {
	rows, e := ParseSockets(context.Background(), UDP4Source, strings.NewReader(netHeader+procRow("00000000:0000", "00000000:0000", "07", 0)))
	if e != nil || rows[0].Row.State != "unbound" || rows[0].Row.Kind != "unclassified" {
		t.Fatal("zero endpoint mislabel", e)
	}
}
func TestSocketParserFailsNoPrefix(t *testing.T) {
	good := procRow("00000000:0050", "00000000:0000", "0A", 7)
	for _, input := range []string{"", good, netHeader + good + "invalid\n", netHeader + strings.Replace(good, "0A", "FF", 1), netHeader + strings.Replace(good, "00000000:0050", "GGGGGGGG:0050", 1), netHeader + strings.Replace(good, "00000000:0050", "00000000:10000", 1)} {
		rows, e := ParseSockets(context.Background(), TCP4Source, strings.NewReader(input))
		if e == nil || rows != nil {
			t.Fatalf("accepted malformed socket: %q", input)
		}
	}
	if rows, e := ParseSockets(context.Background(), TCP4Source, strings.NewReader(netHeader+strings.Repeat(good, MaxSocketRows+1))); !errors.Is(e, ErrItemLimit) || rows != nil {
		t.Fatal("row cap ignored")
	}
}
func TestAllTCPStates(t *testing.T) {
	for n := 1; n <= 13; n++ {
		rows, e := ParseSockets(context.Background(), TCP4Source, strings.NewReader(netHeader+procRow("00000000:0050", "00000000:0000", fmt.Sprintf("%02X", n), 0)))
		if e != nil || len(rows) != 1 {
			t.Fatalf("state %d: %v", n, e)
		}
	}
}
func TestRawSourceCapAndContext(t *testing.T) {
	if _, e := readBounded(context.Background(), strings.NewReader(strings.Repeat("x", MaxRawSourceBytes+1))); !errors.Is(e, ErrSourceLimit) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ParseServices(ctx, strings.NewReader(""), strings.NewReader("")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

type inertProvider struct {
	runtime, units           string
	net                      map[SocketSource]string
	err                      map[string]error
	owners                   map[uint64]AttributionResult
	attrErr                  error
	opens, attrCalls, closed int
	block                    <-chan struct{}
	entered                  chan<- struct{}
}

func newInert() *inertProvider {
	return &inertProvider{runtime: "fixture.service loaded active running fixture\n", units: "fixture.service enabled enabled\n", net: map[SocketSource]string{TCP4Source: netHeader + procRow("00000000:0050", "00000000:0000", "0A", 123), TCP6Source: netHeader, UDP4Source: netHeader, UDP6Source: netHeader}, err: map[string]error{}}
}
func (p *inertProvider) OpenServices(ctx context.Context, k ServiceSource) (io.ReadCloser, error) {
	p.opens++
	if p.block != nil {
		if p.entered != nil {
			p.entered <- struct{}{}
		}
		<-p.block
	}
	if e := p.err[string(k)]; e != nil {
		return nil, e
	}
	s := p.runtime
	if k == UnitFilesSource {
		s = p.units
	}
	return io.NopCloser(strings.NewReader(s)), nil
}
func (p *inertProvider) OpenSockets(ctx context.Context, k SocketSource) (io.ReadCloser, error) {
	p.opens++
	if e := p.err[string(k)]; e != nil {
		return nil, e
	}
	return io.NopCloser(strings.NewReader(p.net[k])), nil
}
func (p *inertProvider) Attribute(ctx context.Context, inodes []uint64) (map[uint64]AttributionResult, error) {
	p.attrCalls++
	return p.owners, p.attrErr
}
func (p *inertProvider) Close() error { p.closed++; return nil }
func runInert(t *testing.T, p *inertProvider) Snapshot {
	t.Helper()
	s, e := collectWith(context.Background(), testID, testAt, &atomic.Bool{}, func() (Provider, error) { return p, nil })
	if e != nil {
		t.Fatal(e)
	}
	if p.closed != 1 {
		t.Fatal("provider not closed")
	}
	return s
}
func TestInertCollectionAndIndependentFailure(t *testing.T) {
	p := newInert()
	p.err["unit_files"] = SourceError{ReasonPermissionDenied}
	s := runInert(t, p)
	if s.Services.Meta.Coverage != Failed || s.Services.Meta.Reason != ReasonPermissionDenied || len(s.Services.Items) != 0 || s.Sockets.Meta.Coverage != Complete || len(s.Sockets.Items) != 1 {
		t.Fatal("false coverage")
	}
	p = newInert()
	p.err["udp6"] = SourceError{ReasonSourceMissing}
	s = runInert(t, p)
	if s.Services.Meta.Coverage != Complete || s.Sockets.Meta.Coverage != Failed || len(s.Sockets.Items) != 0 || p.attrCalls != 0 {
		t.Fatal("socket prefix escaped")
	}
}
func TestAttributionFailurePreservesSockets(t *testing.T) {
	p := newInert()
	p.attrErr = SourceError{ReasonPermissionDenied}
	s := runInert(t, p)
	if s.Sockets.Meta.Coverage != Complete || len(s.Sockets.Items) != 1 || s.Sockets.Items[0].Attribution.Reason != ReasonPermissionDenied {
		t.Fatal("attribution discarded observation")
	}
}
func TestAttributionPartialAndOwnerCap(t *testing.T) {
	name := "worker"
	p := newInert()
	owners := []Owner{}
	for i := 1; i <= MaxOwnersPerSocket+1; i++ {
		owners = append(owners, Owner{uint32(i), &name, ReasonNone})
	}
	p.owners = map[uint64]AttributionResult{123: {owners, Attribution{AttributionObserved, ReasonNone}}}
	s := runInert(t, p)
	r := s.Sockets.Items[0]
	if len(r.Owners) != MaxOwnersPerSocket || r.Attribution.Coverage != AttributionPartial || r.Attribution.Reason != ReasonOwnerLimit {
		t.Fatal("owner cap dropped socket or not labeled")
	}
}
func TestMaliciousAttributionCannotMutateSockets(t *testing.T) {
	p := newInert()
	bad := "secret\nname"
	p.owners = map[uint64]AttributionResult{123: {[]Owner{{4, &bad, ReasonNone}}, Attribution{AttributionObserved, ReasonNone}}}
	s := runInert(t, p)
	r := s.Sockets.Items[0]
	if r.Attribution.Reason != ReasonInvalidSource || len(r.Owners) != 0 || r.Local.Port != 80 {
		t.Fatal("invalid association escaped")
	}
}
func TestAdmissionRetainedUntilSynchronousReturn(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	p := newInert()
	p.block = release
	p.entered = entered
	slot := &atomic.Bool{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := collectWith(ctx, testID, testAt, slot, func() (Provider, error) { return p, nil })
		done <- e
	}()
	<-entered
	cancel()
	called := false
	s, e := collectWith(context.Background(), testID, testAt, slot, func() (Provider, error) { called = true; return newInert(), nil })
	if e != nil || called || s.Services.Meta.Reason != ReasonCollectorBusy {
		t.Fatal("abandoned synchronous operation released admission")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if slot.Load() {
		t.Fatal("slot leaked")
	}
}
func TestInvalidIdentityNeverCallsProvider(t *testing.T) {
	called := false
	_, e := collectWith(context.Background(), "bad", testAt, &atomic.Bool{}, func() (Provider, error) { called = true; return newInert(), nil })
	if e == nil || called {
		t.Fatal("invalid identity accessed source")
	}
}
func TestServiceByteCeilingFailsEntireSection(t *testing.T) {
	p := newInert()
	var r, u strings.Builder
	for i := 0; i < 3000; i++ {
		name := fmt.Sprintf("unit-%04d-%s.service", i, strings.Repeat("x", 150))
		fmt.Fprintf(&r, "%s loaded active running description\n", name)
		fmt.Fprintf(&u, "%s enabled enabled\n", name)
	}
	p.runtime = r.String()
	p.units = u.String()
	s := runInert(t, p)
	if s.Services.Meta.Coverage != Failed || s.Services.Meta.Reason != ReasonByteLimit || len(s.Services.Items) != 0 || s.Sockets.Meta.Coverage != Complete {
		t.Fatal("encoded cap exported prefix")
	}
}
func TestSectionMetaAndPageRows(t *testing.T) {
	s := validTestSnapshot()
	if ValidateSectionMeta(s.Services.Meta, 1) != nil || ValidateService(s.Services.Items[0]) != nil || ValidateSocket(s.Sockets.Items[0]) != nil {
		t.Fatal("standalone validators rejected rows")
	}
	if ValidateSectionMeta(s.Services.Meta, 0) == nil {
		t.Fatal("metadata count mismatch accepted")
	}
}
func FuzzDecodeStrict(f *testing.F) {
	b, _ := Encode(validTestSnapshot())
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := DecodeStrict(b)
		if e == nil {
			out, e := Encode(s)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := DecodeStrict(out); e != nil {
				t.Fatal(e)
			}
		}
	})
}

func TestSocketOrderingStrictAndEqualDuplicatesAllowed(t *testing.T) {
	s := validTestSnapshot()
	first := s.Sockets.Items[0]
	second := first
	second.Local.Port = 443
	s.Sockets = completeSection(testID, testAt, []Socket{first, first, second})
	if err := Validate(s); err != nil {
		t.Fatal("equal endpoint duplicates rejected", err)
	}
	raw, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict(raw); err != nil {
		t.Fatal(err)
	}
	s.Sockets.Items = []Socket{second, first, first}
	if err := Validate(s); err == nil {
		t.Fatal("reversed typed socket order accepted")
	}
	raw, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict(raw); err == nil {
		t.Fatal("reversed wire socket order accepted")
	}
}
