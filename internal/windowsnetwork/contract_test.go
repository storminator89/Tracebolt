package windowsnetwork

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

const generation = "sample_0123456789abcdef0123456789abcdef"
const grant = "0123456789abcdef0123456789abcdef"

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func pointer[T any](v T) *T { return &v }
func endpoint(protocol, family string, pid uint32) Endpoint {
	local, remote := "192.0.2.9", "198.51.100.5"
	if family == "ipv6" {
		local = "fe80::1%16909060"
		remote = "fe80::2%84281096"
	}
	r := Endpoint{Protocol: protocol, Family: family, LocalAddress: local, LocalPort: 443, PID: pid}
	if protocol == "tcp" {
		r.RemoteAddress = &remote
		r.RemotePort = pointer(uint16(54321))
		r.State = pointer("established")
	}
	return r
}
func rawTable(spec tableSpec, rows []Endpoint) []byte {
	b := make([]byte, 4+len(rows)*spec.stride)
	binary.LittleEndian.PutUint32(b, uint32(len(rows)))
	addr := func(dst []byte, s string) { a := netip.MustParseAddr(s); copy(dst, a.AsSlice()) }
	scope := func(dst []byte, s string) {
		a := netip.MustParseAddr(s)
		var n uint32
		for _, v := range a.Zone() {
			n = n*10 + uint32(v-'0')
		}
		binary.BigEndian.PutUint32(dst, n)
	}
	port := func(dst []byte, n uint16) { binary.BigEndian.PutUint16(dst, n); dst[2] = 0xde; dst[3] = 0xad } // Upper 16 bits are unspecified.
	for i, r := range rows {
		p := b[4+i*spec.stride : 4+(i+1)*spec.stride]
		switch {
		case spec.protocol == "tcp" && spec.family == "ipv4":
			binary.LittleEndian.PutUint32(p, 5)
			addr(p[4:8], r.LocalAddress)
			port(p[8:12], r.LocalPort)
			addr(p[12:16], *r.RemoteAddress)
			port(p[16:20], *r.RemotePort)
			binary.LittleEndian.PutUint32(p[20:24], r.PID)
		case spec.protocol == "tcp" && spec.family == "ipv6":
			addr(p[:16], r.LocalAddress)
			scope(p[16:20], r.LocalAddress)
			port(p[20:24], r.LocalPort)
			addr(p[24:40], *r.RemoteAddress)
			scope(p[40:44], *r.RemoteAddress)
			port(p[44:48], *r.RemotePort)
			binary.LittleEndian.PutUint32(p[48:52], 5)
			binary.LittleEndian.PutUint32(p[52:56], r.PID)
		case spec.protocol == "udp" && spec.family == "ipv4":
			addr(p[:4], r.LocalAddress)
			port(p[4:8], r.LocalPort)
			binary.LittleEndian.PutUint32(p[8:12], r.PID)
		case spec.protocol == "udp" && spec.family == "ipv6":
			addr(p[:16], r.LocalAddress)
			scope(p[16:20], r.LocalAddress)
			port(p[20:24], r.LocalPort)
			binary.LittleEndian.PutUint32(p[24:28], r.PID)
		}
	}
	return b
}
func queryFixtures(data map[tableSpec][]byte) query {
	return func(spec tableSpec, b []byte) (uint32, error) {
		v, ok := data[spec]
		if !ok {
			v = rawTable(spec, nil)
		}
		if len(b) < len(v) {
			return uint32(len(v)), errBuffer
		}
		copy(b, v)
		return uint32(len(v)), nil
	}
}
func fixture(t *testing.T) Snapshot {
	t.Helper()
	data := map[tableSpec][]byte{}
	for _, s := range tables {
		data[s] = rawTable(s, []Endpoint{endpoint(s.protocol, s.family, 42)})
	}
	out, e := collectUsing(context.Background(), generation, grant, epoch, queryFixtures(data))
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestFourTablesAndNetworkByteOrder(t *testing.T) {
	v := fixture(t)
	if v.Quality != "observed" || !v.CountExact || v.ObservedCount != 4 || v.Truncated || len(v.Rows) != 4 || !v.CollectedAt.Equal(epoch) {
		t.Fatal(v)
	}
	for i, s := range tables {
		want := endpoint(s.protocol, s.family, 42)
		if !reflect.DeepEqual(v.Rows[i], want) {
			t.Fatalf("table %d: got %+v want %+v", i, v.Rows[i], want)
		}
	}
	for _, s := range tables {
		r := endpoint(s.protocol, s.family, ^uint32(0))
		if s.family == "ipv6" {
			r.LocalAddress = "::ffff:192.0.2.1"
			if s.protocol == "tcp" {
				r.RemoteAddress = pointer("::")
			}
		}
		r.LocalPort = 0
		data := rawTable(s, []Endpoint{r})
		got := parseTable(context.Background(), s, data)
		if !got.complete || len(got.rows) != 1 || !reflect.DeepEqual(got.rows[0], r) {
			t.Fatal(got)
		}
	}
}
func TestCanonicalContractStrict(t *testing.T) {
	s := fixture(t)
	b, _ := json.Marshal(s)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	invalid := []string{
		string(b) + " ", strings.Replace(string(b), `"scope":`, `"unknown":0,"scope":`, 1),
		strings.Replace(string(b), `"pid":42`, `"pid":42,"pid":42`, 1),
		strings.Replace(string(b), `"pid":42`, `"pid":null`, 1),
		strings.Replace(string(b), `"localPort":443`, `"localPort":65536`, 1),
		strings.Replace(string(b), `"localPort":443`, `"localPort":443.0`, 1),
		strings.Replace(string(b), `"remoteAddress":null`, `"remoteAddress":"0.0.0.0"`, 1),
		strings.Replace(string(b), `"countExact":true`, `"countExact":null`, 1),
		strings.Replace(string(b), `"observedCount":4`, `"observedCount":16385`, 1),
		strings.Replace(string(b), `"collectedAt":"2026-01-01T00:00:00Z"`, `"collectedAt":"2026-01-01T00:00:00+00:00"`, 1),
		strings.Replace(string(b), `"truncated":false`, `"truncated":true`, 1),
		strings.Replace(string(b), `"quality":"observed"`, `"quality":"partial"`, 1),
		strings.Replace(string(b), `"192.0.2.9"`, `"host.example"`, 1),
	}
	for _, raw := range invalid {
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatalf("accepted invalid: %s", raw)
		}
	}
	if _, e := Decode(append(b, 0xff)); e == nil {
		t.Fatal("accepted non-UTF8")
	}
	v := s
	v.Rows = append([]Endpoint{}, s.Rows...)
	v.Rows[0], v.Rows[1] = v.Rows[1], v.Rows[0]
	if Validate(v) == nil {
		t.Fatal("accepted unsorted")
	}
	v = s
	v.Rows = nil
	if Validate(v) == nil {
		t.Fatal("accepted nil rows")
	}
	for _, quality := range []string{"denied", "unavailable"} {
		v = s
		v.Quality = quality
		v.CountExact = false
		if Validate(v) == nil {
			t.Fatal("accepted failure with rows")
		}
	}
}
func TestAddressAndScopeCanonical(t *testing.T) {
	for _, s := range []string{"fe80::1%1", "::ffff:192.0.2.1", "::", "2001:db8::1", "fe80::1%4294967295"} {
		if _, ok := address(s, "ipv6"); !ok {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"192.0.2.1", "FE80::1", "fe80:0:0:0:0:0:0:1", "fe80::1%0", "fe80::1%01", "fe80::1%eth0", "fe80::1%4294967296", "fe80::1%+1", "fe80::1%1%2"} {
		if _, ok := address(s, "ipv6"); ok {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"::ffff:192.0.2.1", "192.00.2.1", "192.0.2.1%2", "1.2.3.256", "localhost"} {
		if _, ok := address(s, "ipv4"); ok {
			t.Fatal(s)
		}
	}
	if compareAddress("fe80::1%2", "fe80::1%10") >= 0 || compareAddress("192.0.2.2", "192.0.2.10") >= 0 {
		t.Fatal("lexical address/scope sort")
	}
}
func TestConsentCannotPromoteOtherScopes(t *testing.T) {
	binding := strings.Repeat("b", 64)
	c := Consent{ConsentVersion, Scope, binding, grant, false}
	b, e := EncodeConsent(c, binding)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecodeConsent(b, binding); e != nil || got.Enabled {
		t.Fatal(got, e)
	}
	c.Enabled = true
	b, e = EncodeConsent(c, binding)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{append(b, ' '), []byte(strings.Replace(string(b), Scope, "windows-process-metrics-v1", 1)), []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":null`, 1)), []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":true,"enabled":true`, 1))} {
		if _, e := DecodeConsent(raw, binding); e == nil {
			t.Fatal("accepted altered consent")
		}
	}
	if _, e := DecodeConsent(b, strings.Repeat("c", 64)); e == nil {
		t.Fatal("foreign binding")
	}
}
func TestMalformedAndTrailingNativeTables(t *testing.T) {
	for _, s := range tables {
		valid := rawTable(s, []Endpoint{endpoint(s.protocol, s.family, 3)})
		invalid := [][]byte{nil, {0, 0, 0}, valid[:len(valid)-1]}
		huge := append([]byte{}, valid...)
		binary.LittleEndian.PutUint32(huge, ^uint32(0))
		invalid = append(invalid, huge)
		for _, b := range invalid {
			r := parseTable(context.Background(), s, b)
			if r.err == nil || r.complete || len(r.rows) != 0 {
				t.Fatal(s, r)
			}
		}
		// Allocation surplus may follow a table that shrank since its size
		// probe. It is ignored, never interpreted as another endpoint.
		for _, b := range [][]byte{append(append([]byte{}, valid...), 0xff), append(rawTable(s, nil), make([]byte, s.stride)...)} {
			r := parseTable(context.Background(), s, b)
			if r.err != nil || !r.complete || len(r.rows) != int(binary.LittleEndian.Uint32(b[:4])) {
				t.Fatal(s, r)
			}
		}
	}
	s := tables[0]
	bad := rawTable(s, []Endpoint{endpoint("tcp", "ipv4", 1), endpoint("tcp", "ipv4", 2)})
	binary.LittleEndian.PutUint32(bad[4+s.stride:], 13)
	r := parseTable(context.Background(), s, bad)
	if r.err == nil || r.complete || len(r.rows) != 1 || !r.available {
		t.Fatal(r)
	}
}
func TestBufferGrowthBoundAndCancellation(t *testing.T) {
	for _, size := range []uint32{0, 3, MaxTableBytes + 1, ^uint32(0)} {
		calls := 0
		r := readTable(context.Background(), tables[0], func(tableSpec, []byte) (uint32, error) { calls++; return size, errBuffer })
		if !errors.Is(r.err, ErrBounds) || calls != 1 {
			t.Fatal(size, r, calls)
		}
	}
	calls := 0
	r := readTable(context.Background(), tables[0], func(_ tableSpec, b []byte) (uint32, error) { calls++; return uint32(len(b) + 4), errBuffer })
	if !errors.Is(r.err, ErrBounds) || calls != MaxTableCalls {
		t.Fatal(r, calls)
	}
	calls = 0
	r = readTable(context.Background(), tables[0], func(_ tableSpec, b []byte) (uint32, error) { calls++; return 4, errBuffer })
	if !errors.Is(r.err, ErrBounds) || calls != 2 {
		t.Fatal(r, calls)
	}
	r = readTable(context.Background(), tables[0], func(tableSpec, []byte) (uint32, error) { return 8, nil })
	if r.err == nil {
		t.Fatal("successful absent buffer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	r = readTable(ctx, tables[0], func(tableSpec, []byte) (uint32, error) { calls++; cancel(); return 4, errBuffer })
	if !errors.Is(r.err, context.Canceled) || calls != 1 {
		t.Fatal(r, calls)
	}
}
func TestStatusesAndUnknownCounts(t *testing.T) {
	for _, e := range []error{ErrDenied, ErrUnavailable, ErrUnsupported, ErrBounds} {
		v, err := collectUsing(context.Background(), generation, grant, epoch, func(tableSpec, []byte) (uint32, error) { return 0, e })
		expected := "unavailable"
		if e == ErrDenied {
			expected = "denied"
		}
		if err != nil || v.Quality != expected || v.CountExact || v.Truncated || v.ObservedCount != 0 || len(v.Rows) != 0 {
			t.Fatal(v, err)
		}
	}
	q := queryFixtures(nil)
	v, e := collectUsing(context.Background(), generation, grant, epoch, func(s tableSpec, b []byte) (uint32, error) {
		if s == tables[0] {
			return q(s, b)
		}
		return 0, ErrDenied
	})
	if e != nil || v.Quality != "partial" || v.CountExact || v.ObservedCount != 0 || v.Truncated {
		t.Fatal(v, e)
	}
	data := map[tableSpec][]byte{tables[0]: rawTable(tables[0], []Endpoint{endpoint("tcp", "ipv4", 1)})}
	q = queryFixtures(data)
	v, e = collectUsing(context.Background(), generation, grant, epoch, func(s tableSpec, b []byte) (uint32, error) {
		if s.protocol == "udp" {
			return 0, ErrDenied
		}
		return q(s, b)
	})
	if e != nil || v.Quality != "partial" || v.CountExact || v.ObservedCount != 1 || len(v.Rows) != 1 {
		t.Fatal(v, e)
	}
}
func TestBoundedCountsStableRowsAndBudget(t *testing.T) {
	data := map[tableSpec][]byte{}
	for _, s := range tables {
		rows := make([]Endpoint, MaxRowsPerTable+1)
		for i := range rows {
			rows[i] = endpoint(s.protocol, s.family, uint32(MaxRowsPerTable+1-i))
		}
		data[s] = rawTable(s, rows)
	}
	v, e := collectUsing(context.Background(), generation, grant, epoch, queryFixtures(data))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(v)
	if v.ObservedCount != MaxObservedRows || v.CountExact || v.Quality != "partial" || !v.Truncated || len(v.Rows) > MaxRows || len(raw) > MaxBytes {
		t.Fatal(v.ObservedCount, v.CountExact, v.Quality, v.Truncated, len(v.Rows), len(raw))
	}
	for i := 1; i < len(v.Rows); i++ {
		if v.Rows[i].PID <= v.Rows[i-1].PID {
			t.Fatal("unstable PID tie ordering")
		}
	}
	smaller, e := FitBudget(v, 1024)
	if e != nil || len(smaller.Rows) >= len(v.Rows) || smaller.ObservedCount != v.ObservedCount || smaller.CountExact != v.CountExact || !smaller.CollectedAt.Equal(v.CollectedAt) || smaller.GenerationID != v.GenerationID || smaller.GrantID != v.GrantID || smaller.Quality != v.Quality {
		t.Fatal(smaller, e)
	}
	if _, e := FitBudget(v, 1); e == nil {
		t.Fatal("accepted impossible budget")
	}
	if _, e := FitBudget(v, 0); e == nil {
		t.Fatal("accepted zero budget")
	}
	if len(v.Rows) == 0 {
		t.Fatal("FitBudget mutated original")
	}
	rows := make([]Endpoint, 65)
	for i := range rows {
		rows[i] = endpoint("udp", "ipv4", 1)
	}
	v, e = collectUsing(context.Background(), generation, grant, epoch, queryFixtures(map[tableSpec][]byte{tables[2]: rawTable(tables[2], rows)}))
	if e != nil || !v.CountExact || v.Quality != "observed" || v.ObservedCount != 65 || !v.Truncated {
		t.Fatal(v, e)
	}
	// Duplicate UDP rows are counted and retained, never deduplicated into a false count.
	if len(v.Rows) < 2 || !reflect.DeepEqual(v.Rows[0], v.Rows[1]) {
		t.Fatal(v)
	}
}
func TestInvalidAndCanceledInputDoesNotRead(t *testing.T) {
	calls := 0
	read := func(string, string, []byte) (uint32, error) { calls++; return 0, ErrDenied }
	if _, e := CollectWithReader(nil, generation, grant, epoch, read); e == nil {
		t.Fatal("nil context")
	}
	if _, e := CollectWithReader(context.Background(), generation, "", epoch, read); e == nil {
		t.Fatal("missing grant")
	}
	if _, e := CollectWithReader(context.Background(), "bad", grant, epoch, read); e == nil {
		t.Fatal("invalid generation")
	}
	if _, e := CollectWithReader(context.Background(), generation, grant, time.Time{}, read); e == nil {
		t.Fatal("invalid time")
	}
	if _, e := CollectWithReader(context.Background(), generation, grant, epoch, nil); e == nil {
		t.Fatal("nil reader")
	}
	if _, e := CollectWithReader(context.Background(), generation, grant, epoch.In(time.FixedZone("UTC", 0)), read); e == nil {
		t.Fatal("noncanonical UTC")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CollectWithReader(ctx, generation, grant, epoch, read); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if calls != 0 {
		t.Fatal(calls)
	}
}

type cancelAfterChecks struct {
	context.Context
	checks int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks > 2 {
		return context.DeadlineExceeded
	}
	return nil
}
func TestCooperativeParsingBudgetPreservesLowerBound(t *testing.T) {
	ctx := &cancelAfterChecks{Context: context.Background()}
	s := tables[2]
	r := parseTable(ctx, s, rawTable(s, []Endpoint{endpoint("udp", "ipv4", 1), endpoint("udp", "ipv4", 2), endpoint("udp", "ipv4", 3)}))
	if !errors.Is(r.err, context.DeadlineExceeded) || len(r.rows) != 2 || r.complete || !r.available {
		t.Fatal(r)
	}
}

func TestTCPListenerHasNoRemotePeer(t *testing.T) {
	for _, spec := range tables[:2] {
		b := rawTable(spec, []Endpoint{endpoint("tcp", spec.family, 42)})
		stateOffset := 4
		if spec.family == "ipv6" {
			stateOffset += 48
		}
		binary.LittleEndian.PutUint32(b[stateOffset:stateOffset+4], 2)
		v, e := collectUsing(context.Background(), generation, grant, epoch, queryFixtures(map[tableSpec][]byte{spec: b}))
		if e != nil || len(v.Rows) != 1 || v.Rows[0].State == nil || *v.Rows[0].State != "listen" || v.Rows[0].RemoteAddress != nil || v.Rows[0].RemotePort != nil {
			t.Fatal(v, e)
		}
		raw, _ := json.Marshal(v)
		if _, e := Decode(raw); e != nil {
			t.Fatal(e)
		}
		changed := v
		changed.Rows = append([]Endpoint{}, v.Rows...)
		changed.Rows[0].RemoteAddress = pointer("0.0.0.0")
		changed.Rows[0].RemotePort = pointer(uint16(0))
		if Validate(changed) == nil {
			t.Fatal("listener accepted apparent peer")
		}
		changed = v
		changed.Rows = append([]Endpoint{}, v.Rows...)
		changed.Rows[0].State = pointer("established")
		if Validate(changed) == nil {
			t.Fatal("established missing peer")
		}
		listener := v.Rows[0]
		connected := endpoint("tcp", spec.family, 42)
		if compareRows(listener, connected) >= 0 || compareRows(connected, listener) <= 0 || compareRows(listener, listener) != 0 {
			t.Fatal("listener ordering")
		}
	}
}
func TestPublicInjectedReaderUsesProductionPath(t *testing.T) {
	calls := 0
	v, e := CollectWithReader(context.Background(), generation, grant, epoch, func(protocol, family string, b []byte) (uint32, error) {
		calls++
		for _, spec := range tables {
			if spec.protocol == protocol && spec.family == family {
				raw := rawTable(spec, []Endpoint{endpoint(protocol, family, 42)})
				if len(b) < len(raw) {
					return uint32(len(raw)), ErrInsufficientBuffer
				}
				copy(b, raw)
				return uint32(len(raw)), nil
			}
		}
		t.Fatal("unexpected table")
		return 0, ErrUnavailable
	})
	if e != nil || v.ObservedCount != 4 || !v.CountExact || calls != 8 {
		t.Fatal(v, e, calls)
	}
}

func TestShrinkingTableIgnoresSurplusAllocation(t *testing.T) {
	for _, spec := range tables {
		for _, retained := range []int{0, 1} {
			calls := 0
			r := readTable(context.Background(), spec, func(s tableSpec, b []byte) (uint32, error) {
				calls++
				full := rawTable(s, []Endpoint{endpoint(s.protocol, s.family, 1), endpoint(s.protocol, s.family, 2), endpoint(s.protocol, s.family, 3)})
				if len(b) == 0 {
					return uint32(len(full)), ErrInsufficientBuffer
				}
				// Simulate success retaining the allocated size after the actual table
				// shrank. Sentinel bytes after counted rows must never become endpoint data.
				for i := range b {
					b[i] = 0xff
				}
				copy(b, full[:4+retained*s.stride])
				binary.LittleEndian.PutUint32(b, uint32(retained))
				return uint32(len(b)), nil
			})
			if r.err != nil || !r.complete || !r.available || len(r.rows) != retained || calls != 2 {
				t.Fatal(spec, retained, r, calls)
			}
			if retained == 1 && r.rows[0].PID != 1 {
				t.Fatal(r)
			}
		}
	}
}
