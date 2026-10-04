package endpointidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testGeneration = "sample_00112233445566778899aabbccddeeff"

var testTime = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

type fixtureProvider struct {
	hostname      string
	hostnameErr   error
	interfaces    []SourceInterface
	interfaceErr  error
	addresses     map[uint32][]SourceAddress
	addressErrors map[uint32]error
	calls         atomic.Int32
}

func (p *fixtureProvider) Hostname(context.Context) (string, error) {
	p.calls.Add(1)
	return p.hostname, p.hostnameErr
}
func (p *fixtureProvider) Interfaces(context.Context) ([]SourceInterface, error) {
	p.calls.Add(1)
	return p.interfaces, p.interfaceErr
}
func (p *fixtureProvider) Addresses(_ context.Context, index uint32, family string) ([]SourceAddress, error) {
	p.calls.Add(1)
	out := []SourceAddress{}
	for _, a := range p.addresses[index] {
		if !a.Addr.IsValid() || (family == "ipv4") == a.Addr.Is4() {
			out = append(out, a)
		}
	}
	return out, p.addressErrors[index]
}
func (p *fixtureProvider) Close() error     { return nil }
func addr(s string, _ uint16) SourceAddress { return SourceAddress{netip.MustParseAddr(s)} }
func provider() *fixtureProvider {
	return &fixtureProvider{hostname: "reported-host", interfaces: []SourceInterface{{7, "veth-example", true, false}, {1, "lo", true, true}, {2, "eth0", true, false}}, addresses: map[uint32][]SourceAddress{
		1: {addr("127.0.0.1", 8), addr("::1", 128)},
		2: {addr("192.168.40.5", 24), addr("10.2.3.4", 8), addr("172.20.1.2", 16), addr("fe80::42", 64), addr("fd00::42", 64), addr("2001:db8::42", 64)},
		7: {addr("169.254.3.4", 16), addr("::ffff:192.0.2.4", 128)},
	}}
}
func collect(t *testing.T, p Provider) Snapshot {
	t.Helper()
	s, e := CollectWithProvider(context.Background(), testGeneration, testTime, p)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestAssignedAddressesPreservedWithHonestScope(t *testing.T) {
	p := provider()
	original := append([]SourceInterface(nil), p.interfaces...)
	s := collect(t, p)
	if !reflect.DeepEqual(original, p.interfaces) {
		t.Fatal("provider slice mutated")
	}
	if s.ReportedHostname.Value == nil || *s.ReportedHostname.Value != "reported-host" || s.Interfaces.Meta.Coverage != Complete || *s.Interfaces.Meta.ObservedCount != 3 {
		t.Fatal("missing observation")
	}
	seen := map[string]Address{}
	for _, r := range s.Interfaces.Items {
		if r.HardwareKind != "unknown" {
			t.Fatal("invented interface classification")
		}
		for _, a := range append(append([]Address{}, r.Addresses.IPv4.Items...), r.Addresses.IPv6.Items...) {
			seen[a.Address] = a
		}
	}
	expected := map[string]string{"127.0.0.1": "loopback", "::1": "loopback", "192.168.40.5": "private", "10.2.3.4": "private", "172.20.1.2": "private", "169.254.3.4": "link-local", "fe80::42": "link-local", "fd00::42": "private", "2001:db8::42": "other", "::ffff:192.0.2.4": "other"}
	if len(seen) != len(expected) {
		t.Fatal("addresses dropped")
	}
	for a, scope := range expected {
		if seen[a].Scope != scope {
			t.Fatalf("wrong fixed fixture scope: %s", a)
		}
	}
	if seen["::ffff:192.0.2.4"].Family != "ipv6" {
		t.Fatal("family or assigned host bits lost")
	}
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	round, e := DecodeStrict(raw)
	if e != nil || !reflect.DeepEqual(s, round) {
		t.Fatal("roundtrip failed", e)
	}
}
func TestFailureCoverageIsIndependentAndNotEmptySuccess(t *testing.T) {
	p := provider()
	p.hostnameErr = ErrPermissionDenied
	p.addressErrors = map[uint32]error{2: ErrPermissionDenied}
	s := collect(t, p)
	if s.ReportedHostname.Coverage != Failed || s.ReportedHostname.Value != nil || s.ReportedHostname.Reason != ReasonPermissionDenied {
		t.Fatal("hostname denial hidden")
	}
	if s.Interfaces.Meta.Coverage != Partial || s.Interfaces.Meta.Reason != ReasonAddressUnavailable || !s.Interfaces.Meta.CountExact || *s.Interfaces.Meta.ObservedCount != 3 {
		t.Fatal("partial interface coverage hidden")
	}
	denied := s.Interfaces.Items[1].Addresses.IPv4
	if denied.Meta.Coverage != Failed || denied.Meta.ObservedCount != nil || denied.Meta.CountExact || len(denied.Items) != 0 || denied.Items == nil {
		t.Fatal("denial converted into empty success")
	}
	p = provider()
	p.interfaces = []SourceInterface{}
	s = collect(t, p)
	if s.Interfaces.Meta.Coverage != Complete || s.Interfaces.Meta.ObservedCount == nil || *s.Interfaces.Meta.ObservedCount != 0 {
		t.Fatal("complete empty enumeration lost")
	}
	p = provider()
	p.interfaceErr = ErrNotSupported
	s = collect(t, p)
	if s.ReportedHostname.Coverage != Complete || s.Interfaces.Meta.Coverage != Failed || s.Interfaces.Meta.Reason != ReasonNotSupported {
		t.Fatal("unsupported source not explicit")
	}
}
func TestLimitsNeverYieldCompletePrefix(t *testing.T) {
	t.Run("interfaces", func(t *testing.T) {
		p := provider()
		p.interfaces = make([]SourceInterface, MaxInterfaces+1)
		s := collect(t, p)
		if s.Interfaces.Meta.Reason != ReasonItemLimit || len(s.Interfaces.Items) != 0 || p.calls.Load() != 2 {
			t.Fatal("interface limit not bounded")
		}
	})
	t.Run("per-interface", func(t *testing.T) {
		p := provider()
		p.addresses[2] = make([]SourceAddress, MaxAddressesPerInterface+1)
		s := collect(t, p)
		if s.Interfaces.Meta.Coverage != Partial || s.Interfaces.Items[1].Addresses.IPv4.Meta.Reason != ReasonItemLimit || len(s.Interfaces.Items[1].Addresses.IPv4.Items) != 0 {
			t.Fatal("address prefix retained")
		}
	})
	t.Run("total-addresses", func(t *testing.T) {
		p := provider()
		p.interfaces = nil
		p.addresses = map[uint32][]SourceAddress{}
		for i := 1; i <= 5; i++ {
			p.interfaces = append(p.interfaces, SourceInterface{uint32(i), fmt.Sprintf("i%d", i), true, false})
			for j := 1; j <= 32; j++ {
				p.addresses[uint32(i)] = append(p.addresses[uint32(i)], addr(fmt.Sprintf("10.%d.0.%d", i, j), 24))
			}
		}
		s := collect(t, p)
		if s.Interfaces.Meta.Reason != ReasonItemLimit || len(s.Interfaces.Items) != 0 {
			t.Fatal("total-address prefix retained")
		}
	})
	t.Run("encoded-bytes", func(t *testing.T) {
		p := provider()
		p.interfaces = nil
		p.addresses = map[uint32][]SourceAddress{}
		for i := 1; i <= 32; i++ {
			p.interfaces = append(p.interfaces, SourceInterface{uint32(i), fmt.Sprintf("iface-name-%02d", i), true, false})
			p.addresses[uint32(i)] = []SourceAddress{addr("2001:db8:ffff:eeee:dddd:cccc:bbbb:aaaa", 128)}
		}
		s := collect(t, p)
		if s.Interfaces.Meta.Reason != ReasonByteLimit || len(s.Interfaces.Items) != 0 || s.ReportedHostname.Coverage != Complete {
			t.Fatal("oversized payload not failed independently")
		}
	})
}
func TestInvalidSourceAndNoRawErrorExport(t *testing.T) {
	tests := map[string]func(*fixtureProvider){
		"duplicate-index":    func(p *fixtureProvider) { p.interfaces[0].Index = 2 },
		"duplicate-name":     func(p *fixtureProvider) { p.interfaces[0].Name = "eth0" },
		"bad-interface-name": func(p *fixtureProvider) { p.interfaces[0].Name = "eth0\u202e" },
		"zero-index":         func(p *fixtureProvider) { p.interfaces[0].Index = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := provider()
			mutate(p)
			s := collect(t, p)
			if s.Interfaces.Meta.Reason != ReasonInvalidSource {
				t.Fatal("invalid interface accepted")
			}
		})
	}
	for _, bad := range []string{"", strings.Repeat("a", MaxHostnameBytes+1), "host\nname", "host\u202ename", "\xff", "host\ufffd", " leading"} {
		p := provider()
		p.hostname = bad
		s := collect(t, p)
		if s.ReportedHostname.Reason != ReasonInvalidSource || s.ReportedHostname.Value != nil {
			t.Fatal("invalid hostname accepted")
		}
	}
	for _, bad := range []SourceAddress{{netip.Addr{}}} {
		p := provider()
		p.addresses[2] = []SourceAddress{bad}
		s := collect(t, p)
		if s.Interfaces.Items[1].Addresses.IPv4.Meta.Reason != ReasonInvalidSource {
			t.Fatal("invalid address accepted")
		}
	}
	p := provider()
	p.addresses[2] = []SourceAddress{addr("192.0.2.2", 24), addr("192.0.2.2", 24)}
	s := collect(t, p)
	if s.Interfaces.Items[1].Addresses.IPv4.Meta.Reason != ReasonInvalidSource {
		t.Fatal("duplicate address accepted")
	}
	p = provider()
	p.hostnameErr = errors.New("private path should not escape")
	s = collect(t, p)
	raw, _ := Encode(s)
	if bytes.Contains(raw, []byte("private path")) || s.ReportedHostname.Reason != ReasonReadFailed {
		t.Fatal("raw error escaped")
	}
}
func TestStrictContractRejectsAmbiguousAndExtraJSON(t *testing.T) {
	s := collect(t, provider())
	raw, _ := Encode(s)
	mutations := map[string][]byte{
		"unknown-host":         bytes.Replace(raw, []byte(`"reportedHostname":{`), []byte(`"reportedHostname":{"attested":true,`), 1),
		"mac":                  bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":1,"macAddress":"00:11:22:33:44:55"`), 1),
		"duplicate":            bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":1,"index":1`), 1),
		"alias":                bytes.Replace(raw, []byte(`"index":1`), []byte(`"Index":1`), 1),
		"missing-nullable":     bytes.Replace(raw, []byte(`"value":"reported-host",`), nil, 1),
		"null-items":           bytes.Replace(raw, []byte(`"items":[`), []byte(`"items":null,"extra":[`), 1),
		"exponent":             bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":1e0`), 1),
		"negative-zero":        bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":-0`), 1),
		"string-number":        bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":"1"`), 1),
		"overflow":             bytes.Replace(raw, []byte(`"index":1`), []byte(`"index":4294967296`), 1),
		"physical-inference":   bytes.Replace(raw, []byte(`"hardwareKind":"unknown"`), []byte(`"hardwareKind":"physical"`), 1),
		"noncanonical-address": bytes.Replace(raw, []byte(`"::1"`), []byte(`"0:0:0:0:0:0:0:1"`), 1),
		"wrong-address-scope":  bytes.Replace(raw, []byte(`"scope":"loopback"`), []byte(`"scope":"private"`), 1),
		"trailing":             append(append([]byte{}, raw...), []byte(` {}`)...),
		"invalid-utf8":         bytes.Replace(raw, []byte("reported-host"), []byte{0xff}, 1),
	}
	// Remove the required nullable hostname member without depending on order.
	mutations["missing-nullable"] = bytes.Replace(raw, []byte(`,"value":"reported-host"`), nil, 1)
	for name, b := range mutations {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(b, raw) {
				t.Fatal("mutation did not apply")
			}
			if _, e := DecodeStrict(b); e == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
	failed := Empty(testGeneration, testTime, ReasonPermissionDenied)
	b, _ := Encode(failed)
	if _, e := DecodeStrict(bytes.Replace(b, []byte(`"value":null`), []byte(`"value":"hidden"`), 1)); e == nil {
		t.Fatal("failed hostname with value accepted")
	}
	if _, e := DecodeStrict(append(bytes.Repeat([]byte(" "), MaxSnapshotBytes), raw...)); !errors.Is(e, ErrSnapshotLimit) {
		t.Fatal("raw cap not enforced")
	}
}
func TestValidateCoverageAndOrdering(t *testing.T) {
	base := collect(t, provider())
	raw, _ := Encode(base)
	tests := map[string]func(*Snapshot){
		"false-complete": func(s *Snapshot) { s.Interfaces.Items[0].Addresses.IPv4 = failedAddresses(ReasonPermissionDenied) },
		"false-partial": func(s *Snapshot) {
			s.Interfaces.Meta.Coverage = Partial
			s.Interfaces.Meta.Reason = ReasonAddressUnavailable
		},
		"bad-count": func(s *Snapshot) { n := uint32(7); s.Interfaces.Meta.ObservedCount = &n },
		"unordered": func(s *Snapshot) {
			s.Interfaces.Items[0], s.Interfaces.Items[1] = s.Interfaces.Items[1], s.Interfaces.Items[0]
		},
		"address-order":    func(s *Snapshot) { a := s.Interfaces.Items[1].Addresses.IPv4.Items; a[0], a[1] = a[1], a[0] },
		"nil-array":        func(s *Snapshot) { s.Interfaces.Items[0].Addresses.IPv4.Items = nil },
		"wrong-generation": func(s *Snapshot) { s.GenerationID = "reported-host" },
		"wrong-time":       func(s *Snapshot) { s.CollectedAt = s.CollectedAt.In(time.FixedZone("alias", 0)) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			var s Snapshot
			if json.Unmarshal(raw, &s) != nil {
				t.Fatal("fixture")
			}
			change(&s)
			if Validate(s) == nil {
				t.Fatal("contradictory snapshot accepted")
			}
		})
	}
}

type blockingProvider struct {
	fixtureProvider
	entered chan struct{}
	release chan struct{}
}

func (p *blockingProvider) Hostname(context.Context) (string, error) {
	close(p.entered)
	<-p.release
	return p.hostname, nil
}
func TestCancellationRetainsSingleFlightUntilSynchronousReturn(t *testing.T) {
	p := &blockingProvider{fixtureProvider: *provider(), entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Snapshot, 1)
	go func() { s, _ := CollectWithProvider(ctx, testGeneration, testTime, p); done <- s }()
	<-p.entered
	cancel()
	other := provider()
	s := collect(t, other)
	if s.Interfaces.Meta.Reason != ReasonCollectorBusy || other.calls.Load() != 0 {
		t.Fatal("busy collector admitted a source")
	}
	close(p.release)
	s = <-done
	if s.ReportedHostname.Reason != ReasonTimeout || s.Interfaces.Meta.Reason != ReasonTimeout || p.calls.Load() != 0 {
		t.Fatal("cancellation source handling")
	}
	s = collect(t, provider())
	if s.Interfaces.Meta.Coverage != Complete {
		t.Fatal("slot not released")
	}
}
func TestInvalidOrCanceledAdmissionMakesNoSourceCalls(t *testing.T) {
	p := provider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, e := CollectWithProvider(ctx, testGeneration, testTime, p)
	if e != nil || s.Interfaces.Meta.Reason != ReasonTimeout || p.calls.Load() != 0 {
		t.Fatal("canceled call touched source")
	}
	if _, e = CollectWithProvider(context.Background(), "invalid", testTime, p); e == nil || p.calls.Load() != 0 {
		t.Fatal("invalid call touched source")
	}
}
func FuzzDecodeStrict(f *testing.F) {
	raw, _ := Encode(Empty(testGeneration, testTime, ReasonNotCollected))
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, e := DecodeStrict(raw)
		if e != nil {
			return
		}
		out, e := Encode(s)
		if e != nil {
			t.Fatal(e)
		}
		again, e := DecodeStrict(out)
		if e != nil || !reflect.DeepEqual(s, again) {
			t.Fatal("non-roundtripping accepted value")
		}
	})
}
