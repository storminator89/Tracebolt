package macosinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func request() Request {
	return Request{Consent: Consent{ConsentVersion, Scope, strings.Repeat("a", 64), strings.Repeat("b", 32), true}, SenderBinding: strings.Repeat("a", 64), GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
}
func plist(ids ...string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><array><string>` + strings.Join(ids, `</string><string>`) + `</string></array></plist>`)
}
func processLine(name string, pid, ppid int) string {
	return fmt.Sprintf("%-16s %5d %5d\n", name, pid, ppid)
}

const ipv4Fixture = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\toptions=1203<RXCSUM,TXCSUM>\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.0.2.8 netmask 0xffffff00 broadcast 192.0.2.255\n\tstatus: active\n"
const ipv6Fixture = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0x4\n\tinet6 2001:db8::1 prefixlen 64 autoconf secured\n\tstatus: active\n"

func fixtures(ctx context.Context, cmd fixedCommand) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	switch cmd {
	case hardwareCommand:
		return []byte("Mac14,2\n8\n8\n17179869184\n"), nil
	case receiptsCommand:
		return plist("org.example.zeta", "com.apple.pkg.Example"), nil
	case processesCommand:
		return []byte(processLine("launchd", 1, 0) + processLine("Demo App", 42, 1)), nil
	case ipv4Command:
		return []byte(ipv4Fixture), nil
	case ipv6Command:
		return []byte(ipv6Fixture), nil
	}
	return nil, ErrInvalid
}
func snapshot(t *testing.T) Snapshot {
	t.Helper()
	s, e := CollectWithSources(context.Background(), request(), commandSources(fixtures))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestContractRoundTrip(t *testing.T) {
	s := snapshot(t)
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(b)
	if e != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip: %v", e)
	}
	if s.Hardware.MemoryCapacityBytes != 17179869184 || s.Receipts.Identifiers[0] != "com.apple.pkg.Example" || s.Processes.Rows[1].AccountingName != "Demo App" || s.Network.IPv4.Rows[0].Name != "en0" || s.Network.IPv6.Rows[0].Addresses[0].IP != "2001:db8::1" {
		t.Fatal("incorrect projections")
	}
	if ValidateBinding(s, request().GenerationID, request().Consent.GrantID, request().CollectedAt) != nil {
		t.Fatal("binding")
	}
	if ValidateBinding(s, "sample_"+strings.Repeat("d", 32), s.GrantID, s.CollectedAt) == nil {
		t.Fatal("generation accepted")
	}
	if ValidateBinding(s, s.GenerationID, strings.Repeat("d", 32), s.CollectedAt) == nil {
		t.Fatal("grant accepted")
	}
	if ValidateBinding(s, s.GenerationID, s.GrantID, s.CollectedAt.Add(time.Second)) == nil {
		t.Fatal("time accepted")
	}
	for _, mutated := range [][]byte{append(bytes.Clone(b), '\n'), bytes.Replace(b, []byte(`"scope":`), []byte(`"unknown":0,"scope":`), 1), bytes.Replace(b, []byte(`"schemaVersion":`), []byte(`"scope":"evil","schemaVersion":`), 1), append(bytes.Clone(b), b...)} {
		if _, e := Decode(mutated); e == nil {
			t.Fatal("noncanonical/unknown/duplicate/trailing accepted")
		}
	}
}
func TestConsentBeforeAllSources(t *testing.T) {
	calls := 0
	p := commandSources(func(context.Context, fixedCommand) ([]byte, error) { calls++; return nil, errors.New("secret") })
	for _, mutate := range []func(*Request){func(r *Request) { r.Consent.Enabled = false }, func(r *Request) { r.Consent.Scope = "windows-read-inventory-v1" }, func(r *Request) { r.SenderBinding = strings.Repeat("d", 64) }, func(r *Request) { r.GenerationID = "bad" }, func(r *Request) { r.CollectedAt = time.Time{} }} {
		r := request()
		mutate(&r)
		if _, e := CollectWithSources(context.Background(), r, p); e == nil {
			t.Fatal("invalid admission accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := CollectWithSources(ctx, request(), p); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if calls != 0 {
		t.Fatal("source ran before admission")
	}
	if _, e := CollectWithSources(nil, request(), p); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	r := request()
	r.Consent.Enabled = false
	if _, e := CollectNative(context.Background(), r); !errors.Is(e, ErrDisabled) {
		t.Fatal("native default-off guard", e)
	}
	b, e := EncodeConsent(request().Consent, request().SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeConsent(append(b, ' '), request().SenderBinding); e == nil {
		t.Fatal("noncanonical consent accepted")
	}
}
func TestProviderFailuresAreIndependentAndSafe(t *testing.T) {
	p := commandSources(func(ctx context.Context, c fixedCommand) ([]byte, error) {
		if c == receiptsCommand {
			return nil, errors.New("private path /Users/alice/secret and command")
		}
		if c == ipv6Command {
			return nil, os.ErrPermission
		}
		return fixtures(ctx, c)
	})
	s, e := CollectWithSources(context.Background(), request(), p)
	if e != nil {
		t.Fatal(e)
	}
	if s.Hardware.Quality != "observed" || s.Processes.Quality != "observed" || s.Network.IPv4.Quality != "observed" || s.Network.IPv6.Quality != "denied" || s.Receipts.Reason != ErrUnavailable.Error() {
		t.Fatal("sibling failure or unsafe reason")
	}
	b, _ := Encode(s)
	if bytes.Contains(b, []byte("alice")) {
		t.Fatal("raw diagnostic leaked")
	}
	p = Sources{Hardware: func(context.Context) (Hardware, error) {
		return Hardware{Status: Status{HardwareSource, "observed", ""}, ModelIdentifier: "/secret"}, nil
	}}
	s, e = CollectWithSources(context.Background(), request(), p)
	if e != nil || s.Hardware.Reason != ErrMetadata.Error() {
		t.Fatal("bad injected provider accepted", e)
	}
}
func TestParserFailClosed(t *testing.T) {
	for _, raw := range []string{"Mac14,2\n8\n7\n100\n", "Mac14,2\n8\n8\n0\n", "Mac14,2\n-1\n8\n100\n", "Mac14,2\n8\n8\n100", "Mac14,2\r\n8\n8\n100\n", "/Users/name\n8\n8\n100\n"} {
		if _, e := ParseHardware([]byte(raw)); e == nil {
			t.Fatal("bad hardware accepted")
		}
	}
	for _, raw := range [][]byte{plist("com.example.one", "com.example.one"), plist("com.example.one\ncom.example.two"), []byte(`<plist version="1.0"><array><string><string>nested</string></string></array></plist>`), []byte(`<plist version="1.0"><array/><dict/></plist>`), []byte(`<!DOCTYPE plist [<!ENTITY leak SYSTEM "file:///secret">]><plist version="1.0"><array><string>&leak;</string></array></plist>`), []byte(`<plist version="1.0"><array><string>foo</string></array></plist><plist version="1.0"><array/></plist>`)} {
		if _, e := ParseReceipts(raw); e == nil {
			t.Fatal("bad receipt XML accepted")
		}
	}
	r, e := ParseReceipts([]byte(`<plist version="1.0"><array/></plist>`))
	if e != nil || r.Quality != "observed" || len(r.Identifiers) != 0 {
		t.Fatal("empty receipts", e)
	}
	for _, raw := range []string{"", processLine("launchd", 1, 0) + processLine("other", 1, 0), processLine("a 1 0\nx", 99, 1), "launchd 1 0\n", processLine("launchd", -1, 0), strings.TrimSuffix(processLine("launchd", 1, 0), "\n")} {
		if _, e := ParseProcesses([]byte(raw)); e == nil {
			t.Fatalf("bad processes accepted %q", raw)
		}
	}
	p, e := ParseProcesses([]byte(processLine("/private/path", 1, 0)))
	if e != nil || p.Rows[0].NameQuality != "unavailable" || p.Rows[0].AccountingName != "" {
		t.Fatal("path-like name not suppressed", e)
	}
	for _, raw := range []string{strings.Replace(ipv4Fixture, "0xffffff00", "0xff00ff00", 1), strings.Replace(ipv4Fixture, "192.0.2.8", "host.example", 1), ipv4Fixture + ipv4Fixture, strings.Replace(ipv4Fixture, "mtu 1500", "mtu 0", 1), "\tinet 192.0.2.8 netmask 0xffffff00\n", ipv4Fixture + "arbitrary footer\n"} {
		if _, e := ParseInterfaces([]byte(raw), false); e == nil {
			t.Fatal("bad interfaces accepted")
		}
	}
	for _, raw := range []string{strings.Replace(ipv6Fixture, "%en0", "%secret", 1), strings.Replace(ipv6Fixture, "prefixlen 64", "prefixlen 129", 1), strings.Replace(ipv6Fixture, "fe80::1%en0", "::ffff:192.0.2.1", 1)} {
		if _, e := ParseInterfaces([]byte(raw), true); e == nil {
			t.Fatal("bad IPv6 accepted")
		}
	}
}
func TestNoPrefixOnBounds(t *testing.T) {
	lines := strings.Repeat(processLine("app", 1, 0), MaxProcesses+1)
	if p, e := ParseProcesses([]byte(lines)); !errors.Is(e, ErrBounds) || len(p.Rows) != 0 {
		t.Fatal("process prefix", e)
	}
	ids := make([]string, MaxReceipts+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("pkg.%d", i)
	}
	if r, e := ParseReceipts(plist(ids...)); !errors.Is(e, ErrBounds) || len(r.Identifiers) != 0 {
		t.Fatal("receipt prefix", e)
	}
	raw := []byte(strings.Repeat("a", MaxSourceBytes+1))
	if _, e := ParseHardware(raw); !errors.Is(e, ErrBounds) {
		t.Fatal(e)
	}
	many := strings.Builder{}
	for i := 0; i <= MaxInterfaces; i++ {
		fmt.Fprintf(&many, "en%d: flags=1<UP> mtu 1500\n", i)
	}
	if v, e := ParseInterfaces([]byte(many.String()), false); !errors.Is(e, ErrBounds) || len(v.Rows) != 0 {
		t.Fatal("interface prefix", e)
	}
}
func TestOutputBoundConcurrentStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := newOutputBudget(1024, cancel)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := b.stdout()
			if i == 1 {
				w = b.stderr()
			}
			for j := 0; j < 100; j++ {
				_, _ = w.Write([]byte(strings.Repeat("x", 32)))
			}
		}(i)
	}
	wg.Wait()
	if !b.exceeded() || ctx.Err() != context.Canceled || len(b.bytes()) > 1024 {
		t.Fatal("output budget/cancel")
	}
	b = newOutputBudget(4, func() {})
	_, _ = b.stderr().Write([]byte("hide"))
	if len(b.bytes()) != 0 || !b.hasStderr() {
		t.Fatal("stderr retained")
	}
	if _, e := b.stdout().Write([]byte("x")); !errors.Is(e, ErrBounds) {
		t.Fatal("stderr not counted")
	}
}
func TestFixedCommandAllowlist(t *testing.T) {
	want := map[fixedCommand][]string{hardwareCommand: {"/usr/sbin/sysctl", "-n", "hw.model", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"}, receiptsCommand: {"/usr/sbin/pkgutil", "--pkgs-plist"}, processesCommand: {"/bin/ps", "-A", "-o", "ucomm=,pid=,ppid="}, ipv4Command: {"/sbin/ifconfig", "-a", "inet"}, ipv6Command: {"/sbin/ifconfig", "-a", "inet6"}}
	for k, w := range want {
		s, e := specification(k)
		if e != nil || !reflect.DeepEqual(append([]string{s.path}, s.args...), w) || s.maxBytes > MaxSourceBytes {
			t.Fatalf("unexpected command %v", k)
		}
	}
	if _, e := specification(255); e == nil {
		t.Fatal("unknown command accepted")
	}
}
func TestWireRejectsFabricatedAvailability(t *testing.T) {
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.Hardware.Quality = "unavailable"; s.Hardware.Reason = ErrUnavailable.Error() }, func(s *Snapshot) { s.Processes.Rows = append(s.Processes.Rows, s.Processes.Rows[0]) }, func(s *Snapshot) { s.Network.IPv4.Rows[0].Addresses[0].IP = "host.example" }, func(s *Snapshot) { s.Receipts.Source = "Homebrew" }, func(s *Snapshot) { s.Network.IPv6.Rows[0].Addresses[0].IP = "2001:0db8::1" }, func(s *Snapshot) { s.Receipts.Identifiers = nil }} {
		s := snapshot(t)
		mutate(&s)
		if Validate(s) == nil {
			t.Fatal("invalid metadata accepted")
		}
		raw, _ := json.Marshal(s)
		if _, e := Decode(raw); e == nil {
			t.Fatal("invalid wire accepted")
		}
	}
}
func FuzzParsers(f *testing.F) {
	f.Add([]byte(ipv4Fixture))
	f.Add(plist("com.example.app"))
	f.Add([]byte(processLine("app", 4, 1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxSourceBytes+1 {
			return
		}
		_, _ = ParseHardware(b)
		_, _ = ParseReceipts(b)
		_, _ = ParseProcesses(b)
		_, _ = ParseInterfaces(b, false)
		_, _ = ParseInterfaces(b, true)
		_, _ = Decode(b)
	})
}

func TestZeroPrefixAndNoObservedFabrication(t *testing.T) {
	v, e := ParseInterfaces([]byte(strings.Replace(ipv4Fixture, "0xffffff00", "0x0", 1)), false)
	if e != nil || v.Rows[0].Addresses[0].PrefixBits != 0 {
		t.Fatal("valid zero prefix", e)
	}
	for _, e := range []error{ErrBudget, context.DeadlineExceeded, ErrBounds, ErrUnsupported, ErrMetadata, ErrDenied} {
		s, err := CollectWithSources(context.Background(), request(), Sources{Hardware: func(context.Context) (Hardware, error) { return Hardware{}, e }})
		if err != nil || s.Hardware.Reason != SafeReason(e) || s.Hardware.Quality == "observed" {
			t.Fatal("failure projected as observation", err)
		}
	}
}

func TestMidCollectionCancellationDoesNotInvokeLaterSources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	p := Sources{Hardware: func(context.Context) (Hardware, error) { cancel(); return Hardware{}, context.Canceled }, Receipts: func(context.Context) (Receipts, error) { called = true; return Receipts{}, ErrUnavailable }}
	if _, e := CollectWithSources(ctx, request(), p); !errors.Is(e, context.Canceled) || called {
		t.Fatal("continued after cancellation", e)
	}
}
