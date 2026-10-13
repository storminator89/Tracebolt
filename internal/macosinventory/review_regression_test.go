package macosinventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkSecondFamilyTimeoutRetainsCompletedFirstFamily(t *testing.T) {
	ipv4, e := ParseInterfaces([]byte(ipv4Fixture), false)
	if e != nil {
		t.Fatal(e)
	}
	p := Sources{Network: func(ctx context.Context) (Network, error) {
		<-ctx.Done()
		return Network{IPv4: ipv4, IPv6: EmptyInterfaces(IPv6Source, SafeReason(ctx.Err()))}, nil
	}}
	s, e := CollectWithSources(context.Background(), request(), p)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(s.Network.IPv4, ipv4) || s.Network.IPv6.Quality != "unavailable" || s.Network.IPv6.Reason != ErrBudget.Error() {
		t.Fatalf("lost independent family dispositions: %#v", s.Network)
	}
	if Validate(s) != nil {
		t.Fatal("invalid snapshot")
	}
}

func TestNetworkCallerCancellationStillDiscardsCompletedFamily(t *testing.T) {
	ipv4, e := ParseInterfaces([]byte(ipv4Fixture), false)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := Sources{Network: func(context.Context) (Network, error) {
		cancel()
		return Network{IPv4: ipv4, IPv6: EmptyInterfaces(IPv6Source, ErrBudget.Error())}, nil
	}}
	s, e := CollectWithSources(ctx, request(), p)
	if !errors.Is(e, context.Canceled) || !reflect.DeepEqual(s, Snapshot{}) {
		t.Fatal("retained snapshot after caller cancellation", e)
	}
}

func TestNetworkAggregateErrorAndInvalidFamilyStillFailClosed(t *testing.T) {
	ipv4, e := ParseInterfaces([]byte(ipv4Fixture), false)
	if e != nil {
		t.Fatal(e)
	}
	p := Sources{Network: func(context.Context) (Network, error) { return Network{IPv4: ipv4}, ErrBudget }}
	s, e := CollectWithSources(context.Background(), request(), p)
	if e != nil || s.Network.IPv4.Quality != "unavailable" || s.Network.IPv6.Quality != "unavailable" || s.Network.IPv4.Reason != ErrBudget.Error() {
		t.Fatal("aggregate error not applied", e)
	}
	p.Network = func(context.Context) (Network, error) {
		return Network{IPv4: ipv4, IPv6: Interfaces{Status: Status{IPv6Source, "observed", ""}}}, nil
	}
	s, e = CollectWithSources(context.Background(), request(), p)
	if e != nil || !reflect.DeepEqual(s.Network.IPv4, ipv4) || s.Network.IPv6.Reason != ErrMetadata.Error() {
		t.Fatal("invalid family accepted or valid sibling erased", e)
	}
}

func TestProcessInvalidUTF8NameDoesNotErasePIDRows(t *testing.T) {
	for _, name := range []string{strings.Repeat("\xff", 16), strings.Repeat("a", 15) + "\xe2"} {
		raw := []byte(processLine("launchd", 1, 0) + name + "    42     1\n")
		p, e := ParseProcesses(raw)
		if e != nil || len(p.Rows) != 2 || p.Rows[0].AccountingName != "launchd" || p.Rows[1].PID != 42 || p.Rows[1].ParentPID != 1 || p.Rows[1].AccountingName != "" || p.Rows[1].NameQuality != "unavailable" {
			t.Fatalf("name-only failure erased process evidence: %v, %#v", e, p)
		}
		if !validProcesses(p) {
			t.Fatal("invalid sanitized process rows")
		}
	}
	for _, raw := range []string{processLine("app", 42, 1) + strings.Repeat("a", 16) + " \xff 1\n", processLine("a 1 0\nx", 99, 1)} {
		if _, e := ParseProcesses([]byte(raw)); e == nil {
			t.Fatal("malformed numeric field or newline framing accepted")
		}
	}
	if _, e := ParseHardware([]byte("Mac14,\xff\n8\n8\n17179869184\n")); e == nil {
		t.Fatal("hardware UTF-8 policy relaxed")
	}
	if _, e := ParseInterfaces([]byte(strings.Replace(ipv4Fixture, "en0:", "en\xff:", 1)), false); e == nil {
		t.Fatal("network UTF-8 policy relaxed")
	}
}

func TestInterfaceCLATOppositeFamilyIsValidatedAndDiscarded(t *testing.T) {
	want, e := ParseInterfaces([]byte(ipv4Fixture), false)
	if e != nil {
		t.Fatal(e)
	}
	raw := ipv4Fixture + "\tinet6 2001:db8::123 prefixlen 128 clat46\n"
	got, e := ParseInterfaces([]byte(raw), false)
	if e != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("CLAT erased or contaminated IPv4 result", e)
	}
	want6, e := ParseInterfaces([]byte(ipv6Fixture), true)
	if e != nil {
		t.Fatal(e)
	}
	got6, e := ParseInterfaces([]byte(ipv6Fixture+"\tinet 192.0.2.8 netmask 0xffffff00\n"), true)
	if e != nil || !reflect.DeepEqual(got6, want6) {
		t.Fatal("opposite IPv4 contaminated IPv6 result", e)
	}
	for _, bad := range []string{"\tinet6 invalid prefixlen 128 clat46\n", "\tinet6 2001:db8::123 prefixlen 129 clat46\n", "\tinet 192.0.2.8 netmask 0xff00ff00\n"} {
		if _, e := ParseInterfaces([]byte(ipv4Fixture+bad), false); e == nil {
			t.Fatal("malformed address record accepted")
		}
	}
	// Opposite-family metadata is not added to the selected row count or copied
	// into the independently unavailable IPv6 source result.
	p := commandSources(func(ctx context.Context, c fixedCommand) ([]byte, error) {
		if c == ipv4Command {
			return []byte(raw), nil
		}
		if c == ipv6Command {
			return nil, ErrBudget
		}
		return fixtures(ctx, c)
	})
	s, e := CollectWithSources(context.Background(), request(), p)
	if e != nil || !reflect.DeepEqual(s.Network.IPv4, want) || s.Network.IPv6.Quality != "unavailable" || len(s.Network.IPv6.Rows) != 0 {
		t.Fatal("cross-family availability promotion", e)
	}
}

func TestNativeErrorSanitizationPreservesCanonicalClassification(t *testing.T) {
	raw := fmt.Errorf("exec /private/diagnostic: %w", os.ErrPermission)
	sanitized := safeError(raw)
	if !errors.Is(sanitized, ErrDenied) || sanitized.Error() != ErrDenied.Error() || safeError(sanitized) != ErrDenied {
		t.Fatal("permission classification lost or diagnostic retained", sanitized)
	}
	p := Sources{Hardware: func(context.Context) (Hardware, error) { return Hardware{}, sanitized }}
	s, e := CollectWithSources(context.Background(), request(), p)
	if e != nil || s.Hardware.Quality != "denied" || s.Hardware.Reason != ErrDenied.Error() {
		t.Fatal("denied source downgraded", e)
	}
	for _, sentinel := range []error{ErrDenied, ErrUnsupported, ErrMetadata, ErrBounds, ErrBudget, ErrUnavailable} {
		if got := safeError(fmt.Errorf("sensitive native detail: %w", sentinel)); got != sentinel || safeError(got) != sentinel {
			t.Fatal("noncanonical sanitized error", got)
		}
	}
	if got := safeError(errors.New("raw private path and diagnostics")); got != ErrUnavailable {
		t.Fatal("raw diagnostic exposed", got)
	}
}

func TestOppositeFamilyDoesNotConsumeSelectedAddressBudget(t *testing.T) {
	raw := "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
	for i := 1; i <= MaxAddresses; i++ {
		raw += fmt.Sprintf("\tinet 192.0.2.%d netmask 0xffffff00\n", i)
	}
	raw += "\tinet6 2001:db8::123 prefixlen 128 clat46\n"
	v, e := ParseInterfaces([]byte(raw), false)
	if e != nil || len(v.Rows) != 1 || len(v.Rows[0].Addresses) != MaxAddresses {
		t.Fatal("opposite family consumed selected budget", e)
	}
	if _, e := ParseInterfaces([]byte(raw+"\tinet 192.0.2.250 netmask 0xffffff00\n"), false); !errors.Is(e, ErrBounds) {
		t.Fatal("selected address bound bypassed", e)
	}
	if _, e := ParseInterfaces([]byte(raw+"\tinet 192.0.2.1 netmask 0xffffff00\n"), false); e == nil {
		t.Fatal("duplicate selected address accepted")
	}
}
