package macosinventory

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestInterfaceDiagnosticClosedFirstRejection(t *testing.T) {
	header := "en0: flags=1<UP> mtu 1500\n"
	cases := []struct {
		name, raw, code string
		ipv6            bool
		bounds          bool
	}{
		{"size", strings.Repeat("x", MaxSourceBytes+1), "source_size", false, true},
		{"control", header + "\tignored \r\n", "source_control", false, false},
		{"newline", strings.TrimSuffix(header, "\n"), "source_newline", false, false},
		{"line", header + "\t" + strings.Repeat("x", 4096) + "\n", "source_line_size", false, true},
		{"encoding", header + "\tignored \xff\n", "source_encoding", false, false},
		{"empty", header + "\n", "empty_record", false, false},
		{"interface limit", strings.Repeat(header, MaxInterfaces+1), "interface_limit", false, true},
		{"header", "unrecognized native footer\n", "header_shape", false, false},
		{"flags", "en0: flags=xyz<UP> mtu 1500\n", "header_flags", false, false},
		{"name", "bad/name: flags=1<UP> mtu 1500\n", "header_name", false, false},
		{"missing MTU", "en0: flags=1<UP> metric 1\n", "mtu_missing", false, false},
		{"duplicate MTU", "en0: flags=1<UP> mtu 1500 mtu 1500\n", "mtu_duplicate", false, false},
		{"zero MTU", "en0: flags=1<UP> mtu 0\n", "mtu_value", false, false},
		{"MTU number", "en0: flags=1<UP> mtu invalid\n", "mtu_value", false, false},
		{"orphan", "\tinet 192.0.2.1 netmask 0xffffff00\n", "orphan_record", false, false},
		{"blank", header + "\t \n", "blank_record", false, false},
		{"address shape", header + "\tinet 192.0.2.1\n", "address_shape", false, false},
		{"numeric", header + "\tinet host.invalid netmask 0xffffff00\n", "address_numeric", false, false},
		{"family", header + "\tinet6 192.0.2.1 prefixlen 64\n", "address_family", true, false},
		{"mapped", header + "\tinet6 ::ffff:192.0.2.1 prefixlen 128\n", "address_family", true, false},
		{"zone", header + "\tinet6 fe80::1%other0 prefixlen 64\n", "address_zone", true, false},
		{"missing prefix", header + "\tinet 192.0.2.1 broadcast 192.0.2.255\n", "prefix_missing", false, false},
		{"duplicate prefix", header + "\tinet 192.0.2.1 netmask 0xffffff00 netmask 0xffffff00\n", "prefix_duplicate", false, false},
		{"noncontiguous mask", header + "\tinet 192.0.2.1 netmask 0xff00ff00\n", "prefix_value", false, false},
		{"invalid prefix", header + "\tinet6 2001:db8::1 prefixlen 129\n", "prefix_value", true, false},
		{"address limit", header + strings.Repeat("\tinet 192.0.2.1 netmask 0xffffff00\n", MaxAddresses+1), "address_limit", false, true},
		{"empty result", "", "result_empty", false, false},
		{"duplicate interface", header + header, "duplicate_interface", false, false},
		{"duplicate address", header + strings.Repeat("\tinet 192.0.2.1 netmask 0xffffff00\n", 2), "duplicate_address", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, code, err := ParseInterfacesWithDiagnostic([]byte(tc.raw), tc.ipv6)
			wantErr := ErrMetadata
			if tc.bounds {
				wantErr = ErrBounds
			}
			if code.String() != tc.code || err != wantErr || !reflect.DeepEqual(got, Interfaces{}) {
				t.Fatalf("unexpected fixed rejection: code=%s error=%v", code, err)
			}
			old, oldErr := legacyParseInterfaces([]byte(tc.raw), tc.ipv6)
			if oldErr != err || !reflect.DeepEqual(old, got) {
				t.Fatal("diagnostic changed legacy result")
			}
		})
	}
	for _, tc := range []struct {
		raw  string
		ipv6 bool
	}{
		{ipv4Fixture, false}, {ipv6Fixture, true}, {"stf0: flags=0<> mtu 1280\n", false},
		{header + "\tinet 192.0.2.1 --> 192.0.2.2 netmask 0xffffffff\n", false},
		{header + "\tinet6 fe80::1%en0 --> fe80::2%en0 prefixlen 64 scopeid 0x4\n", true},
		{header + "\tinet6 2001:db8::1 prefixlen 128 clat46\n", false},
	} {
		got, code, err := ParseInterfacesWithDiagnostic([]byte(tc.raw), tc.ipv6)
		old, oldErr := legacyParseInterfaces([]byte(tc.raw), tc.ipv6)
		if err != nil || code != InterfaceParseOK || oldErr != err || !reflect.DeepEqual(old, got) {
			t.Fatal("valid source projection changed")
		}
	}
	if InterfaceParseNotRun.String() != "not_run" || InterfaceParseCode(255).String() != "unclassified" {
		t.Fatal("unknown diagnostic code not contained")
	}
}

// Compare against a frozen source-only copy of the pre-diagnostic parser.
// The duplicated implementation is test-only; the runtime uses one parser.
func FuzzInterfaceDiagnosticLegacyParity(f *testing.F) {
	for _, raw := range []string{ipv4Fixture, ipv6Fixture, "", "stf0: flags=0<> mtu 1280\n"} {
		f.Add([]byte(raw), false)
		f.Add([]byte(raw), true)
	}
	f.Fuzz(func(t *testing.T, raw []byte, ipv6 bool) {
		got, code, err := ParseInterfacesWithDiagnostic(raw, ipv6)
		want, wantErr := legacyParseInterfaces(raw, ipv6)
		if err != wantErr || !reflect.DeepEqual(got, want) {
			t.Fatal("diagnostic changed legacy admission or result")
		}
		if (err == nil) != (code == InterfaceParseOK) || code == InterfaceParseNotRun || code.String() == "unclassified" {
			t.Fatal("inconsistent rejection classification")
		}
		if err != nil && !errors.Is(err, ErrMetadata) && !errors.Is(err, ErrBounds) {
			t.Fatal("noncanonical error")
		}
	})
}

func TestInterfaceDiagnosticNeverRetainsInput(t *testing.T) {
	for _, secret := range []string{"secret_canary_alpha", "other_canary_beta"} {
		_, code, err := ParseInterfacesWithDiagnostic([]byte("en0: flags=1<UP> mtu 1500\n\tinet "+secret+" netmask 0xffffff00\n"), false)
		if code.String() != "address_numeric" || err != ErrMetadata || strings.Contains(fmt.Sprint(code, err), secret) {
			t.Fatal("diagnostic depends on raw content")
		}
	}
}
