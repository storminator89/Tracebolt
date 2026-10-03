package assessment

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNativeDebianComparatorPolicyCases(t *testing.T) {
	if _, err := os.Stat("/usr/bin/dpkg"); err != nil {
		t.Skip("native dpkg unavailable; no semver substitute")
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"1:1.0-1", "2.0-9", 1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0-2", "1.0-10", -1},
		{"1.0-1+deb13u1", "1.0-1+deb13u2", -1},
		{"1.0-1~bpo13+1", "1.0-1", -1},
		{"1.0-1+b1", "1.0-1", 1},
		{"1.0", "1.0-0", 0},
		{"2:1.0-1", "1:9.9-99", 1},
		{"1.0+git1-1", "1.0-1", 1},
		{"1:2.0-1+deb13u2", "1:2.0-1+deb13u2", 0},
	}
	for _, tc := range cases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got, err := (NativeDebianComparator{}).Compare(context.Background(), tc.a, tc.b)
			if err != nil || got != tc.want {
				t.Fatalf("dpkg policy ordering got %d %v, want %d", got, err, tc.want)
			}
		})
	}
}
func TestDebianVersionValidationAndCancellation(t *testing.T) {
	for _, version := range []string{"", "-1", "--help", "1.0;evil", "1.0\n2.0", "bad:1.0", "1.0-", "1.0_1", "1.0/1", "1:abc"} {
		if ValidDebianVersion(version) {
			t.Fatalf("accepted %q", version)
		}
		if _, err := (NativeDebianComparator{}).Compare(context.Background(), version, "1.0"); !errors.Is(err, ErrVersionInvalid) {
			t.Fatal("invalid version reached comparator")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (NativeDebianComparator{}).Compare(ctx, "1.0", "2.0"); !errors.Is(err, ErrComparatorUnavailable) {
		t.Fatal("cancelled comparison not bounded")
	}
}
