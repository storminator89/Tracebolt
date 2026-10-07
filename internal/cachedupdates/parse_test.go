package cachedupdates

import (
	"context"
	"strings"
	"testing"
)

func TestDpkgQueryHoldsResidualAndMalformed(t *testing.T) {
	raw := "curl\t1:8.14.1-2\tamd64\tinstall\tinstalled\tok\nheld-package:amd64\t2.0~rc1-1\tamd64\thold\tinstalled\tok\nremoved\t\t\tpurge\tnot-installed\tok\n"
	got, e := parseInstalled(context.Background(), []byte(raw))
	if e != nil || len(got) != 2 || !got["held-package:amd64"].held {
		t.Fatal(got, e)
	}
	for _, bad := range []string{raw + raw, "bad;touch /tmp/pwned\t1\tamd64\tinstall\tinstalled\tok\n", "pkg:arm64\t1\tamd64\tinstall\tinstalled\tok\n", strings.Replace(raw, "\tinstall\t", "\tINVALID\t", 1)} {
		if _, e := parseInstalled(context.Background(), []byte(bad)); e == nil {
			t.Fatal("accepted invalid query")
		}
	}
}
func TestPolicyOnlyRetainsSelectedNativeFields(t *testing.T) {
	p := []installedPackage{{"curl", "amd64", "1:8.14.1-2", false}, {"held-package", "amd64", "2.0~rc1-1", true}}
	raw := "curl:\n  Installed: 1:8.14.1-2\n  Candidate: 1:8.14.1-2+deb13u1\n  Version table:\n     1:8.14.1-2+deb13u1 500\n        500 https://secret:password@private.example.invalid/repository trixie/main amd64 Packages\nheld-package:amd64:\n  Installed: 2.0~rc1-1\n  Candidate: (none)\n  Version table:\n"
	got, e := parsePolicy(context.Background(), []byte(raw), p)
	if e != nil || got["curl:amd64"] != "1:8.14.1-2+deb13u1" || got["held-package:amd64"] != "" {
		t.Fatal(got, e)
	}
	for _, bad := range []string{strings.Replace(raw, "Installed: 1:8.14.1-2", "Installed: 0.1", 1), strings.Replace(raw, "Candidate: 1:8.14.1-2+deb13u1", "Candidate: $(touch /tmp/pwned)", 1), raw + raw, strings.Replace(raw, "curl:", "unrequested:", 1), "  Candidate: 2.0\n"} {
		if _, e := parsePolicy(context.Background(), []byte(bad), p); e == nil {
			t.Fatal("accepted invalid policy")
		}
	}
	for _, arch := range []string{"arm64", "armhf", "all"} {
		// APT may omit the architecture in a native header. Each collector batch
		// has one architecture, so both forms retain the exact package key.
		for _, header := range []string{"fixture-package", "fixture-package:" + arch} {
			p := []installedPackage{{"fixture-package", arch, "1.0-1", false}}
			raw := header + ":\n  Installed: 1.0-1\n  Candidate: 2.0-1\n  Version table:\n"
			got, err := parsePolicy(context.Background(), []byte(raw), p)
			if err != nil || len(got) != 1 || got["fixture-package:"+arch] != "2.0-1" {
				t.Fatal("ARM64 or multiarch APT header lost identity")
			}
		}
	}
}
func TestMissingPolicyIsUnknownNotZeroSuccess(t *testing.T) {
	got, e := parsePolicy(context.Background(), nil, []installedPackage{{"curl", "amd64", "1.0", false}})
	if e != nil || len(got) != 0 {
		t.Fatal(got, e)
	}
}
