package native

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPrerequisiteDiagnosticsHaveFiniteLocationAndCanonicalRights(t *testing.T) {
	for _, c := range []struct {
		i, n int
		pf   bool
		want string
	}{{0, 1, true, "volume-root"}, {0, 3, false, "volume-root"}, {1, 2, true, "program-files"}, {2, 3, false, "program-data"}, {1, 3, true, "intermediate"}} {
		if ancestorLocation(c.i, c.n, c.pf) != c.want {
			t.Fatal("location leaked path-specific detail")
		}
	}
	if got := replacementRights(0x10000000 | 0x40 | 0x2 | 0x100); !reflect.DeepEqual(got, []string{"generic-all", "delete-child", "add-file", "write-attributes"}) {
		t.Fatal("noncanonical right classification")
	}
	for _, d := range []PrerequisiteDiagnostic{{"volume-root", "owner-untrusted", []string{}}, {"program-data", "untrusted-write-grant", []string{"add-file", "write-attributes"}}} {
		if !d.valid() {
			t.Fatal("finite diagnostic refused")
		}
	}
}
func TestPrerequisiteDiagnosticsRejectNativeDetailsAndMisleadingFacts(t *testing.T) {
	for _, d := range []PrerequisiteDiagnostic{
		{`C:\private`, "owner-untrusted", []string{}}, {"volume-root", "S-1-5-private", []string{}}, {"volume-root", "owner-untrusted", nil},
		{"volume-root", "owner-untrusted", []string{"delete"}}, {"volume-root", "untrusted-write-grant", []string{}}, {"volume-root", "untrusted-write-grant", []string{"private-mask"}},
		{"volume-root", "untrusted-write-grant", []string{"delete", "delete"}}, {"volume-root", "untrusted-write-grant", []string{"delete", "generic-all"}},
	} {
		if d.valid() {
			t.Fatal("raw or misleading diagnostic allowed")
		}
	}
	for _, p := range []PrerequisiteObservation{
		{Status: "supported", Check: "complete", Reason: "none", Diagnostic: &PrerequisiteDiagnostic{Location: "volume-root", Failure: "owner-untrusted", Rights: []string{}}},
		{Status: "blocked", Check: "ancestor-policy", Reason: "prerequisite-blocked"},
	} {
		if p.Valid() {
			t.Fatal("diagnostic attached to wrong result or missing from ancestor failure")
		}
	}
	d := PrerequisiteDiagnostic{Location: "volume-root", Failure: "open-failed", Rights: []string{}}
	b, _ := json.Marshal(d)
	for _, raw := range []string{`C:\`, "S-1-", "D:", "handle", "token"} {
		if strings.Contains(string(b), raw) {
			t.Fatal("raw host detail escaped")
		}
	}
}

func TestProgramDataWriteMaskRetainsEveryDestructiveBit(t *testing.T) {
	const benign = uint32(0x112)
	strict, shared := ancestorWriteMask(false), ancestorWriteMask(true)
	if strict^shared != benign || shared&benign != 0 {
		t.Fatal("exception is not exact")
	}
	for _, bit := range []uint32{0x10000000, 0x40000000, 0x80000, 0x40000, 0x10000, 0x40} {
		if strict&bit == 0 || shared&bit == 0 {
			t.Fatal("destructive grant no longer rejected")
		}
	}
}
