package actionpermit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAffectedServicesProjectionCanonicalAndV1Unchanged(t *testing.T) {
	good := []string{"dependent.service", "fixture.service"}
	digest, e := AffectedServicesDigest(good)
	if e != nil || !ValidDigest(digest) {
		t.Fatal(digest, e)
	}
	for _, list := range [][]string{nil, {}, {"fixture.service", "dependent.service"}, {"fixture.service", "fixture.service"}, {"x@instance.service"}, {"x.socket"}, {"../x.service"}, make([]string, MaxAffectedServices+1)} {
		if _, e := AffectedServicesDigest(list); e == nil {
			t.Fatal("noncanonical projection accepted", list)
		}
	}
	shortened, _ := AffectedServicesDigest([]string{"fixture.service"})
	added, _ := AffectedServicesDigest([]string{"dependent.service", "extra.service", "fixture.service"})
	if shortened == digest || added == digest {
		t.Fatal("changed impact projection unbound")
	}
	p, _, _ := fixture(t)
	old, _ := json.Marshal(p.Plan)
	if strings.Contains(string(old), "affectedServicesDigest") {
		t.Fatal("v1 bytes changed")
	}
	p.Plan.AffectedServicesDigest = digest
	if _, e := PlanDigest(p.Plan); e == nil {
		t.Fatal("v1 widened")
	}
	p.Version = VersionV2
	p.Plan.Version = PlanVersionV2
	p.Plan.AffectedServicesDigest = ""
	if _, e := PlanDigest(p.Plan); e == nil {
		t.Fatal("v2 missing affected projection accepted")
	}
	p.Plan.AffectedServicesDigest = digest
	if _, e := PlanDigest(p.Plan); e != nil {
		t.Fatal(e)
	}
}
