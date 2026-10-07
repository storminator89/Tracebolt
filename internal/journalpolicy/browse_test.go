package journalpolicy

import (
	"localrmm/internal/journalview"
	"testing"
	"time"
)

func TestRetainedGrantIsFreshExplicitAndCannotPromoteOldPolicy(t *testing.T) {
	_, c, q, now := fixture()
	q.BrowseMode = journalview.BrowseMode
	q.Start = time.Unix(0, 0).UTC()
	for _, version := range []string{Version, VersionV2, VersionV3} {
		p := servicePolicy(AllSystemServices)
		if version != VersionV3 {
			p.SchemaVersion = version
			p.Scope = Scope
			p.ServiceAuthorization = ""
			p.AllowedUnits = []string{q.Unit}
			if version == Version {
				p.Revision = 0
				p.Generation = ""
			}
		}
		g, e := PolicyGeneration(p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := AuthorizeBound(p, c, q, g, now); e != ErrDenied {
			t.Fatal("old policy promoted", version)
		}
	}
	p := servicePolicy(AllSystemServices)
	p.SchemaVersion = VersionV4
	p.Scope = ScopeV4
	p.BrowsingContract = journalview.BrowseContract
	p.MaxWindowSeconds = 0
	p.MaxLookbackSeconds = 0
	raw, e := Encode(p)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := Decode(raw)
	if e != nil || decoded.BrowsingContract != journalview.BrowseContract {
		t.Fatal("v4 canonical grant failed", e)
	}
	g, _ := PolicyGeneration(p)
	q.Unit = "future-new-worker.service"
	permit, e := AuthorizeBound(p, c, q, g, now)
	if e != nil {
		t.Fatal("new supported service needs no allowlist edit", e)
	}
	p.Enabled = false
	if permit.Recheck(p, c, now) == nil {
		t.Fatal("revoked grant released page")
	}
	p.Enabled = true
	p.SchemaVersion = VersionV3
	if Validate(p) == nil {
		t.Fatal("v4 declaration downgraded")
	}
}
