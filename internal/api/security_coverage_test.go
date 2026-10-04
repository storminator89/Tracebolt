package api

import (
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/offlinecatalog"
	"localrmm/internal/operational"
	"testing"
	"time"
)

func softwareCoverageFixture() enrollmentstore.OperationalView {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	op := operational.Empty(now, operational.ReasonSourceMissing)
	m := op.Sections.Software.Meta
	m.Quality = operational.Healthy
	m.Reason = operational.ReasonNone
	m.Complete = true
	m.CountExact = true
	m.ObservedCount = 1
	op.Sections.Software = operational.SoftwareSection{Meta: m, Items: []operational.Software{{Name: "fixture", Version: "1.0-1", Architecture: "amd64", Manager: "dpkg"}}}
	view := enrollmentstore.EmptyOperationalView("agent_00000000000000000000000000000001", now)
	view.Status = "fresh"
	view.Snapshot = &op
	view.ReceivedAt = &now
	return view
}
func TestSecurityCoverageSeparatesInventoryFromUnknownAssessments(t *testing.T) {
	view := softwareCoverageFixture()
	got := projectSecurityCoverage(view, offlinecatalog.DisabledView(view.ServerNow))
	if got.Inventory.Coverage != "observed" || got.Inventory.Freshness != "fresh" || got.Inventory.InstalledCount == nil || *got.Inventory.InstalledCount != 1 {
		t.Fatal("observed inventory lost")
	}
	if got.Vulnerabilities.Coverage != "unknown" || got.Vulnerabilities.AffectedCVEs != nil || got.Vulnerabilities.ReviewCandidates != nil || got.OfferedUpdates.OfferedCount != nil {
		t.Fatal("inventory invented assessments")
	}
	// Even a parsed uploaded catalog does not supply missing client/vendor facts.
	catalog := offlinecatalog.View{Catalog: &offlinecatalog.Metadata{SHA256: "fixture", Synthetic: true}}
	got = projectSecurityCoverage(view, catalog)
	if got.Vulnerabilities.AffectedCVEs != nil || got.Vulnerabilities.ReasonCodes[0] != "advisory_authority_unverified" || got.Catalog.OriginAssurance != "unverified" || got.Catalog.Freshness != "unknown" {
		t.Fatal("upload promoted vendor or endpoint trust")
	}
}
func TestSecurityCoveragePartialStaleUnknownAndRetainedRemainDistinct(t *testing.T) {
	v := softwareCoverageFixture()
	v.Snapshot.Sections.Software.Meta.Complete = false
	v.Snapshot.Sections.Software.Meta.Truncated = true
	v.Snapshot.Sections.Software.Meta.Reason = operational.ReasonItemLimit
	v.Snapshot.Sections.Software.Meta.ObservedCount = 2
	got := projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.Coverage != "partial" || got.Inventory.InstalledCount != nil || got.Inventory.ReportedItemCount == nil || *got.Inventory.ReportedItemCount != 1 {
		t.Fatal("partial became complete or unavailable")
	}
	v.ServerNow = v.ServerNow.Add(3 * time.Minute)
	got = projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.Freshness != "stale" {
		t.Fatal("old software stayed fresh")
	}
	v = softwareCoverageFixture()
	last := v.Snapshot.Sections.Software
	last.Meta.Quality = "stale"
	v.LastGood.Software = &last
	unknown := operational.Empty(v.ServerNow, operational.ReasonPermissionDenied)
	v.Snapshot = &unknown
	got = projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.Coverage != "observed" || got.Inventory.Freshness != "stale" || !got.Inventory.CollectedAt.Equal(last.Meta.ObservedAt) {
		t.Fatal("retained source lost age/provenance")
	}
	v.LastGood.Software.Meta.Quality = operational.Unknown
	got = projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.Coverage != "unknown" || got.Inventory.ReportedItemCount != nil {
		t.Fatal("invalid unknown cache became observed")
	}
	v = softwareCoverageFixture()
	v.Status = "revoked"
	got = projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.Freshness != "stale" || got.CollectionStatus != "revoked" {
		t.Fatal("revoked source stayed fresh")
	}
}
func TestSecurityCoverageLegitimateEmptyInventoryIsNotZeroCVEs(t *testing.T) {
	v := softwareCoverageFixture()
	v.Snapshot.Sections.Software.Items = []operational.Software{}
	v.Snapshot.Sections.Software.Meta.ObservedCount = 0
	got := projectSecurityCoverage(v, offlinecatalog.View{})
	if got.Inventory.InstalledCount == nil || *got.Inventory.InstalledCount != 0 || got.Vulnerabilities.AffectedCVEs != nil || got.OfferedUpdates.OfferedCount != nil {
		t.Fatal("empty inventory confused with zero vulnerabilities/updates")
	}
}
