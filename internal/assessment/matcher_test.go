package assessment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// This comparator is an explicit synthetic test oracle, never SemVer and never
// production code. Native Debian semantics have a separate dpkg acceptance test.
type fixtureComparator struct{}

func (fixtureComparator) Compare(_ context.Context, a, b string) (int, error) {
	positions := map[string]int{"1:2.0-1+deb13u1": 1, "1:2.0-1+deb13u2": 2, "1:2.0-1+deb13u3": 3}
	x, ok := positions[a]
	y, other := positions[b]
	if !ok || !other {
		return 0, ErrVersionInvalid
	}
	if x < y {
		return -1, nil
	}
	if x > y {
		return 1, nil
	}
	return 0, nil
}

type failComparator struct{}

func (failComparator) Compare(context.Context, string, string) (int, error) {
	return 0, errors.New("private stderr must not appear")
}
func fixtureDocument(t *testing.T) debianDocument {
	t.Helper()
	data, err := os.ReadFile("testdata/debian-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc debianDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
func fixtureSnapshot(t *testing.T, edit func(*debianDocument, *SourceSnapshot)) *DebianSnapshot {
	t.Helper()
	doc := fixtureDocument(t)
	now := testNow()
	source := SourceSnapshot{ID: "synthetic-debian-001", Provider: "debian-security-tracker", Kind: "advisory", FetchedAt: now.Add(-time.Minute), ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Trust: "synthetic_fixture", Synthetic: true}
	if edit != nil {
		edit(&doc, &source)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	source.SHA256 = hex.EncodeToString(hash[:])
	snapshot, err := ParseDebianSnapshot(bytes.NewReader(data), source)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
func fixtureInventory(t *testing.T) Inventory {
	t.Helper()
	packages, hash, err := ParseDpkgStatus(context.Background(), strings.NewReader(strings.Split(syntheticStatus, "\n\n")[0]+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := &packages[0]
	p.Origin = OriginEvidence{Distribution: "debian", Release: "trixie", RepositoryID: "synthetic-repository", EvidenceID: "synthetic-artifact-binding", Package: p.Name, BinaryVersion: p.Version, Architecture: p.Architecture, SourcePackage: p.SourcePackage, SourceVersion: p.SourceVersion, VerifiedMetadata: true, InstalledArtifactVerified: true}
	now := testNow()
	return InventoryFromParsed(testPlatform(), packages, SourceSnapshot{ID: "synthetic-inventory-001", Provider: "synthetic-dpkg", Kind: "inventory", SHA256: hash, FetchedAt: now, ValidatedAt: now, ExpiresAt: now.Add(time.Hour), Trust: "synthetic_fixture", Synthetic: true}, now)
}
func setSourceVersion(inventory *Inventory, version string) {
	p := &inventory.Packages[0]
	p.SourceVersion = version
	p.Origin.SourceVersion = version
}
func evaluate(t *testing.T, inventory Inventory, snapshot *DebianSnapshot) VulnerabilityAssessment {
	t.Helper()
	return AssessDebian(context.Background(), inventory, snapshot, fixtureComparator{}, testNow())
}
func TestResolvedArchiveStillComparesInstalledSourceVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		verdict Verdict
		count   int
	}{{"1:2.0-1+deb13u1", Affected, 1}, {"1:2.0-1+deb13u2", Fixed, 0}, {"1:2.0-1+deb13u3", Fixed, 0}} {
		t.Run(tc.version, func(t *testing.T) {
			inventory := fixtureInventory(t)
			setSourceVersion(&inventory, tc.version)
			result := evaluate(t, inventory, fixtureSnapshot(t, nil))
			if len(result.Matches) != 1 || result.Matches[0].Verdict != tc.verdict || result.Quality.Coverage != Assessed || result.AffectedCVEs == nil || *result.AffectedCVEs != tc.count {
				t.Fatalf("wrong scoped result: %+v", result)
			}
			match := result.Matches[0]
			if !match.Synthetic || match.PublishedFixedVersion != "1:2.0-1+deb13u2" || match.Activation != "unknown" {
				t.Fatal("fix evidence or activation separation lost")
			}
			if match.SourcePackage == match.Package {
				t.Fatal("binary was substituted for source name")
			}
			if updates := UnimplementedUpdates(testNow()); updates.OfferedCount != nil || len(updates.Updates) != 0 {
				t.Fatal("fix threshold became an update offer")
			}
		})
	}
}
func TestFixedVersionZeroIsNotAffectedSentinel(t *testing.T) {
	snapshot := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) { doc.Rules[0].FixedVersion = "0" })
	result := AssessDebian(context.Background(), fixtureInventory(t), snapshot, failComparator{}, testNow())
	if len(result.Matches) != 1 || result.Matches[0].Verdict != NotAffected || result.Matches[0].PublishedFixedVersion != "" || result.Matches[0].FixAvailability == "published" {
		t.Fatal("not-affected sentinel treated as patch version")
	}
}
func TestAmbiguousVendorStatesStayCandidates(t *testing.T) {
	cases := []struct {
		name, status, fixed, release string
		reason                       string
	}{
		{"unfixed", "open", "", "trixie", "unfixed_vendor_record_requires_version_evidence"},
		{"undetermined", "undetermined", "", "trixie", "vendor_status_undetermined"},
		{"resolved missing fix", "resolved", "", "trixie", "vendor_record_uninterpretable"},
		{"future state", "future-status", "", "trixie", "vendor_record_uninterpretable"},
		{"missing target release", "resolved", "1:2.0-1+deb13u2", "bookworm", "release_record_missing"},
		{"inconsistent open fix", "open", "1:2.0-1+deb13u2", "trixie", "vendor_record_uninterpretable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) {
				rule := &doc.Rules[0]
				rule.Status = tc.status
				rule.FixedVersion = tc.fixed
				rule.Release = tc.release
				rule.Qualifications = []string{"no-dsa", "postponed"}
			})
			result := evaluate(t, fixtureInventory(t), snapshot)
			if len(result.Matches) != 1 || result.Matches[0].Verdict != NeedsReview || result.Matches[0].Reason != tc.reason || len(result.Matches[0].Qualifications) != 2 || result.AffectedCVEs != nil || result.Quality.Coverage != Partial {
				t.Fatalf("ambiguous record became definitive: %+v", result)
			}
		})
	}
}
func TestOriginAndVersionBindingRequired(t *testing.T) {
	edits := map[string]func(*InstalledPackage){
		"dpkg only":            func(p *InstalledPackage) { p.Origin = OriginEvidence{} },
		"metadata coincidence": func(p *InstalledPackage) { p.Origin.InstalledArtifactVerified = false },
		"other release":        func(p *InstalledPackage) { p.Origin.Release = "bookworm" },
		"other vendor":         func(p *InstalledPackage) { p.Origin.Distribution = "ubuntu" },
		"wrong binary":         func(p *InstalledPackage) { p.Origin.BinaryVersion = "1:2.0-1+deb13u3" },
		"wrong source":         func(p *InstalledPackage) { p.Origin.SourcePackage = "different-source" },
		"wrong source version": func(p *InstalledPackage) { p.Origin.SourceVersion = "1:2.0-1+deb13u3" },
		"wrong architecture":   func(p *InstalledPackage) { p.Origin.Architecture = "arm64" },
		"missing evidence":     func(p *InstalledPackage) { p.Origin.EvidenceID = "" },
		"incomplete":           func(p *InstalledPackage) { p.InstallState = "incomplete" },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			inventory := fixtureInventory(t)
			edit(&inventory.Packages[0])
			if inventory.Packages[0].InstallState == "incomplete" {
				inventory.InstalledCount = count(0)
			}
			result := evaluate(t, inventory, fixtureSnapshot(t, nil))
			if result.Matches[0].Verdict != NeedsReview || result.AffectedCVEs != nil || result.Quality.Coverage != Partial {
				t.Fatal("ambiguous origin/state became assured")
			}
		})
	}
}
func TestNoFalseGreenOnMissingUnsupportedOrUntrustedInput(t *testing.T) {
	snapshot := fixtureSnapshot(t, nil)
	for _, tc := range []struct {
		name string
		edit func(*Inventory)
		feed *DebianSnapshot
	}{
		{"missing inventory", func(i *Inventory) { i.InstalledCount = nil; i.Quality.Coverage = Unknown }, snapshot},
		{"missing feed", func(*Inventory) {}, nil},
		{"mint is not debian", func(i *Inventory) { i.Platform.Distribution = "linuxmint" }, snapshot},
		{"ubuntu is not debian", func(i *Inventory) { i.Platform.Distribution = "ubuntu" }, snapshot},
		{"unsupported debian", func(i *Inventory) { i.Platform.Codename = "bookworm"; i.Platform.Version = "12" }, snapshot},
		{"fixture cannot assess real inventory", func(i *Inventory) { i.Source.Synthetic = false; i.Source.Trust = "local" }, snapshot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := fixtureInventory(t)
			tc.edit(&inventory)
			result := evaluate(t, inventory, tc.feed)
			if result.Quality.Coverage != Unknown || result.AffectedCVEs != nil || len(result.Matches) != 0 {
				t.Fatal("missing/unsupported scope became green")
			}
		})
	}
	untrusted := fixtureSnapshot(t, func(doc *debianDocument, source *SourceSnapshot) {
		doc.Synthetic = false
		source.Synthetic = false
		source.Trust = "local"
	})
	inventory := fixtureInventory(t)
	inventory.Source.Synthetic = false
	inventory.Source.Trust = "local"
	result := evaluate(t, inventory, untrusted)
	if result.Matches[0].Verdict != NeedsReview || result.Matches[0].Reason != "advisory_authority_unverified" || result.AffectedCVEs != nil {
		t.Fatal("local JSON self-attested vendor authority")
	}
}
func TestComparatorFailureIsSanitizedAndUnknown(t *testing.T) {
	for _, comparator := range []VersionComparator{nil, failComparator{}} {
		result := AssessDebian(context.Background(), fixtureInventory(t), fixtureSnapshot(t, nil), comparator, testNow())
		if result.Matches[0].Verdict != NeedsReview || result.AffectedCVEs != nil {
			t.Fatal("comparator failure produced clean count")
		}
		encoded, _ := json.Marshal(result)
		if strings.Contains(string(encoded), "private stderr") {
			t.Fatal("raw subprocess error leaked")
		}
	}
}
func TestCoverageFreshnessAndScopedNoMatches(t *testing.T) {
	inventory := fixtureInventory(t)
	stale := fixtureSnapshot(t, func(_ *debianDocument, source *SourceSnapshot) {
		source.FetchedAt = testNow().Add(-2 * time.Hour)
		source.ValidatedAt = source.FetchedAt
		source.ExpiresAt = testNow().Add(-time.Hour)
	})
	result := evaluate(t, inventory, stale)
	if result.Quality.Status() != StatusStale || result.Quality.Coverage != Assessed || result.Matches[0].Verdict != Affected {
		t.Fatal("stale evidence was discarded or refreshed by evaluation")
	}
	inventory.Quality.Coverage = Partial
	result = evaluate(t, inventory, stale)
	if result.Quality.Coverage != Partial || result.Quality.Freshness != Stale {
		t.Fatal("partial and stale cannot coexist")
	}
	unknownAge := fixtureSnapshot(t, func(_ *debianDocument, source *SourceSnapshot) { source.ExpiresAt = time.Time{} })
	result = evaluate(t, fixtureInventory(t), unknownAge)
	if result.Quality.Freshness != FreshnessUnknown || result.AffectedCVEs != nil || result.Matches[0].Verdict != NeedsReview {
		t.Fatal("unknown source age became current assurance")
	}
	noMatch := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) { doc.Rules = []DebianRule{} })
	result = evaluate(t, fixtureInventory(t), noMatch)
	if result.Quality.Coverage != Assessed || result.AffectedCVEs == nil || *result.AffectedCVEs != 0 || len(result.Quality.ExcludedScopes) == 0 {
		t.Fatal("scoped no matches did not preserve exclusions")
	}
	uncovered := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) {
		doc.Rules = []DebianRule{}
		doc.CoveredSources = []string{"different-source"}
	})
	result = evaluate(t, fixtureInventory(t), uncovered)
	if result.Quality.Coverage != Partial || result.AffectedCVEs != nil {
		t.Fatal("uncovered source inferred safe")
	}
}
func TestSameCVEDeduplicatesAcrossComponents(t *testing.T) {
	inventory := fixtureInventory(t)
	second := inventory.Packages[0]
	second.Name = "tracebolt-second-binary"
	second.Origin.Package = second.Name
	inventory.Packages = append(inventory.Packages, second)
	inventory.InstalledCount = count(2)
	result := evaluate(t, inventory, fixtureSnapshot(t, nil))
	if len(result.Matches) != 2 || result.AffectedCVEs == nil || *result.AffectedCVEs != 1 {
		t.Fatal("CVE counted once per component instead of unique CVE")
	}
}
func TestCancelledAssessmentDoesNotEmitZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := AssessDebian(ctx, fixtureInventory(t), fixtureSnapshot(t, nil), fixtureComparator{}, testNow())
	if result.Quality.Coverage != Partial || result.AffectedCVEs != nil || !contains(result.Quality.ReasonCodes, "assessment_cancelled_or_timed_out") {
		t.Fatal("cancelled assessment emitted zero")
	}
}
func TestNonCVEAdvisoryDoesNotInventCVE(t *testing.T) {
	snapshot := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) { doc.Rules[0].AdvisoryID = "TEMP-SYNTHETIC-1" })
	result := evaluate(t, fixtureInventory(t), snapshot)
	if result.Matches[0].CVEID != "" || result.Matches[0].Verdict != Affected || *result.AffectedCVEs != 0 {
		t.Fatal("temporary vendor issue invented a CVE")
	}
}
func TestContradictoryInventoryNeverEmitsZero(t *testing.T) {
	for _, edit := range []func(*Inventory){
		func(i *Inventory) { i.Packages = nil },
		func(i *Inventory) { i.Packages = append(i.Packages, i.Packages[0]); i.InstalledCount = count(2) },
		func(i *Inventory) { i.Source.SHA256 = "" },
		func(i *Inventory) { i.Source.Kind = "advisory" },
		func(i *Inventory) { i.Quality.Coverage = "invented" },
		func(i *Inventory) { i.Source.Trust = "local" },
	} {
		inventory := fixtureInventory(t)
		edit(&inventory)
		result := evaluate(t, inventory, fixtureSnapshot(t, nil))
		if result.Quality.Coverage != Unknown || result.AffectedCVEs != nil || len(result.Matches) != 0 {
			t.Fatal("contradictory inventory became a successful prefix")
		}
	}
}
func TestMatchLimitIsExplicitPartial(t *testing.T) {
	snapshot := fixtureSnapshot(t, func(doc *debianDocument, _ *SourceSnapshot) {
		base := doc.Rules[0]
		base.FixedVersion = "0"
		for j := 1; j < 1000; j++ {
			rule := base
			rule.AdvisoryID = fmt.Sprintf("TEMP-SYNTHETIC-%d", j)
			doc.Rules = append(doc.Rules, rule)
		}
	})
	inventory := fixtureInventory(t)
	original := inventory.Packages[0]
	for i := 1; i < 102; i++ {
		pkg := original
		pkg.Name = fmt.Sprintf("fixture-binary-%d", i)
		pkg.Origin.Package = pkg.Name
		inventory.Packages = append(inventory.Packages, pkg)
	}
	inventory.InstalledCount = count(len(inventory.Packages))
	result := evaluate(t, inventory, snapshot)
	if result.Quality.Coverage != Partial || len(result.Matches) != MaxAssessmentMatches || !contains(result.Quality.ReasonCodes, "assessment_match_limit_exceeded") {
		t.Fatalf("result budget was not enforced: %d", len(result.Matches))
	}
}
func TestUnknownFreshnessDominatesStaleWithoutFalseFixedZero(t *testing.T) {
	if combinedFreshness(Stale, FreshnessUnknown) != FreshnessUnknown || combinedFreshness(FreshnessUnknown, Stale) != FreshnessUnknown {
		t.Fatal("stale masks unknown source age")
	}
	for _, fixed := range []string{"1:2.0-1+deb13u2", "0"} {
		for _, unknownInventoryAge := range []bool{false, true} {
			inventory := fixtureInventory(t)
			setSourceVersion(&inventory, "1:2.0-1+deb13u3")
			snapshot := fixtureSnapshot(t, func(doc *debianDocument, s *SourceSnapshot) {
				doc.Rules[0].FixedVersion = fixed
				if unknownInventoryAge {
					s.FetchedAt = testNow().Add(-2 * time.Hour)
					s.ValidatedAt = s.FetchedAt
					s.ExpiresAt = testNow().Add(-time.Hour)
				} else {
					s.ExpiresAt = time.Time{}
				}
			})
			if unknownInventoryAge {
				inventory.Source.ExpiresAt = time.Time{}
			} else {
				inventory.Source.FetchedAt = testNow().Add(-2 * time.Hour)
				inventory.Source.ValidatedAt = inventory.Source.FetchedAt
				inventory.Source.ExpiresAt = testNow().Add(-time.Hour)
			}
			result := evaluate(t, inventory, snapshot)
			if result.Quality.Freshness != FreshnessUnknown || result.Quality.Coverage != Partial || result.AffectedCVEs != nil || result.Matches[0].Verdict != NeedsReview || result.Matches[0].Reason != "source_freshness_unknown" {
				t.Fatalf("invalid source age became fixed/not-affected assurance: %+v", result)
			}
		}
	}
}
