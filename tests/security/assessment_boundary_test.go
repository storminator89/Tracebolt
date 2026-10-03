package security_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"localrmm/internal/assessment"
	"strings"
	"testing"
	"time"
)

type reviewDebianComparator struct{}

func (reviewDebianComparator) Compare(_ context.Context, a, b string) (int, error) {
	if a == "1.0-1" && b == "2.0-1" {
		return -1, nil
	}
	return 0, fmt.Errorf("unexpected synthetic comparison")
}

func reviewAssessmentFixture(t *testing.T, fixed string, sourceEdit func(*assessment.SourceSnapshot, *assessment.SourceSnapshot)) (assessment.Inventory, *assessment.DebianSnapshot, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	packages, digest, err := assessment.ParseDpkgStatus(context.Background(), strings.NewReader("Package: review-bin\nStatus: install ok installed\nVersion: 1.0-1+b1\nArchitecture: amd64\nSource: review-src (1.0-1)\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := &packages[0]
	p.Origin = assessment.OriginEvidence{Distribution: "debian", Release: "trixie", RepositoryID: "synthetic-repo", EvidenceID: "synthetic-artifact-proof", Package: p.Name, BinaryVersion: p.Version, Architecture: p.Architecture, SourcePackage: p.SourcePackage, SourceVersion: p.SourceVersion, VerifiedMetadata: true, InstalledArtifactVerified: true}
	invSource := assessment.SourceSnapshot{ID: "review-inventory", Provider: "synthetic-dpkg", Kind: "inventory", SHA256: digest, FetchedAt: now.Add(-time.Minute), ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Trust: "synthetic_fixture", Synthetic: true}
	feedSource := invSource
	feedSource.ID, feedSource.Provider, feedSource.Kind = "review-feed", "debian-security-tracker", "advisory"
	document := fmt.Sprintf(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["review-src"],"rules":[{"sourcePackage":"review-src","advisoryId":"CVE-2026-12345","release":"trixie","status":"resolved","fixedVersion":%q,"qualifications":[],"archiveVersions":[]}]}`, fixed)
	hash := sha256.Sum256([]byte(document))
	feedSource.SHA256 = hex.EncodeToString(hash[:])
	if sourceEdit != nil {
		sourceEdit(&invSource, &feedSource)
	}
	snapshot, err := assessment.ParseDebianSnapshot(strings.NewReader(document), feedSource)
	if err != nil {
		t.Fatal(err)
	}
	inv := assessment.InventoryFromParsed(assessment.Platform{OS: "linux", Architecture: "amd64", Distribution: "debian", Version: "13", Codename: "trixie"}, packages, invSource, now)
	return inv, snapshot, now
}

func TestIndependentAssessmentAuthorityAndAge(t *testing.T) {
	for _, fixed := range []string{"0", "2.0-1"} {
		for _, inverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("fixed=%s/inverse=%t", fixed, inverse), func(t *testing.T) {
				inv, feed, now := reviewAssessmentFixture(t, fixed, func(a, b *assessment.SourceSnapshot) {
					if inverse {
						a, b = b, a
					}
					a.FetchedAt, a.ValidatedAt, a.ExpiresAt = a.FetchedAt.Add(-time.Hour), a.ValidatedAt.Add(-time.Hour), a.ExpiresAt.Add(-2*time.Hour)
					b.ValidatedAt = time.Time{}
				})
				result := assessment.AssessDebian(context.Background(), inv, feed, reviewDebianComparator{}, now)
				if result.Quality.Freshness != assessment.FreshnessUnknown || result.Quality.Coverage != assessment.Partial || result.AffectedCVEs != nil || len(result.Matches) != 1 || result.Matches[0].Verdict != assessment.NeedsReview {
					t.Fatalf("invalid freshness granted authority: %+v", result)
				}
			})
		}
	}
	inv, feed, now := reviewAssessmentFixture(t, "2.0-1", nil)
	result := assessment.AssessDebian(context.Background(), inv, feed, reviewDebianComparator{}, now)
	if len(result.Matches) != 1 || result.Matches[0].Verdict != assessment.Affected || result.Matches[0].InstalledSourceVersion != "1.0-1" || result.Matches[0].Activation != "unknown" {
		t.Fatalf("source-version boundary lost: %+v", result)
	}
	inv.Packages[0].Origin.InstalledArtifactVerified = false
	result = assessment.AssessDebian(context.Background(), inv, feed, reviewDebianComparator{}, now)
	if result.Matches[0].Verdict != assessment.NeedsReview || result.AffectedCVEs != nil {
		t.Fatal("metadata coincidence gained installed-origin authority")
	}
	if offered := assessment.UnimplementedUpdates(now); offered.OfferedCount != nil || len(offered.Updates) != 0 {
		t.Fatal("advisory threshold became an offered update")
	}
}

func TestIndependentAssessmentLastGoodRetention(t *testing.T) {
	inv, feed, now := reviewAssessmentFixture(t, "0", nil)
	result := assessment.AssessDebian(context.Background(), inv, feed, reviewDebianComparator{}, now)
	var cache assessment.AssessmentCache
	if err := cache.Commit(feed, result, now); err != nil {
		t.Fatal(err)
	}
	result.Matches[0].Verdict = assessment.Affected
	cache.RecordFailure(now.Add(2*time.Hour), "private path and upstream response body")
	view := cache.View(now.Add(2 * time.Hour))
	if view.FailureReason != "refresh_failed" || view.Assessment.Quality.Freshness != assessment.Stale || view.Assessment.Matches[0].Verdict != assessment.NotAffected || !view.Assessment.Quality.AssessedAt.Equal(now) {
		t.Fatalf("last-good semantics lost: %+v", view)
	}
	*view.Assessment.AffectedCVEs = 999
	view.Assessment.Matches[0].Verdict = assessment.Affected
	if again := cache.View(now.Add(2 * time.Hour)); *again.Assessment.AffectedCVEs != 0 || again.Assessment.Matches[0].Verdict != assessment.NotAffected {
		t.Fatal("returned view mutates cache")
	}
}
