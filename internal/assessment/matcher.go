package assessment

import (
	"context"
	"encoding/hex"
	"sort"
	"time"
)

const MaxAssessmentMatches = 100000

// AssessDebian evaluates ONLY explicitly covered Debian 13/Trixie source-package
// rules. It performs no I/O of its own; comparison is injected. Even a complete
// result excludes other software, exploitability and running-process activation.
func AssessDebian(ctx context.Context, inventory Inventory, snapshot *DebianSnapshot, comparator VersionComparator, now time.Time) VulnerabilityAssessment {
	result := VulnerabilityAssessment{Quality: Quality{Coverage: Unknown, Freshness: FreshnessUnknown, Scope: "debian-trixie-source-package-rules", ExcludedScopes: []string{"non-dpkg-software", "other-releases-and-vendors", "exploitability", "running-process-activation"}, AssessedAt: now.UTC()}}
	fail := func(reason string) VulnerabilityAssessment {
		result.Quality.ReasonCodes = append(result.Quality.ReasonCodes, reason)
		return result
	}
	if !inventory.Platform.supportedDebian() {
		return fail("vulnerability_adapter_unimplemented")
	}
	if snapshot == nil {
		return fail("advisory_snapshot_unavailable")
	}
	result.Sources = []SourceSnapshot{inventory.Source, snapshot.source}
	if inventory.Quality.Coverage == Unknown || inventory.InstalledCount == nil {
		return fail("inventory_unavailable")
	}
	if !validInventory(inventory) {
		return fail("inventory_invalid")
	}
	if inventory.Source.Synthetic != snapshot.source.Synthetic {
		return fail("fixture_authority_mismatch")
	}
	result.Quality.Freshness = combinedFreshness(inventory.Source.FreshnessAt(now), snapshot.source.FreshnessAt(now))
	trusted := snapshotAuthority(snapshot) && oneOf(inventory.Source.Trust, "local", "synthetic_fixture")
	// The total evaluation, including native comparisons, is bounded. No caller
	// can accidentally create an unbounded one-process-per-rule workload.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rules := map[string][]DebianRule{}
	covered := map[string]bool{}
	for _, name := range snapshot.document.CoveredSources {
		covered[name] = true
	}
	for _, rule := range snapshot.document.Rules {
		rules[rule.SourcePackage] = append(rules[rule.SourcePackage], rule)
	}
	assessed, unassessed := 0, 0
	candidates := 0
	affected := map[string]bool{}
	for _, pkg := range inventory.Packages {
		if ctx.Err() != nil {
			return incompleteAssessment(result, len(inventory.Packages), assessed, candidates, affected, "assessment_cancelled_or_timed_out")
		}
		pkgAssessed := trusted && result.Quality.Freshness != FreshnessUnknown && originApplies(inventory.Platform, pkg) && pkg.InstallState == "installed" && covered[pkg.SourcePackage]
		if !covered[pkg.SourcePackage] {
			result.Quality.ReasonCodes = appendUnique(result.Quality.ReasonCodes, "source_package_not_covered")
		}
		// One logical row per source/advisory; other-release entries cannot mask a
		// missing target release or create duplicate counts.
		issues := map[string][]DebianRule{}
		for _, rule := range rules[pkg.SourcePackage] {
			issues[rule.AdvisoryID] = append(issues[rule.AdvisoryID], rule)
		}
		issueIDs := make([]string, 0, len(issues))
		for id := range issues {
			issueIDs = append(issueIDs, id)
		}
		sort.Strings(issueIDs)
		for _, id := range issueIDs {
			if ctx.Err() != nil {
				return incompleteAssessment(result, len(inventory.Packages), assessed, candidates, affected, "assessment_cancelled_or_timed_out")
			}
			if len(result.Matches) >= MaxAssessmentMatches {
				return incompleteAssessment(result, len(inventory.Packages), assessed, candidates, affected, "assessment_match_limit_exceeded")
			}
			var rule DebianRule
			found := false
			for _, entry := range issues[id] {
				if entry.Release == inventory.Platform.Codename {
					rule = entry
					found = true
					break
				}
			}
			if !found {
				rule = issues[id][0]
			}
			match := Match{Package: pkg.Name, Architecture: pkg.Architecture, SourcePackage: pkg.SourcePackage, InstalledSourceVersion: pkg.SourceVersion, AdvisoryID: id, VendorStatus: rule.Status, Qualifications: append([]string(nil), rule.Qualifications...), Verdict: NeedsReview, Basis: "candidate_only", FixAvailability: "unknown", Activation: "unknown", SnapshotID: snapshot.source.ID, Synthetic: snapshot.source.Synthetic}
			if cveID.MatchString(id) {
				match.CVEID = id
			}
			switch {
			case !trusted:
				match.Reason = "advisory_authority_unverified"
			case result.Quality.Freshness == FreshnessUnknown:
				match.Reason = "source_freshness_unknown"
			case !originApplies(inventory.Platform, pkg):
				match.Reason = "installed_origin_unverified"
			case pkg.InstallState != "installed":
				match.Reason = "package_installation_incomplete"
			case !found:
				match.Reason = "release_record_missing"
			case rule.Status == "resolved" && rule.FixedVersion == "0":
				match.Verdict = NotAffected
				match.Basis = "vendor_rule"
				match.Reason = "vendor_not_affected_sentinel"
			case rule.Status == "resolved" && rule.FixedVersion != "":
				match.PublishedFixedVersion = rule.FixedVersion
				match.FixAvailability = "published"
				if comparator == nil {
					match.Reason = "debian_comparator_unavailable"
					break
				}
				comparison, err := comparator.Compare(ctx, pkg.SourceVersion, rule.FixedVersion)
				if err != nil || comparison < -1 || comparison > 1 {
					match.Reason = "debian_comparison_failed"
					break
				}
				match.Basis = "vendor_rule"
				if comparison < 0 {
					match.Verdict = Affected
					match.Reason = "installed_source_below_vendor_fix"
				} else {
					match.Verdict = Fixed
					match.Reason = "installed_source_at_or_above_vendor_fix"
				}
			case rule.Status == "open" && rule.FixedVersion == "":
				match.Reason = "unfixed_vendor_record_requires_version_evidence"
				match.FixAvailability = "no_fix_published"
			case rule.Status == "undetermined":
				match.Reason = "vendor_status_undetermined"
			default:
				match.Reason = "vendor_record_uninterpretable"
			}
			if match.Verdict == NeedsReview || match.Verdict == VerdictUnknown {
				pkgAssessed = false
				candidates++
			}
			if match.Verdict == Affected && match.CVEID != "" {
				affected[match.CVEID] = true
			}
			result.Matches = append(result.Matches, match)
		}
		if pkgAssessed {
			assessed++
		} else {
			unassessed++
		}
	}
	sort.Slice(result.Matches, func(i, j int) bool {
		a, b := result.Matches[i], result.Matches[j]
		return a.Package+":"+a.Architecture+":"+a.AdvisoryID < b.Package+":"+b.Architecture+":"+b.AdvisoryID
	})
	result.Quality.AssessedItems = count(assessed)
	result.Quality.UnassessedItems = count(unassessed)
	result.Quality.Coverage = Assessed
	if unassessed > 0 || inventory.Quality.Coverage == Partial {
		result.Quality.Coverage = Partial
		result.Quality.ReasonCodes = appendUnique(result.Quality.ReasonCodes, "unassessed_package_scope")
	}
	if !trusted || result.Quality.Freshness == FreshnessUnknown {
		result.Quality.Coverage = Partial
	}
	// Review counts are scoped to rules we actually inspected. Affected=0 is not
	// emitted where every item is unassessed. Partial positive counts are lower bounds.
	result.ReviewCandidates = count(candidates)
	if assessed > 0 || len(affected) > 0 || len(inventory.Packages) == 0 && trusted && result.Quality.Freshness != FreshnessUnknown {
		result.AffectedCVEs = count(len(affected))
	}
	return result
}
func snapshotAuthority(s *DebianSnapshot) bool {
	if s.source.Synthetic {
		return s.source.Trust == "synthetic_fixture"
	}
	return s.source.PublicURL == "https://security-tracker.debian.org/tracker/data/json" && oneOf(s.source.Trust, "https_origin_only", "vendor_signature_verified")
}
func validInstalledPackage(p InstalledPackage) bool {
	return packageName.MatchString(p.Name) && archName.MatchString(p.Architecture) && ValidDebianVersion(p.Version) && packageName.MatchString(p.SourcePackage) && ValidDebianVersion(p.SourceVersion) && oneOf(p.InstallState, "installed", "incomplete")
}
func originApplies(platform Platform, p InstalledPackage) bool {
	o := p.Origin
	return o.VerifiedMetadata && o.InstalledArtifactVerified && o.EvidenceID != "" && o.RepositoryID != "" && o.Distribution == platform.Distribution && o.Release == platform.Codename && o.Package == p.Name && o.BinaryVersion == p.Version && o.Architecture == p.Architecture && o.SourcePackage == p.SourcePackage && o.SourceVersion == p.SourceVersion
}
func combinedFreshness(a, b Freshness) Freshness {
	// Unknown/invalid evidence must dominate expired-but-known evidence: stale
	// cannot grant the authority that a missing/future timestamp removes.
	if a == FreshnessUnknown || b == FreshnessUnknown {
		return FreshnessUnknown
	}
	if a == Stale || b == Stale {
		return Stale
	}
	return Fresh
}
func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
func incompleteAssessment(result VulnerabilityAssessment, total, assessed, candidates int, affected map[string]bool, reason string) VulnerabilityAssessment {
	result.Quality.Coverage = Partial
	result.Quality.ReasonCodes = appendUnique(result.Quality.ReasonCodes, reason)
	result.Quality.AssessedItems = count(assessed)
	result.Quality.UnassessedItems = count(total - assessed)
	result.ReviewCandidates = count(candidates)
	if len(affected) > 0 {
		result.AffectedCVEs = count(len(affected))
	}
	return result
}

// Keep contradictory adapter/transport inputs from turning into an empty success.
func validInventory(in Inventory) bool {
	if in.SchemaVersion != SchemaVersion || len(in.Packages) > MaxInventoryPackages || in.InstalledCount == nil || (in.Quality.Coverage != Assessed && in.Quality.Coverage != Partial) || in.Source.Kind != "inventory" || !safeToken.MatchString(in.Source.ID) {
		return false
	}
	digest, err := hex.DecodeString(in.Source.SHA256)
	if err != nil || len(digest) != 32 {
		return false
	}
	if in.Source.Synthetic != (in.Source.Trust == "synthetic_fixture") {
		return false
	}
	identities := map[string]bool{}
	installed := 0
	for _, pkg := range in.Packages {
		key := pkg.Name + ":" + pkg.Architecture
		if identities[key] || !validInstalledPackage(pkg) {
			return false
		}
		identities[key] = true
		if pkg.InstallState == "installed" {
			installed++
		}
	}
	return installed == *in.InstalledCount
}
