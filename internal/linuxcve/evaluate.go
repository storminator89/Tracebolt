package linuxcve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/assessment"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"sort"
	"strings"
	"time"
)

// Evaluate uses a completed generation supplied by the storage adapter. It also
// verifies the entire row set against the manifest so a missing page cannot be
// mistaken for an empty result. Only source-version comparisons are relevant;
// a newer binary version cannot hide an older mapped source version.
func Evaluate(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, comparator assessment.VersionComparator, now time.Time) Result {
	result := Result{SchemaVersion: ResultSchemaVersion, Status: "unavailable", Freshness: "unknown", InventoryFreshness: InventoryFreshness(manifest.CollectedAt, now), AssessedAt: now.UTC(), Findings: []Finding{}, ReasonCodes: []string{}}
	reason := func(code string) { result.ReasonCodes = appendUnique(result.ReasonCodes, code) }
	if ctx == nil || ctx.Err() != nil {
		reason("evaluation_canceled_or_timed_out")
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if !validTime(now) || result.InventoryFreshness == "unknown" {
		reason("inventory_time_invalid")
		return result
	}
	if !validInventory(ctx, manifest, rows) {
		if ctx.Err() != nil {
			reason("evaluation_canceled_or_timed_out")
		} else {
			reason("inventory_invalid_or_incomplete")
		}
		return result
	}
	result.GenerationID = manifest.GenerationID
	target := manifest.Release.Fields.Target()
	if target != linuxpackages.Debian13 && target != linuxpackages.Ubuntu2404 {
		reason("release_unsupported")
		return result
	}
	if snapshot == nil || !snapshot.valid {
		reason("feed_missing")
		return result
	}
	metadata := snapshot.Metadata(now)
	result.Feed, result.Freshness = &metadata, metadata.Freshness
	if metadata.Target != target {
		reason("feed_target_mismatch")
		return result
	}
	if metadata.Freshness == "unknown" {
		reason("feed_time_invalid")
		return result
	}
	reason(metadata.Coverage)
	if metadata.Trust != "https_origin_only" {
		reason("feed_origin_unverified")
	}
	reason("installed_origin_unverified")
	reason("published_fixes_only")
	reason("runtime_activation_not_assessed")
	result.Status = "partial"
	if result.Freshness == "stale" {
		result.Status = "stale"
		reason("feed_stale")
	}
	if result.InventoryFreshness == "stale" {
		result.Status = "stale"
		reason("inventory_stale")
	}
	type group struct {
		source, version string
		binaries        []Binary
	}
	groups := map[string]*group{}
	for _, p := range rows {
		if ctx.Err() != nil {
			result.Truncated = true
			reason("evaluation_canceled_or_timed_out")
			return result
		}
		if p.InstallState != "installed" {
			result.SkippedPackageCount++
			reason("package_installation_incomplete")
			continue
		}
		if excludedVersion(p.Version) || excludedVersion(p.SourceVersion) {
			result.SkippedPackageCount++
			reason("nonstandard_package_version")
			continue
		}
		key := p.SourcePackage + "\x00" + p.SourceVersion
		g := groups[key]
		if g == nil {
			g = &group{source: p.SourcePackage, version: p.SourceVersion}
			groups[key] = g
		}
		g.binaries = append(g.binaries, Binary{Name: p.Name, Version: p.Version, Architecture: p.Architecture})
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	memo := map[string]int{}
	comparisons := 0
	compare := func(a, b string) (int, error) {
		if ctx.Err() != nil {
			return 0, ErrCanceled
		}
		key := a + "\x00" + b
		if v, ok := memo[key]; ok {
			return v, nil
		}
		if comparator == nil {
			return 0, assessment.ErrComparatorUnavailable
		}
		if comparisons >= MaxComparisons {
			return 0, ErrLimit
		}
		comparisons++
		v, err := comparator.Compare(ctx, a, b)
		if err != nil || v < -1 || v > 1 {
			return 0, assessment.ErrComparatorUnavailable
		}
		memo[key] = v
		return v, nil
	}
	evaluated := map[string]bool{}
	findingGroups := []*group{}
	stopped := false
	for _, key := range keys {
		g := groups[key]
		if ctx.Err() != nil {
			reason("evaluation_canceled_or_timed_out")
			result.Truncated = true
			break
		}
		rules := snapshot.rules[g.source]
		if len(rules) == 0 {
			result.SkippedPackageCount += len(g.binaries)
			reason("source_package_not_in_import")
			continue
		}
		evaluatedGroup := false
		for _, rule := range rules {
			if ctx.Err() != nil {
				reason("evaluation_canceled_or_timed_out")
				result.Truncated = true
				stopped = true
				break
			}
			if rule.reason != "" {
				if rule.reason == "vendor_not_affected" {
					evaluatedGroup = true
				} else {
					reason(rule.reason)
				}
				continue
			}
			fixed, applied, err := matchRule(rule, g.version, compare)
			if err != nil {
				switch {
				case errors.Is(err, ErrLimit):
					reason("comparison_limit_exceeded")
					result.Truncated = true
					stopped = true
				case ctx.Err() != nil || errors.Is(err, ErrCanceled):
					reason("evaluation_canceled_or_timed_out")
					result.Truncated = true
					stopped = true
				default:
					reason("debian_comparator_unavailable")
				}
				if stopped {
					break
				}
				continue
			}
			evaluatedGroup = true
			if !applied {
				continue
			}
			if len(result.Findings) >= MaxFindings {
				reason("finding_limit_exceeded")
				result.Truncated = true
				stopped = true
				break
			}
			result.Findings = append(result.Findings, Finding{CVEID: rule.cve, SourcePackage: g.source, InstalledSourceVersion: g.version, PublishedFixedVersion: fixed, Basis: "distribution_package_version_match", AdvisoryURL: rule.advisoryURL, Binaries: []Binary{}})
			findingGroups = append(findingGroups, g)
		}
		if evaluatedGroup {
			evaluated[g.source] = true
		} else {
			result.SkippedPackageCount += len(g.binaries)
		}
		if stopped {
			break
		}
	}
	result.EvaluatedSourceCount = len(evaluated)
	// First reserve one installed binary per finding; distribute remaining space
	// only afterward. Every visible finding remains tied to an installed row.
	binaryRows := 0
	for i, g := range findingGroups {
		result.Findings[i].Binaries = append(result.Findings[i].Binaries, g.binaries[0])
		binaryRows++
	}
	for i, g := range findingGroups {
		remaining := min(len(g.binaries), MaxBinariesPerFinding)
		for j := 1; j < remaining && binaryRows < MaxBinaryRows; j++ {
			result.Findings[i].Binaries = append(result.Findings[i].Binaries, g.binaries[j])
			binaryRows++
		}
		if len(result.Findings[i].Binaries) < len(g.binaries) {
			result.Findings[i].BinariesTruncated = true
			result.Truncated = true
			reason("binary_limit_exceeded")
		}
	}
	// Field lengths are independently bounded, but many maximum-length Debian
	// versions can still exceed the UI budget. Trim only whole match rows and
	// expose the lower bound; never silently shorten an identity or version.
	for {
		encoded, err := json.Marshal(result)
		if err == nil && len(encoded) <= MaxResultBytes {
			break
		}
		if len(result.Findings) == 0 {
			break
		}
		result.Findings = result.Findings[:len(result.Findings)-1]
		result.Truncated = true
		reason("response_byte_limit_exceeded")
	}
	return result
}

func matchRule(r rule, installed string, compare func(string, string) (int, error)) (string, bool, error) {
	if r.fixed != "" {
		cmp, err := compare(installed, r.fixed)
		return r.fixed, err == nil && cmp < 0, err
	}
	for _, rg := range r.intervals {
		if rg.introduced != "0" {
			bounds, err := compare(rg.introduced, rg.fixed)
			if err != nil {
				return "", false, err
			}
			if bounds >= 0 {
				return "", false, assessment.ErrVersionInvalid
			}
			start, err := compare(installed, rg.introduced)
			if err != nil {
				return "", false, err
			}
			if start < 0 {
				continue
			}
		}
		end, err := compare(installed, rg.fixed)
		if err != nil {
			return "", false, err
		}
		if end < 0 {
			return rg.fixed, true, nil
		}
	}
	return "", false, nil
}

func excludedVersion(v string) bool {
	v = strings.ToLower(v)
	for _, marker := range []string{"~bpo", "+bpo", "ppa", "+local", "~local", ".local", "-local", "+custom", "~custom", "+rebuild", "~rebuild"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func validInventory(ctx context.Context, m fullinventory.Manifest, rows []linuxpackages.PackageRow) bool {
	if rows == nil || fullinventory.ValidateManifest(m) != nil || uint64(len(rows)) != m.ObservedCount {
		return false
	}
	h := sha256.New()
	// The complete-inventory v1 contract's canonical row digest domain.
	_, _ = h.Write([]byte("tracebolt.complete-linux-packages.rows.v1\x00"))
	var installed, canonicalBytes uint64
	for i, p := range rows {
		if ctx.Err() != nil || fullinventory.ValidateRow(p) != nil {
			return false
		}
		if i > 0 && (rows[i-1].Name > p.Name || rows[i-1].Name == p.Name && rows[i-1].Architecture >= p.Architecture) {
			return false
		}
		if p.InstallState == "installed" {
			installed++
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return false
		}
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{'\n'})
		canonicalBytes += uint64(len(raw) + 1)
	}
	return installed == m.InstalledCount && canonicalBytes == m.CanonicalRowBytes && hex.EncodeToString(h.Sum(nil)) == m.RowsSHA256
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
