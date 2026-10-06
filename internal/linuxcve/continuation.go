package linuxcve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/assessment"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"sort"
	"time"
)

const EvaluatorVersion = "tracebolt.linux-cve-evaluator.v3"
const MaxCheckpointBytes = 240 << 10

var ErrCheckpoint = errors.New("linux_cve_checkpoint_invalid")

// AssessmentIdentity is supplied only from revalidated manager authority.
// Caller-supplied detail positions never provide or override this binding.
type AssessmentIdentity struct {
	DeviceID string
	Sequence uint64
}

// AssessmentID pins immutable evidence. ValidatedAt is deliberately excluded:
// reparsing a persisted feed at restart must not renew or invalidate its age.
func AssessmentID(snapshot *Snapshot, manifest fullinventory.Manifest, identity AssessmentIdentity) (string, error) {
	if snapshot == nil || !snapshot.valid {
		return "", ErrInvalid
	}
	digest, err := fullinventory.ManifestDigest(manifest)
	if err != nil {
		return "", ErrInvalid
	}
	m := snapshot.metadata
	raw, err := json.Marshal(struct {
		Version              string
		Identity             AssessmentIdentity
		ManifestHash         string
		Provider             string
		Target               linuxpackages.ReleaseTarget
		Hash                 string
		FetchedAt, ExpiresAt time.Time
		Trust, Coverage      string
	}{EvaluatorVersion, identity, digest, m.Provider, m.Target, m.SHA256, m.FetchedAt, m.ExpiresAt, m.Trust, m.Coverage})
	if err != nil {
		return "", ErrInvalid
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

type versionGroup struct {
	source, version string
	binaries        []Binary
}
type sourceGroup struct {
	source   string
	versions []*versionGroup
	rules    []rule
}
type workPlan struct {
	sources  []sourceGroup
	versions map[string]*versionGroup
}

// Only the current source/advisory has deduplication flags. All prior records
// are behind the cursor; no growing set of CVEs or comparisons is persisted.
type checkpoint struct {
	Version           string                  `json:"version"`
	AssessmentID      string                  `json:"assessmentId"`
	Source            int                     `json:"source"`
	Record            int                     `json:"record"`
	InstalledVersion  int                     `json:"installedVersion"`
	SourceEvaluated   bool                    `json:"sourceEvaluated"`
	RecordMatched     bool                    `json:"recordMatched"`
	RecordUnassessed  bool                    `json:"recordUnassessed"`
	RecordReasons     uint64                  `json:"recordReasons"`
	Revision          uint64                  `json:"revision"`
	Completed         uint64                  `json:"completed"`
	MatchedFindings   uint64                  `json:"matchedFindings"`
	MatchedWarnings   int                     `json:"matchedWarnings"`
	EvaluatedSources  int                     `json:"evaluatedSources"`
	UnassessedRecords int                     `json:"unassessedRecords"`
	UnassessedReasons []UnassessedReasonCount `json:"unassessedReasons"`
	Findings          []Finding               `json:"findings"`
	DisplayReasons    []string                `json:"displayReasons"`
	AssessedAt        time.Time               `json:"assessedAt"`
}

var gapReasons = []string{"debian_comparator_unavailable", "published_fix_unavailable", "vendor_fixed_version_unsupported", "vendor_range_unsupported", "vendor_status_undetermined", "vendor_record_uninterpretable"}

func gapBit(code string) uint64 {
	for i, v := range gapReasons {
		if code == v {
			return 1 << i
		}
	}
	return 0
}
func (p *checkpoint) gap(code string) {
	bit := gapBit(code)
	if !p.RecordUnassessed {
		p.UnassessedRecords++
		p.RecordUnassessed = true
	}
	if p.RecordReasons&bit != 0 {
		return
	}
	p.RecordReasons |= bit
	for i := range p.UnassessedReasons {
		if p.UnassessedReasons[i].Reason == code {
			p.UnassessedReasons[i].Count++
			return
		}
	}
	p.UnassessedReasons = append(p.UnassessedReasons, UnassessedReasonCount{code, 1})
}
func (p *checkpoint) evaluated() {
	if !p.SourceEvaluated {
		p.SourceEvaluated = true
		p.EvaluatedSources++
	}
}
func (p *checkpoint) advance(plan workPlan) {
	p.Completed++
	p.InstalledVersion++
	if p.InstalledVersion == len(plan.sources[p.Source].versions) {
		p.InstalledVersion = 0
		p.Record++
		p.RecordMatched = false
		p.RecordUnassessed = false
		p.RecordReasons = 0
		if p.Record == len(plan.sources[p.Source].rules) {
			p.Record = 0
			p.Source++
			p.SourceEvaluated = false
		}
	}
}

func planInventory(ctx context.Context, snapshot *Snapshot, rows []linuxpackages.PackageRow, result *Result) (workPlan, bool) {
	plan := workPlan{versions: map[string]*versionGroup{}}
	for _, p := range rows {
		if ctx.Err() != nil {
			return workPlan{}, false
		}
		if p.InstallState != "installed" {
			result.SkippedPackageCount++
			result.Coverage.PackageGaps.InstallationIncomplete++
			result.ReasonCodes = appendUnique(result.ReasonCodes, "package_installation_incomplete")
			continue
		}
		if excludedVersion(p.Version) || excludedVersion(p.SourceVersion) {
			result.SkippedPackageCount++
			result.Coverage.PackageGaps.NonstandardVersion++
			result.ReasonCodes = appendUnique(result.ReasonCodes, "nonstandard_package_version")
			continue
		}
		key := p.SourcePackage + "\x00" + p.SourceVersion
		g := plan.versions[key]
		if g == nil {
			g = &versionGroup{source: p.SourcePackage, version: p.SourceVersion}
			plan.versions[key] = g
		}
		g.binaries = append(g.binaries, Binary{Name: p.Name, Version: p.Version, Architecture: p.Architecture})
	}
	keys := make([]string, 0, len(plan.versions))
	for key := range plan.versions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			return workPlan{}, false
		}
		g := plan.versions[key]
		rules := snapshot.rules[g.source]
		if len(rules) == 0 {
			result.SkippedPackageCount += len(g.binaries)
			result.Coverage.PackageGaps.SourceMissing += len(g.binaries)
			result.ReasonCodes = appendUnique(result.ReasonCodes, "source_package_not_in_import")
			continue
		}
		result.Coverage.TotalCheckCount += uint64(len(rules))
		if len(plan.sources) == 0 || plan.sources[len(plan.sources)-1].source != g.source {
			plan.sources = append(plan.sources, sourceGroup{source: g.source, rules: rules})
		}
		s := &plan.sources[len(plan.sources)-1]
		s.versions = append(s.versions, g)
	}
	return plan, true
}

func decodeCheckpoint(raw []byte, id string, plan workPlan, total uint64, now time.Time) (checkpoint, error) {
	p := checkpoint{Version: EvaluatorVersion, AssessmentID: id, Findings: []Finding{}, UnassessedReasons: []UnassessedReasonCount{}, DisplayReasons: []string{}}
	if len(raw) == 0 {
		return p, nil
	}
	if len(raw) > MaxCheckpointBytes || validateJSON(context.Background(), raw) != nil {
		return checkpoint{}, ErrCheckpoint
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version != EvaluatorVersion || p.AssessmentID != id || p.Revision == 0 || p.Revision > total+1 || !validTime(p.AssessedAt) || p.AssessedAt.After(now) {
		return checkpoint{}, ErrCheckpoint
	}
	canonical, marshalErr := json.Marshal(p)
	if marshalErr != nil || !bytes.Equal(raw, canonical) || p.Findings == nil || p.UnassessedReasons == nil || p.DisplayReasons == nil {
		return checkpoint{}, ErrCheckpoint
	}
	if p.Source < 0 || p.Source > len(plan.sources) || p.Record < 0 || p.InstalledVersion < 0 {
		return checkpoint{}, ErrCheckpoint
	}
	var completed uint64
	visitedRecords := 0
	for i := 0; i < p.Source; i++ {
		completed += uint64(len(plan.sources[i].rules)) * uint64(len(plan.sources[i].versions))
		visitedRecords += len(plan.sources[i].rules)
	}
	if p.Source < len(plan.sources) {
		s := plan.sources[p.Source]
		if p.Record >= len(s.rules) || p.InstalledVersion >= len(s.versions) {
			return checkpoint{}, ErrCheckpoint
		}
		completed += uint64(p.Record)*uint64(len(s.versions)) + uint64(p.InstalledVersion)
		visitedRecords += p.Record
		if p.InstalledVersion > 0 {
			visitedRecords++
		}
	} else if p.Record != 0 || p.InstalledVersion != 0 || p.SourceEvaluated {
		return checkpoint{}, ErrCheckpoint
	}
	if completed != p.Completed || completed == 0 && total > 0 || completed > total || p.MatchedFindings > completed || p.MatchedWarnings < 0 || uint64(p.MatchedWarnings) > p.MatchedFindings || p.EvaluatedSources < 0 || p.EvaluatedSources > len(plan.sources) || p.EvaluatedSources > p.Source+boolCount(p.SourceEvaluated) || p.UnassessedRecords < 0 || uint64(p.UnassessedRecords) > completed-p.MatchedFindings || p.UnassessedRecords > visitedRecords || p.MatchedWarnings > visitedRecords || p.RecordReasons >= 1<<len(gapReasons) || p.RecordUnassessed != (p.RecordReasons != 0) || len(p.Findings) > MaxFindings || uint64(len(p.Findings)) > p.MatchedFindings || len(p.UnassessedReasons) > len(gapReasons) || len(p.DisplayReasons) > 3 {
		return checkpoint{}, ErrCheckpoint
	}
	if p.InstalledVersion == 0 && (p.RecordMatched || p.RecordUnassessed || p.RecordReasons != 0) {
		return checkpoint{}, ErrCheckpoint
	}
	if p.Record == 0 && p.InstalledVersion == 0 && p.SourceEvaluated {
		return checkpoint{}, ErrCheckpoint
	}
	if p.SourceEvaluated && p.EvaluatedSources == 0 || p.RecordMatched && (p.MatchedWarnings == 0 || !p.SourceEvaluated) || p.RecordUnassessed && p.UnassessedRecords == 0 || p.MatchedFindings > 0 && (p.MatchedWarnings == 0 || p.EvaluatedSources == 0) || completed > 0 && p.Revision > completed {
		return checkpoint{}, ErrCheckpoint
	}
	last := ""
	gapTotal := 0
	reasonBits := uint64(0)
	for _, reason := range p.UnassessedReasons {
		if gapBit(reason.Reason) == 0 || reason.Reason <= last || reason.Count < 1 || reason.Count > p.UnassessedRecords {
			return checkpoint{}, ErrCheckpoint
		}
		last = reason.Reason
		gapTotal += reason.Count
		reasonBits |= gapBit(reason.Reason)
	}
	if gapTotal < p.UnassessedRecords || p.RecordReasons & ^reasonBits != 0 {
		return checkpoint{}, ErrCheckpoint
	}
	byteTrimmed := false
	for i, reason := range p.DisplayReasons {
		if reason != "finding_limit_exceeded" && reason != "response_byte_limit_exceeded" && reason != "binary_limit_exceeded" {
			return checkpoint{}, ErrCheckpoint
		}
		if reason == "response_byte_limit_exceeded" {
			byteTrimmed = true
		}
		for j := 0; j < i; j++ {
			if p.DisplayReasons[j] == reason {
				return checkpoint{}, ErrCheckpoint
			}
		}
	}
	if !byteTrimmed && uint64(len(p.Findings)) != min(uint64(MaxFindings), p.MatchedFindings) {
		return checkpoint{}, ErrCheckpoint
	}
	for i, f := range p.Findings {
		g := plan.versions[f.SourcePackage+"\x00"+f.InstalledSourceVersion]
		if g == nil || len(f.Binaries) != 1 || f.BinariesTruncated || f.Binaries[0] != g.binaries[0] || f.Basis != "distribution_package_version_match" || !assessment.ValidDebianVersion(f.PublishedFixedVersion) {
			return checkpoint{}, ErrCheckpoint
		}

		sourceIndex := sort.Search(len(plan.sources), func(j int) bool { return plan.sources[j].source >= f.SourcePackage })
		if sourceIndex == len(plan.sources) || plan.sources[sourceIndex].source != f.SourcePackage {
			return checkpoint{}, ErrCheckpoint
		}
		source := plan.sources[sourceIndex]
		recordIndex := sort.Search(len(source.rules), func(j int) bool { return source.rules[j].cve >= f.CVEID })
		versionIndex := sort.Search(len(source.versions), func(j int) bool { return source.versions[j].version >= f.InstalledSourceVersion })
		if recordIndex == len(source.rules) || versionIndex == len(source.versions) || source.rules[recordIndex].cve != f.CVEID || source.versions[versionIndex].version != f.InstalledSourceVersion {
			return checkpoint{}, ErrCheckpoint
		}
		rule := source.rules[recordIndex]
		if rule.advisoryURL != f.AdvisoryURL || rule.reason != "" || sourceIndex > p.Source || sourceIndex == p.Source && (recordIndex > p.Record || recordIndex == p.Record && versionIndex >= p.InstalledVersion) {
			return checkpoint{}, ErrCheckpoint
		}
		validFix := rule.fixed != "" && rule.fixed == f.PublishedFixedVersion
		if rule.fixed == "" {
			for _, interval := range rule.intervals {
				if interval.fixed == f.PublishedFixedVersion {
					validFix = true
					break
				}
			}
		}
		if !validFix {
			return checkpoint{}, ErrCheckpoint
		}

		for j := 0; j < i; j++ {
			if p.Findings[j].SourcePackage == f.SourcePackage && p.Findings[j].CVEID == f.CVEID && p.Findings[j].InstalledSourceVersion == f.InstalledSourceVersion {
				return checkpoint{}, ErrCheckpoint
			}
		}
	}
	return p, nil
}
func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}

// EvaluateStep validates the entire immutable input, then advances at most 4,000
// checks and 2,000 actual comparator calls within three seconds. An interrupted
// multi-comparison check stays at the cursor and is retried whole. The returned
// checkpoint is a candidate only; callers must durably save it before output.
func EvaluateStep(ctx context.Context, snapshot *Snapshot, manifest fullinventory.Manifest, rows []linuxpackages.PackageRow, comparator assessment.VersionComparator, now time.Time, identity AssessmentIdentity, prior []byte) (Result, []byte, error) {
	result := Result{SchemaVersion: ResultSchemaVersion, Status: "unavailable", Freshness: "unknown", InventoryFreshness: InventoryFreshness(manifest.CollectedAt, now), AssessedAt: now.UTC(), Findings: []Finding{}, ReasonCodes: []string{}, Coverage: EvaluationCoverage{UnassessedReasons: []UnassessedReasonCount{}}}
	reason := func(code string) { result.ReasonCodes = appendUnique(result.ReasonCodes, code) }
	unavailable := func(code string) (Result, []byte, error) { reason(code); return result, nil, nil }
	if ctx == nil || ctx.Err() != nil {
		return unavailable("evaluation_canceled_or_timed_out")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if !validTime(now) || result.InventoryFreshness == "unknown" {
		return unavailable("inventory_time_invalid")
	}
	if !validInventory(ctx, manifest, rows) {
		if ctx.Err() != nil {
			return unavailable("evaluation_canceled_or_timed_out")
		}
		return unavailable("inventory_invalid_or_incomplete")
	}
	result.GenerationID = manifest.GenerationID
	target := manifest.Release.Fields.Target()
	if target != linuxpackages.Debian13 && target != linuxpackages.Ubuntu2404 {
		return unavailable("release_unsupported")
	}
	if snapshot == nil || !snapshot.valid {
		return unavailable("feed_missing")
	}
	metadata := snapshot.Metadata(now)
	result.Feed = &metadata
	result.Freshness = metadata.Freshness
	if metadata.Target != target {
		return unavailable("feed_target_mismatch")
	}
	if metadata.Freshness == "unknown" {
		return unavailable("feed_time_invalid")
	}
	reason(metadata.Coverage)
	if metadata.Trust != "https_origin_only" {
		reason("feed_origin_unverified")
	}
	reason("installed_origin_unverified")
	reason("published_fixes_only")
	reason("runtime_activation_not_assessed")
	plan, ok := planInventory(ctx, snapshot, rows, &result)
	if !ok {
		result.SkippedPackageCount = 0
		result.Coverage = EvaluationCoverage{UnassessedReasons: []UnassessedReasonCount{}}
		return unavailable("evaluation_canceled_or_timed_out")
	}
	id, err := AssessmentID(snapshot, manifest, identity)
	if err != nil {
		return unavailable("inventory_invalid_or_incomplete")
	}
	if len(prior) > 0 && result.InventoryFreshness != "fresh" {
		return result, nil, ErrCheckpoint
	}
	p, err := decodeCheckpoint(prior, id, plan, result.Coverage.TotalCheckCount, now)
	if err != nil {
		return result, nil, err
	}
	if len(prior) > 0 && (p.AssessedAt.Before(manifest.CollectedAt) || p.AssessedAt.Before(snapshot.metadata.FetchedAt)) {
		return result, nil, ErrCheckpoint
	}
	result.Status = "partial"
	if result.Freshness == "stale" {
		result.Status = "stale"
		reason("feed_stale")
	}
	if result.InventoryFreshness == "stale" {
		result.Status = "stale"
		reason("inventory_stale")
	}
	initial := p.Completed
	comparisons := 0
	memo := map[string]int{}
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
		v, e := comparator.Compare(ctx, a, b)
		if e != nil || v < -1 || v > 1 {
			return 0, assessment.ErrComparatorUnavailable
		}
		memo[key] = v
		return v, nil
	}
	stop := ""
	for p.Source < len(plan.sources) {
		if ctx.Err() != nil {
			stop = "evaluation_canceled_or_timed_out"
			break
		}
		if p.Completed-initial >= MaxVisitedChecks {
			stop = "visited_check_limit_exceeded"
			break
		}
		s := plan.sources[p.Source]
		r := s.rules[p.Record]
		g := s.versions[p.InstalledVersion]
		if r.reason != "" {
			if r.reason == "vendor_not_affected" {
				p.evaluated()
			} else {
				p.gap(r.reason)
			}
			p.advance(plan)
			continue
		}
		fixed, applied, e := matchRule(r, g.version, compare)
		if e != nil {
			if errors.Is(e, ErrLimit) {
				stop = "comparison_limit_exceeded"
				break
			}
			if ctx.Err() != nil || errors.Is(e, ErrCanceled) {
				stop = "evaluation_canceled_or_timed_out"
				break
			}
			p.gap("debian_comparator_unavailable")
			p.advance(plan)
			continue
		}
		p.evaluated()
		if applied {
			p.MatchedFindings++
			if !p.RecordMatched {
				p.RecordMatched = true
				p.MatchedWarnings++
			}
			if len(p.Findings) < MaxFindings {
				p.Findings = append(p.Findings, Finding{CVEID: r.cve, SourcePackage: g.source, InstalledSourceVersion: g.version, PublishedFixedVersion: fixed, Basis: "distribution_package_version_match", AdvisoryURL: r.advisoryURL, Binaries: []Binary{g.binaries[0]}})
			} else {
				p.DisplayReasons = appendUnique(p.DisplayReasons, "finding_limit_exceeded")
			}
		}
		p.advance(plan)
	}
	advanced := p.Completed - initial
	complete := p.Completed == result.Coverage.TotalCheckCount
	if advanced > 0 || len(prior) == 0 && complete {
		p.Revision++
		p.AssessedAt = now.UTC()
	}
	result.Continuation = Continuation{AssessmentID: id, State: "pending", Revision: p.Revision, AdvancedCheckCount: advanced, Reason: stop}
	if complete {
		result.Continuation.State = "complete"
	} else {
		reason(stop)
		result.Truncated = true
		if advanced == 0 {
			result.Continuation.State = "blocked"
		}
	}
	if p.Revision > 0 {
		result.AssessedAt = p.AssessedAt
	}
	sort.Slice(p.UnassessedReasons, func(i, j int) bool { return p.UnassessedReasons[i].Reason < p.UnassessedReasons[j].Reason })
	result.Coverage.CompletedCheckCount = p.Completed
	result.Coverage.EvaluationComplete = complete
	result.Coverage.ComparisonCount = comparisons
	result.Coverage.MatchedFindingCount = p.MatchedFindings
	result.Coverage.MatchedWarningCount = p.MatchedWarnings
	result.Coverage.UnassessedReasons = append([]UnassessedReasonCount{}, p.UnassessedReasons...)
	result.EvaluatedSourceCount = p.EvaluatedSources
	result.UnassessedRecordCount = p.UnassessedRecords
	for _, g := range p.UnassessedReasons {
		reason(g.Reason)
	}
	projectFindings(&result, &p, plan)
	if advanced == 0 && !complete {
		return result, nil, nil
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxCheckpointBytes {
		return result, nil, ErrCheckpoint
	}
	return result, raw, nil
}

func projectFindings(result *Result, p *checkpoint, plan workPlan) {
	result.Findings = append([]Finding{}, p.Findings...)
	for i := range result.Findings {
		result.Findings[i].Binaries = append([]Binary{}, p.Findings[i].Binaries...)
	}
	// Reserve the first-binary slots for the pre-trim finding prefix. Byte
	// trimming removes a suffix, but must not redistribute its slots to extra
	// binaries on a cached read and progressively erase more retained rows.
	binaryRows := int(min(uint64(MaxFindings), p.MatchedFindings))
	for i, f := range result.Findings {
		g := plan.versions[f.SourcePackage+"\x00"+f.InstalledSourceVersion]
		limit := min(len(g.binaries), MaxBinariesPerFinding)
		for j := 1; j < limit && binaryRows < MaxBinaryRows; j++ {
			result.Findings[i].Binaries = append(result.Findings[i].Binaries, g.binaries[j])
			binaryRows++
		}
		result.Findings[i].BinariesTruncated = len(result.Findings[i].Binaries) < len(g.binaries)
		if result.Findings[i].BinariesTruncated {
			p.DisplayReasons = appendUnique(p.DisplayReasons, "binary_limit_exceeded")
		}
	}
	for _, r := range p.DisplayReasons {
		result.ReasonCodes = appendUnique(result.ReasonCodes, r)
		result.Truncated = true
	}
	for {
		raw, e := json.Marshal(result)
		if e == nil && len(raw) <= MaxResultBytes {
			break
		}
		if len(result.Findings) == 0 {
			break
		}
		result.Findings = result.Findings[:len(result.Findings)-1]
		p.Findings = p.Findings[:len(p.Findings)-1]
		p.DisplayReasons = appendUnique(p.DisplayReasons, "response_byte_limit_exceeded")
		result.ReasonCodes = appendUnique(result.ReasonCodes, "response_byte_limit_exceeded")
		result.Truncated = true
	}
}
