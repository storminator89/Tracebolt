package linuxcve

import "errors"

// Fixed codes and counters only. Never retain a package/CVE name, JSON value,
// input fragment, URL or lower-level decoder error in parser diagnostics.
type invalidStage uint8

const (
	invalidJSONToken invalidStage = iota + 1
	invalidJSONKey
	invalidJSONDuplicate
	invalidJSONClose
	invalidJSONTrailing
	invalidDebianRoot
	invalidDebianSourceName
	invalidDebianSourceRecords
	invalidDebianEmptySource
	invalidDebianIssue
	invalidDebianReleases
	invalidDebianRelease
	invalidDebianStatus
	invalidDebianFixedVersion
	invalidTargetScope
	invalidJSONUTF8
)

var invalidStageCodes = [...]string{"", "json_token", "json_key", "json_duplicate_key", "json_close", "json_trailing", "debian_root", "debian_source_name", "debian_source_records", "debian_empty_source", "debian_issue", "debian_releases", "debian_release", "debian_status", "debian_fixed_version", "target_scope_empty", "json_utf8"}

type invalidDetail struct {
	stage        invalidStage
	items, depth int
}

func (*invalidDetail) Error() string { return "linux_cve_bundle_invalid" }
func (*invalidDetail) Unwrap() error { return ErrInvalid }
func invalidAt(stage invalidStage, items, depth int) error {
	return &invalidDetail{stage, items, depth}
}

// InvalidDiagnostic exposes only a closed code and bounded counters to the
// opt-in hosted smoke. Ordinary API error text and errors.Is remain unchanged.
func InvalidDiagnostic(err error) (code string, items, depth int, ok bool) {
	var detail *invalidDetail
	if !errors.As(err, &detail) || detail.stage < 1 || int(detail.stage) >= len(invalidStageCodes) || detail.items < 0 || detail.items > 16000001 || detail.depth < 0 || detail.depth > 33 {
		return "", 0, 0, false
	}
	return invalidStageCodes[detail.stage], detail.items, detail.depth, true
}
