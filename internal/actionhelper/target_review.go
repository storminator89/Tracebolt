package actionhelper

// This file builds a review, never authority. The existing runtime remains the
// sole validator immediately before each separately approved service action.
import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"localrmm/internal/actionpermit"
)

const (
	SetupTargetReviewVersion = "tracebolt.service-target-review.v1"
	maxDiscoveryUnits        = 512
	maxReviewInputBytes      = 32 << 20
	maxReviewTotalBytes      = 128 << 20
	// A single assertion belongs in the installer's combined local approval.
	SetupTargetReviewAssertion = "I reviewed every listed service's restart and stop effects and all application execution inputs. The listed pins cover the relevant persistent inputs; these services do not depend on unreviewed scripts, plugins, configuration, subprocesses or other mutable execution inputs. Hashes and automatic discovery do not prove this assertion."
)

// SetupTargetSnapshot is a data-only inspection input. A snapshot supplied by a
// caller is not proof of root protection or of a real host inspection. The
// production collector below reads through the existing protected-file loader.
// Raw bytes are never included in the public report.
type SetupTargetSnapshot struct {
	Architecture string
	Units        []string
	Properties   map[string][]byte
	Files        map[string][]byte
	Revisions    map[string]string
	Unavailable  map[string]string
}

type SetupTargetCandidate struct {
	Unit           string    `json:"unit"`
	Executable     string    `json:"executable"`
	Units          []UnitPin `json:"units"`
	Inputs         []FilePin `json:"inputs"`
	InputRevisions []FilePin `json:"inputRevisions"`
}

type SetupTargetUnavailable struct {
	Unit   string `json:"unit"`
	Reason string `json:"reason"`
}

// Candidates deliberately have neither ReviewDigest nor UnitPolicyDigest.
// They cannot be consumed as Target values until the caller records the exact
// combined local approval and the explicit review-completeness assertion.
type SetupTargetReview struct {
	SchemaVersion     string                   `json:"schemaVersion"`
	Architecture      string                   `json:"architecture"`
	Candidates        []SetupTargetCandidate   `json:"candidates"`
	Unavailable       []SetupTargetUnavailable `json:"unavailable"`
	RequiredAssertion string                   `json:"requiredAssertion"`
	ReportDigest      string                   `json:"reportDigest"`
	seal              string
}

type SetupTargetReviewApproval struct {
	ReportDigest                 string
	ApprovalRecordDigest         string
	CompleteInputsAndEffectsRead bool
}

// BuildSetupTargetReview is pure: only supplied bytes are examined. It neither
// executes a program nor opens a file. Unsupported/ambiguous units remain in
// Unavailable; they never become hashed target grants by implication.
func BuildSetupTargetReview(s SetupTargetSnapshot) (SetupTargetReview, error) {
	r := SetupTargetReview{SchemaVersion: SetupTargetReviewVersion, Architecture: s.Architecture,
		Candidates: []SetupTargetCandidate{}, Unavailable: []SetupTargetUnavailable{}, RequiredAssertion: SetupTargetReviewAssertion}
	if (s.Architecture != "amd64" && s.Architecture != "arm64") || len(s.Units) > maxDiscoveryUnits {
		return SetupTargetReview{}, ErrUnavailable
	}
	total := 0
	for _, raw := range s.Files {
		if len(raw) > maxReviewInputBytes || len(raw) > maxReviewTotalBytes-total {
			return SetupTargetReview{}, ErrUnavailable
		}
		total += len(raw)
	}
	units := slices.Clone(s.Units)
	sort.Strings(units)
	for i, unit := range units {
		if !listedServiceName(unit) || (i > 0 && units[i-1] == unit) {
			return SetupTargetReview{}, ErrRejected
		}
		candidate, reason := buildSetupTargetCandidate(s, unit)
		if reason != "" {
			r.Unavailable = append(r.Unavailable, SetupTargetUnavailable{unit, reason})
		} else {
			r.Candidates = append(r.Candidates, candidate)
		}
	}
	// Never quietly choose whichever sixteen happen to sort first. The existing
	// policy cannot represent a larger aggregate review.
	if len(r.Candidates) > 16 {
		for _, c := range r.Candidates {
			r.Unavailable = append(r.Unavailable, SetupTargetUnavailable{c.Unit, "aggregate_target_limit_exceeded"})
		}
		r.Candidates = []SetupTargetCandidate{}
		sort.Slice(r.Unavailable, func(i, j int) bool { return r.Unavailable[i].Unit < r.Unavailable[j].Unit })
	}
	r.ReportDigest = setupTargetReviewDigest(r)
	r.seal = r.ReportDigest
	return r, nil
}

func setupTargetReviewDigest(r SetupTargetReview) string {
	r.ReportDigest = ""
	raw, _ := json.Marshal(r)
	return actionpermit.Digest(raw)
}

// FinalizeSetupTargetReview only packages a completed local review. The caller
// must have obtained the actual combined approval; a syntactically valid digest
// cannot prove a person reviewed anything. There is no JSON import, apply,
// helper connection or authority write here. Reinspect and compare ReportDigest
// at installation, and keep CheckSetupTarget/runtime checks for every action.
func FinalizeSetupTargetReview(r SetupTargetReview, approval SetupTargetReviewApproval) ([]Target, error) {
	if r.seal == "" || r.ReportDigest != r.seal || setupTargetReviewDigest(r) != r.seal ||
		approval.ReportDigest != r.ReportDigest || !actionpermit.ValidDigest(approval.ApprovalRecordDigest) ||
		!approval.CompleteInputsAndEffectsRead || len(r.Candidates) == 0 || len(r.Candidates) > 16 {
		return nil, ErrRejected
	}
	targets := make([]Target, 0, len(r.Candidates))
	for _, c := range r.Candidates {
		t := Target{Unit: c.Unit, ReviewDigest: approval.ApprovalRecordDigest, Units: slices.Clone(c.Units), Inputs: slices.Clone(c.Inputs)}
		if _, err := SetupTargetDigest(t); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func buildSetupTargetCandidate(s SetupTargetSnapshot, unit string) (SetupTargetCandidate, string) {
	if !canonicalUnit(unit) {
		return SetupTargetCandidate{}, "unsupported_unit_name_template_or_instance"
	}
	if protectedUnit(unit) {
		return SetupTargetCandidate{}, "protected_service"
	}
	if reason := s.Unavailable[unit]; reason != "" {
		switch reason {
		case "loaded_properties_unavailable", "protected_fragment_unavailable", "protected_execution_input_unavailable":
			return SetupTargetCandidate{}, reason
		default:
			return SetupTargetCandidate{}, "inspection_unavailable"
		}
	}
	p, err := parseProperties(s.Properties[unit], configurationProperties)
	if err != nil {
		return SetupTargetCandidate{}, "incomplete_or_invalid_loaded_properties"
	}
	if reason := supportedReviewProperties(unit, p); reason != "" {
		return SetupTargetCandidate{}, reason
	}
	fragment := p["FragmentPath"]
	program, args, reason := parseSimpleService(s.Files[fragment], p)
	if reason != "" {
		return SetupTargetCandidate{}, reason
	}
	if knownInterpreterOrWrapper(program) {
		return SetupTargetCandidate{}, "interpreter_or_command_wrapper_unsupported"
	}
	paths := []string{systemctlPath, fragment, program}
	for _, arg := range args {
		value := arg
		if _, rhs, ok := strings.Cut(arg, "="); ok {
			value = rhs
		}
		if strings.HasPrefix(value, "/") {
			if !safeInputPath(value) {
				return SetupTargetCandidate{}, "unsupported_argument_input_path"
			}
			paths = append(paths, value)
		} else if strings.Contains(value, "/") || strings.HasPrefix(value, ".") {
			return SetupTargetCandidate{}, "ambiguous_relative_argument_input"
		}
	}
	sort.Strings(paths)
	paths = slices.Compact(paths)
	if len(paths) > 32 {
		return SetupTargetCandidate{}, "target_input_limit_exceeded"
	}
	c := SetupTargetCandidate{Unit: unit, Executable: program, Units: []UnitPin{{unit, configurationDigest(p)}}, Inputs: []FilePin{}, InputRevisions: []FilePin{}}
	for _, name := range paths {
		raw, found := s.Files[name]
		if !safeInputPath(name) || !found || len(raw) == 0 || len(raw) > maxReviewInputBytes || !actionpermit.ValidDigest(s.Revisions[name]) {
			return SetupTargetCandidate{}, "missing_unprotected_or_oversized_input"
		}
		c.Inputs = append(c.Inputs, FilePin{name, actionpermit.Digest(raw)})
		c.InputRevisions = append(c.InputRevisions, FilePin{name, s.Revisions[name]})
	}
	if reason := simpleExecutable(s.Files[program], s.Architecture); reason != "" {
		return SetupTargetCandidate{}, reason
	}
	return c, ""
}

// These fixed boot/shutdown edges do not introduce another application service
// into a restart transaction. All other relationships, including ordering edges
// to protected services, are excluded. We do not recursively infer safe effects.
var supportedBootRelationships = map[string][]string{
	"Requires":  {"sysinit.target"},
	"Conflicts": {"shutdown.target"},
	"Before":    {"shutdown.target", "multi-user.target"},
	"After":     {"basic.target", "sysinit.target", "systemd-journald.socket"},
	"WantedBy":  {"multi-user.target"},
}

func supportedReviewProperties(unit string, p map[string]string) string {
	if p["Id"] != unit || p["Names"] != unit {
		return "alias_or_noncanonical_loaded_identity"
	}
	if p["LoadState"] != "loaded" {
		return "service_not_loaded"
	}
	if p["Transient"] != "no" || p["NeedDaemonReload"] != "no" {
		return "transient_or_pending_reload"
	}
	if !safeInputPath(p["FragmentPath"]) || path.Ext(p["FragmentPath"]) != ".service" {
		return "generated_or_unsupported_fragment"
	}
	if p["DropInPaths"] != "" {
		return "drop_in_semantics_require_separate_review"
	}
	if p["Type"] != "simple" {
		return "unsupported_service_type"
	}
	for _, key := range configurationProperties[7 : len(configurationProperties)-3] {
		for _, related := range strings.Fields(p[key]) {
			if strings.HasSuffix(related, ".service") && protectedUnit(related) {
				return "protected_service_relationship:" + key
			}
			if !slices.Contains(supportedBootRelationships[key], related) {
				return "unsupported_service_relationship:" + key
			}
		}
	}
	return ""
}

var simpleToken = regexp.MustCompile(`^[A-Za-z0-9_./,:=+\-]+$`)

func parseSimpleService(raw []byte, p map[string]string) (string, []string, string) {
	if len(raw) == 0 || len(raw) > maxShowBytes || bytes.ContainsAny(raw, "\x00\r\\") {
		return "", nil, "missing_or_ambiguous_unit_fragment"
	}
	values := map[string]string{}
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if line == "[Unit]" || line == "[Service]" || line == "[Install]" {
			section = line[1 : len(line)-1]
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		full := section + "." + key
		if !ok || section == "" || value == "" {
			return "", nil, "ambiguous_unit_syntax"
		}
		if _, exists := values[full]; exists {
			return "", nil, "repeated_unit_directive"
		}
		switch full {
		case "Unit.Description", "Unit.Documentation":
		case "Service.Type", "Service.ExecStart", "Service.User", "Service.Group", "Service.Restart", "Service.KillMode", "Service.KillSignal", "Service.TimeoutStopSec", "Install.WantedBy":
		default:
			return "", nil, "unsupported_unit_directive:" + safeDirectiveName(full)
		}
		values[full] = value
	}
	if values["Service.Type"] != "" && values["Service.Type"] != "simple" {
		return "", nil, "unsupported_service_type"
	}
	// Numeric, nonroot identities avoid unpinned NSS account/group lookup changes.
	for _, key := range []string{"User", "Group"} {
		v := values["Service."+key]
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 || n == uint64(^uint32(0)) || strconv.FormatUint(n, 10) != v || p[key] != v {
			return "", nil, "nonroot_numeric_identity_required"
		}
	}
	for _, item := range [][2]string{{"Service.Restart", "no"}, {"Service.KillMode", "control-group"}, {"Service.KillSignal", "SIGTERM"}, {"Install.WantedBy", "multi-user.target"}} {
		if value := values[item[0]]; value != "" && value != item[1] {
			return "", nil, "unsupported_unit_directive_value:" + item[0]
		}
	}
	if value := values["Service.TimeoutStopSec"]; value != "" {
		seconds := strings.TrimSuffix(value, "s")
		n, err := strconv.ParseUint(seconds, 10, 8)
		if err != nil || n < 1 || n > 90 || strconv.FormatUint(n, 10) != seconds {
			return "", nil, "unsupported_stop_timeout"
		}
	}
	tokens := strings.Fields(values["Service.ExecStart"])
	if len(tokens) == 0 || len(tokens) > 24 || !safeInputPath(tokens[0]) {
		return "", nil, "single_absolute_exec_start_required"
	}
	for _, token := range tokens {
		if !simpleToken.MatchString(token) || len(token) > 512 {
			return "", nil, "exec_expansion_shell_or_escaping_unsupported"
		}
	}
	return tokens[0], slices.Clone(tokens[1:]), ""
}

func safeDirectiveName(name string) string {
	for _, ch := range name {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch == '.') {
			return "unknown"
		}
	}
	if len(name) > 80 {
		return "unknown"
	}
	return name
}

func simpleExecutable(raw []byte, architecture string) string {
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return "script_or_non_elf_executable"
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB ||
		(architecture == "amd64" && f.Machine != elf.EM_X86_64) || (architecture == "arm64" && f.Machine != elf.EM_AARCH64) {
		return "unsupported_executable_format_or_architecture"
	}
	executableSegment := false
	for _, program := range f.Progs {
		if program.Type == elf.PT_INTERP || program.Type == elf.PT_DYNAMIC {
			return "dynamic_executable_input_closure_unsupported"
		}
		if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 && f.Entry >= program.Vaddr && f.Entry-program.Vaddr < program.Memsz {
			executableSegment = true
		}
	}
	if !executableSegment {
		return "unsupported_executable_load_segments"
	}
	for _, section := range f.Sections {
		if section.Type == elf.SHT_DYNAMIC {
			return "dynamic_executable_input_closure_unsupported"
		}
	}
	return ""
}

// A name denylist catches ordinary interpreter entry points, not disguised or
// embedded interpreters. The required application review remains indispensable.
func knownInterpreterOrWrapper(program string) bool {
	name := strings.ToLower(path.Base(program))
	for _, exact := range []string{"sh", "bash", "dash", "zsh", "ksh", "csh", "fish", "busybox", "env", "sudo", "su", "runuser", "chroot", "setpriv", "xargs", "timeout"} {
		if name == exact {
			return true
		}
	}
	for _, prefix := range []string{"python", "perl", "ruby", "node", "lua", "php", "java"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func listedServiceName(unit string) bool {
	if len(unit) < 9 || len(unit) > 255 || !strings.HasSuffix(unit, ".service") {
		return false
	}
	for _, ch := range unit {
		if ch < 33 || ch > 126 || ch == '/' {
			return false
		}
	}
	return true
}
