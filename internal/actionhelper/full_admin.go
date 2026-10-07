package actionhelper

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"localrmm/internal/actionpermit"
)

const (
	PolicyVersionV2       = "tracebolt.action-helper-policy.v2"
	FullAdminServiceScope = actionpermit.FullAdminServiceScope
	CapabilitiesVersionV2 = "tracebolt.action-capabilities.v2"
	MaxServicesV2         = 256
	MaxGraphUnitsV2       = 64
	FullAdminReviewNotice = "This action trusts the existing root-controlled systemd service configuration and its host authority. It may interrupt dependent services, management connectivity, or your current session. Existing root-run programs may indirectly affect Tracebolt; this grant is not a sandbox."
)

// ServiceInspection is a bounded automatic observation, never a host grant.
// Its digest commits to all relevant effective configuration, authority paths,
// files and stop/start propagation collected by the fixed systemd adapter.
type ServiceInspection struct {
	Unit             string      `json:"unit"`
	UnitPolicyDigest string      `json:"unitPolicyDigest"`
	AffectedServices []string    `json:"affectedServices"`
	ObservedState    Observation `json:"observedState"`
}

type fullAdminBackend interface {
	InspectService(context.Context, string) (ServiceInspection, error)
	ListServices(context.Context) ([]string, error)
}

func protectedFullAdminUnit(unit string) bool {
	n := strings.TrimSuffix(strings.ToLower(unit), ".service")
	return n == "tracebolt" || n == "localrmm" || strings.HasPrefix(n, "tracebolt-") || strings.HasPrefix(n, "localrmm-")
}
func protectedFullAdminPath(p string) bool {
	return p == "/opt/tracebolt-agent" || strings.HasPrefix(p, "/opt/tracebolt-agent/") || strings.HasPrefix(p, "/usr/libexec/tracebolt-")
}
func unsupportedUnitAuthorityPath(p string) bool {
	if _, err := authorityPathPartsPortable(p); err != nil {
		return true
	}
	for _, prefix := range []string{"/run/systemd/generator/", "/run/systemd/generator.early/", "/run/systemd/generator.late/", "/run/systemd/transient/", "/run/user/", "/etc/systemd/user/", "/usr/lib/systemd/user/", "/usr/local/lib/systemd/user/", "/run/systemd/user/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
func validRelatedUnit(unit string) bool {
	if len(unit) < 3 || len(unit) > 255 || strings.ContainsAny(unit, "@/\\\x00\r\n\t ") {
		return false
	}
	for _, suffix := range []string{".service", ".target", ".mount", ".slice"} {
		if strings.HasSuffix(unit, suffix) {
			name := strings.TrimSuffix(unit, suffix)
			if name == "" {
				return false
			}
			for _, c := range name {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
					return false
				}
			}
			return true
		}
	}
	return false
}

// v1's exact property set and limits remain untouched. Execution records are
// normalized below because systemd show includes volatile process results.
var fullAdminProperties = append(append([]string{}, configurationProperties...),
	"ActiveState", "UnitFileState", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "ExecCondition",
	"Environment", "EnvironmentFiles", "WorkingDirectory", "RootDirectory", "RootImage", "DynamicUser", "RemainAfterExit", "Restart", "KillMode", "KillSignal", "RestartKillSignal", "SendSIGKILL", "TimeoutStartUSec", "TimeoutStopUSec", "RefuseManualStart", "RefuseManualStop", "StopWhenUnneeded", "OnFailureJobMode", "OnSuccessJobMode")

func fullAdminPropertiesForUnit(unit string) []string {
	if strings.HasSuffix(unit, ".service") {
		return fullAdminProperties
	}
	// Service-only properties are not exported by target/mount/slice objects.
	// Requiring them would reject every ordinary DefaultDependencies service.
	return append(append([]string{}, configurationProperties[:len(configurationProperties)-3]...), "ActiveState", "UnitFileState", "RefuseManualStart", "RefuseManualStop", "StopWhenUnneeded", "OnFailureJobMode", "OnSuccessJobMode")
}

var execPropertiesV2 = []string{"ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "ExecCondition"}

type fullAdminFile struct{ Path, Resolved, Digest, Revision string }
type fullAdminSource struct {
	run commandRunner
	// File follows only root-controlled symlinks/ancestors and returns a stable
	// identity+content fingerprint. The trusted adapter supplies the resolved path.
	file       func(string) (fullAdminFile, error)
	executable func(string) (fullAdminFile, error)
}
type fullAdminNode struct {
	Unit          string
	Effects       uint8
	Configuration map[string]string
	Files         []fullAdminFile
}

const (
	effectStart uint8 = 1
	effectStop  uint8 = 2
)

func normalizedExecV2(value string) (string, []string, error) {
	if value == "" {
		return "", nil, nil
	}

	// The stable prefix ends at ignore_errors. Strict structural parsing rejects
	// escaped/ambiguous paths rather than interpreting systemd text as a shell.
	records := []string{}
	paths := []string{}
	remaining := value
	for remaining != "" {
		if !strings.HasPrefix(remaining, "{ path=") {
			return "", nil, ErrRejected
		}
		end := strings.Index(remaining, " }")
		if end < 0 {
			return "", nil, ErrRejected
		}
		record := remaining[:end+2]
		pathEnd := strings.Index(record, " ; argv[]=")
		stableEnd := strings.Index(record, " ; start_time=")
		if pathEnd < 7 || stableEnd < pathEnd || !strings.Contains(record[pathEnd:stableEnd], " ; ignore_errors=") {
			return "", nil, ErrRejected
		}
		name := record[len("{ path="):pathEnd]
		if _, err := authorityPathPartsPortable(name); err != nil {
			return "", nil, ErrRejected
		}
		paths = append(paths, name)
		records = append(records, record[:stableEnd]+" }")
		remaining = strings.TrimPrefix(remaining[end+2:], " ")
		if len(records) > 32 {
			return "", nil, ErrRejected
		}
	}
	return strings.Join(records, " "), paths, nil
}
func authorityPathPartsPortable(p string) ([]string, error) {
	// This helper intentionally accepts only unambiguous absolute path spellings.
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00\r\n\t ") || len(p) > 512 || strings.Contains(p, "//") {
		return nil, ErrRejected
	}
	parts := strings.Split(p[1:], "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrRejected
		}
	}
	return parts, nil
}
func parseRelationshipsV2(value string) ([]string, error) {
	fields := strings.Fields(value)
	if len(fields) > MaxGraphUnitsV2 {
		return nil, inspectionError{"graph_bound_exceeded"}
	}
	sort.Strings(fields)
	for i, u := range fields {
		if !validRelatedUnit(u) || (i > 0 && u == fields[i-1]) {
			return nil, inspectionError{"unsupported_or_ambiguous_relationship"}
		}
	}
	return fields, nil
}

// Relationship order is not meaningful. Unrelated relationships are committed
// as metadata, not recursively expanded: e.g. an active sysinit.target may have
// hundreds of inverse dependents and template names without restarting them.
func canonicalizeRelationshipsV2(p map[string]string) {
	for _, key := range []string{"Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Conflicts", "Before", "After", "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "ConsistsOf", "ConflictedBy", "PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo", "StopPropagatedFrom", "OnFailure", "OnSuccess", "Triggers", "TriggeredBy", "Upholds", "UpheldBy"} {
		fields := strings.Fields(p[key])
		sort.Strings(fields)
		p[key] = strings.Join(fields, " ")
	}
}

// inspectServiceV2 models only the relevant transaction closure. Starting an
// already-active prerequisite does not stop/restart it or its dependents. An
// inactive prerequisite's start dependencies are followed; actual stop effects
// follow inverse Requires/BindsTo/PartOf and explicit stop propagation.
func inspectServiceV2(ctx context.Context, source fullAdminSource, unit string) (ServiceInspection, error) {
	if !canonicalUnit(unit) {
		return ServiceInspection{}, inspectionError{"canonical_unit_required"}
	}
	if protectedFullAdminUnit(unit) {
		return ServiceInspection{}, inspectionError{"control_plane_protected"}
	}
	if ctx == nil || ctx.Err() != nil || source.run == nil || source.file == nil {
		return ServiceInspection{}, ErrRejected
	}
	client, err := source.file(systemctlPath)
	if err != nil {
		return ServiceInspection{}, ErrRejected
	}
	effects := map[string]uint8{unit: effectStart | effectStop}
	queue := []string{unit}
	nodes := map[string]fullAdminNode{}
	for len(queue) > 0 {
		if ctx.Err() != nil || len(effects) > MaxGraphUnitsV2 {
			return ServiceInspection{}, inspectionError{"graph_bound_exceeded"}
		}
		name := queue[0]
		queue = queue[1:]
		raw, err := source.run(ctx, systemctlArgs("show", name, fullAdminPropertiesForUnit(name)))
		if err != nil {
			return ServiceInspection{}, ErrRejected
		}
		p, err := parseProperties(raw, fullAdminPropertiesForUnit(name))
		if err != nil {
			return ServiceInspection{}, err
		}
		if p["Id"] != name || p["Names"] != name || p["LoadState"] != "loaded" || p["FragmentPath"] == "" || protectedFullAdminUnit(name) {
			return ServiceInspection{}, inspectionError{"canonical_unit_required"}
		}
		if p["Transient"] != "no" {
			return ServiceInspection{}, inspectionError{"generated_or_transient_unit"}
		}
		if p["NeedDaemonReload"] != "no" {
			return ServiceInspection{}, inspectionError{"loaded_configuration_stale"}
		}
		switch p["UnitFileState"] {
		case "generated", "transient", "alias", "masked", "masked-runtime":
			return ServiceInspection{}, inspectionError{"generated_transient_or_masked_unit"}
		}
		// Trigger, automatic uphold, alternate root and special stop behavior need
		// semantics this bounded transaction model deliberately does not advertise.
		for _, key := range []string{"OnFailure", "OnSuccess", "Triggers", "TriggeredBy", "Upholds", "UpheldBy"} {
			if p[key] != "" {
				return ServiceInspection{}, inspectionError{"unsupported_automatic_relationship"}
			}
		}
		if p["RootDirectory"] != "" || p["RootImage"] != "" {
			return ServiceInspection{}, inspectionError{"alternate_execution_root"}
		}
		if (effects[name]&effectStart != 0 && (name == unit || p["ActiveState"] != "active") && p["RefuseManualStart"] != "no") || (effects[name]&effectStop != 0 && p["RefuseManualStop"] != "no") || p["StopWhenUnneeded"] != "no" {
			return ServiceInspection{}, inspectionError{"unsupported_stop_policy"}
		}
		if p["ActiveState"] != "active" && p["ActiveState"] != "inactive" && p["ActiveState"] != "failed" {
			return ServiceInspection{}, inspectionError{"unit_transitioning"}
		}
		canonicalizeRelationshipsV2(p)
		files := []fullAdminFile{}
		paths := append([]string{p["FragmentPath"]}, strings.Fields(p["DropInPaths"])...)
		if len(paths) > 33 {
			return ServiceInspection{}, ErrRejected
		}
		for _, key := range execPropertiesV2 {
			normalized, execs, err := normalizedExecV2(p[key])
			if err != nil {
				return ServiceInspection{}, inspectionError{"ambiguous_execution_path"}
			}
			p[key] = normalized
			for _, name := range execs {
				readExecutable := source.executable
				if readExecutable == nil {
					readExecutable = source.file
				}
				f, err := readExecutable(name)
				if err != nil {
					return ServiceInspection{}, inspectionError{"unit_authority_untrusted"}
				}
				if protectedFullAdminPath(name) || protectedFullAdminPath(f.Resolved) {
					return ServiceInspection{}, inspectionError{"control_plane_protected"}
				}
				files = append(files, f)
			}
		}
		for _, name := range paths {
			if unsupportedUnitAuthorityPath(name) {
				return ServiceInspection{}, inspectionError{"generated_transient_or_user_authority"}
			}
			f, err := source.file(name)
			if err != nil {
				return ServiceInspection{}, inspectionError{"unit_authority_untrusted"}
			}
			if unsupportedUnitAuthorityPath(f.Resolved) {
				return ServiceInspection{}, inspectionError{"generated_transient_or_user_authority"}
			}
			files = append(files, f)
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		node := fullAdminNode{name, effects[name], p, files}
		nodes[name] = node
		add := func(key string, effect uint8) error {
			related, err := parseRelationshipsV2(p[key])
			if err != nil {
				return err
			}
			p[key] = strings.Join(related, " ")
			for _, u := range related {
				if protectedFullAdminUnit(u) {
					return inspectionError{"control_plane_protected"}
				}
				if effects[u]&effect != effect {
					effects[u] |= effect
					queue = append(queue, u)
				}
			}
			return nil
		}
		if effects[name]&effectStop != 0 {
			for _, key := range []string{"RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf", "PropagatesStopTo"} {
				propagation := effectStop
				if effects[name]&effectStart != 0 {
					propagation |= effectStart
				}
				if err := add(key, propagation); err != nil {
					return ServiceInspection{}, err
				}
			}
		}
		if effects[name]&effectStart != 0 && (name == unit || p["ActiveState"] != "active") {
			for _, key := range []string{"Requires", "Requisite", "Wants", "BindsTo"} {
				if err := add(key, effectStart); err != nil {
					return ServiceInspection{}, err
				}
			}
			for _, key := range []string{"Conflicts", "ConflictedBy"} {
				if err := add(key, effectStop); err != nil {
					return ServiceInspection{}, err
				}
			}
		}
	}
	// Final complete pass detects drift during inspection. This does not promise
	// an atomic lock against another root administrator; dispatch re-inspects too.
	ordered := make([]fullAdminNode, 0, len(nodes))
	affected := []string{}
	for name, node := range nodes {
		raw, err := source.run(ctx, systemctlArgs("show", name, fullAdminPropertiesForUnit(name)))
		if err != nil {
			return ServiceInspection{}, ErrRejected
		}
		p, err := parseProperties(raw, fullAdminPropertiesForUnit(name))
		if err != nil {
			return ServiceInspection{}, ErrRejected
		}
		for _, key := range execPropertiesV2 {
			v, _, err := normalizedExecV2(p[key])
			if err != nil {
				return ServiceInspection{}, err
			}
			p[key] = v
		}
		canonicalizeRelationshipsV2(p)
		before, _ := json.Marshal(node.Configuration)
		after, _ := json.Marshal(p)
		if string(before) != string(after) {
			return ServiceInspection{}, inspectionError{"configuration_changed"}
		}
		for _, f := range node.Files {
			read := source.file
			if f.Digest == "" && source.executable != nil {
				read = source.executable
			}
			fresh, err := read(f.Path)
			if err != nil || fresh != f {
				return ServiceInspection{}, ErrRejected
			}
		}
		ordered = append(ordered, node)
		if strings.HasSuffix(name, ".service") {
			affected = append(affected, name)
		}
	}
	fresh, err := source.file(systemctlPath)
	if err != nil || fresh != client || ctx.Err() != nil {
		return ServiceInspection{}, ErrRejected
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Unit < ordered[j].Unit })
	sort.Strings(affected)
	raw, _ := json.Marshal(struct {
		Domain, Unit string
		Client       fullAdminFile
		Nodes        []fullAdminNode
	}{"tracebolt.system-service-inspection.v2", unit, client, ordered})
	return ServiceInspection{unit, actionpermit.Digest(raw), affected, Observation(nodes[unit].Configuration["ActiveState"])}, nil
}

const MaxCapabilitiesBytesV2 = 128 << 10

type ServiceExclusion struct {
	Unit   string `json:"unit"`
	Reason string `json:"reason"`
}
type inspectionError struct{ code string }

func (e inspectionError) Error() string { return e.code }
func (e inspectionError) Unwrap() error { return ErrRejected }
func validExclusionReason(s string) bool {
	switch s {
	case "generated_transient_or_user_authority", "generated_or_transient_unit", "generated_transient_or_masked_unit", "loaded_configuration_stale", "alternate_execution_root", "unsupported_stop_policy", "unit_transitioning", "ambiguous_execution_path", "unsupported_or_ambiguous_relationship", "unsupported_configuration_or_graph", "unit_authority_untrusted", "canonical_unit_required", "unsupported_automatic_relationship", "graph_bound_exceeded", "configuration_changed", "control_plane_protected", "inspection_unavailable":
		return true
	}
	return false
}
func exclusionReason(err error) string {
	var e inspectionError
	if errors.As(err, &e) && validExclusionReason(e.code) {
		return e.code
	}
	return "unsupported_configuration_or_graph"
}
