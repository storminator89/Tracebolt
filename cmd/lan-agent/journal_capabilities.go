package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"localrmm/internal/journalactivation"
	"localrmm/internal/journalpolicy"
)

// This reserved mode is dispatched before all flags and runtime paths. It
// describes this binary only: no identity/configuration, state, journal helper,
// network or running-service inspection is performed.
func journalCapabilitiesInvocation(args []string) (selected, exclusive bool) {
	for _, arg := range args {
		if arg == "--journal-capabilities" || arg == "-journal-capabilities" || strings.HasPrefix(arg, "--journal-capabilities=") || strings.HasPrefix(arg, "-journal-capabilities=") {
			return true, len(args) == 1 && arg == "--journal-capabilities"
		}
	}
	return false, false
}

type journalRuntimeCapabilities struct {
	SchemaVersion            string                               `json:"schemaVersion"`
	PolicyVersions           []string                             `json:"policyVersions"`
	GenerationReportVersions []string                             `json:"generationReportVersions"`
	RequestVersions          []string                             `json:"requestVersions"`
	HelperProtocols          []string                             `json:"helperProtocols"`
	ActivationVersions       []string                             `json:"activationVersions"`
	ServiceAuthorization     []journalpolicy.ServiceAuthorization `json:"serviceAuthorization"`
	Scopes                   []string                             `json:"scopes"`
}

func runJournalCapabilities(exclusive bool, stdout, stderr io.Writer) int {
	if !exclusive {
		fmt.Fprintln(stderr, "Tracebolt journal capabilities requires the exclusive --journal-capabilities mode.")
		return 2
	}
	capabilities := journalRuntimeCapabilities{
		SchemaVersion:            "tracebolt.journal-runtime-capabilities.v1",
		PolicyVersions:           []string{journalpolicy.Version, journalpolicy.VersionV2, journalpolicy.VersionV3, journalpolicy.VersionV4},
		GenerationReportVersions: []string{"tracebolt.journal-generation-report.v1", "tracebolt.journal-generation-report.v2", "tracebolt.journal-generation-report.v3"},
		RequestVersions:          []string{"tracebolt.journal-request.v1", "tracebolt.journal-request.v2", "tracebolt.journal-request.v3"},
		HelperProtocols:          []string{"TBJ1", "TBJ2", "TBJ3"},
		ActivationVersions:       []string{journalactivation.Version},
		ServiceAuthorization:     []journalpolicy.ServiceAuthorization{journalpolicy.ExactUnits, journalpolicy.AllSystemServices},
		Scopes:                   []string{journalpolicy.Scope, journalpolicy.ScopeV3, journalpolicy.ScopeV4},
	}
	if json.NewEncoder(stdout).Encode(capabilities) != nil {
		fmt.Fprintln(stderr, "Tracebolt journal capabilities could not be written.")
		return 2
	}
	return 0
}
