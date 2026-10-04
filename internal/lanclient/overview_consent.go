package lanclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"localrmm/internal/completeoverview"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/overviewstate"
	"os"
	"path/filepath"
)

const (
	overviewConsentName     = "complete-overview-consent.json"
	overviewInitName        = ".complete-overview-initialization"
	overviewConsentVersion  = "tracebolt.complete-overview-consent.v1"
	maxOverviewConsentBytes = 4096
	overviewConsentScope    = "full-agent-visible-processes-and-mounted-filesystems"
	overviewDisclosure      = "Full visible processes and mounted filesystems in the agent's Linux namespaces, including potentially sensitive process names, mount paths and filesystem labels; fixed 60-second capture cadence. Missing row fields remain explicit. No command lines, environment values, file contents or additional OS privileges. HTTP-test content is unencrypted and the manager is unauthenticated."
)

type overviewConsent struct {
	SchemaVersion          string `json:"schemaVersion"`
	ExtensionVersion       string `json:"extensionVersion"`
	Scope                  string `json:"scope"`
	SenderBinding          string `json:"senderBinding"`
	AgentID                string `json:"agentId"`
	CertificateHash        string `json:"certificateHash"`
	ManagerOrigin          string `json:"managerOrigin"`
	TransportProfile       string `json:"transportProfile"`
	CaptureIntervalSeconds uint32 `json:"captureIntervalSeconds"`
	Acknowledged           bool   `json:"acknowledged"`
}

func overviewConsentFor(m Material) overviewConsent {
	return overviewConsent{overviewConsentVersion, completeoverview.SchemaVersion, overviewConsentScope, m.binding, m.config.AgentID, journalLeaf(m), m.config.ManagerOrigin, m.config.Profile, 60, true}
}
func overviewStateDirectory(c Config, section string) string {
	// The only callers use the two fixed recognized sections; never user paths.
	if section != "processes" && section != "volumes" {
		return ""
	}
	return filepath.Join(c.StateDirectory, "overview-"+section)
}
func readOverviewConsent(m Material) bool {
	if !m.valid() || !m.config.complete() || overviewInitializationState(m) != nil {
		return false
	}
	raw, e := lanconfig.ReadProtected(filepath.Join(m.config.StateDirectory, overviewConsentName), true, maxOverviewConsentBytes)
	if e != nil {
		return false
	}
	expected, _ := json.Marshal(overviewConsentFor(m))
	return bytes.Equal(raw, expected)
}

// OverviewConsentResult contains scope and consent status only, never collected
// rows, credentials or private sender-state contents.
type OverviewConsentResult struct {
	SchemaVersion          string `json:"schemaVersion"`
	Mode                   string `json:"mode"`
	ExtensionVersion       string `json:"extensionVersion"`
	Scope                  string `json:"scope"`
	Disclosure             string `json:"disclosure"`
	CaptureIntervalSeconds uint32 `json:"captureIntervalSeconds"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureCompleteOverview is a local, stopped-service action bound to the
// existing v3 identity. It neither collects nor performs network or OS grants.
// Only a fully absent pair can be initialized; partial/corrupt domains and
// initialization temporaries are retained and fail closed. Re-enable validates
// both existing domains rather than resetting their independent floors.
func ConfigureCompleteOverview(path, mode string, acknowledged bool) (OverviewConsentResult, error) {
	return configureCompleteOverview(path, mode, acknowledged, journalAgentIdentity)
}
func configureCompleteOverview(path, mode string, acknowledged bool, identity func() (uint32, uint32, bool)) (OverviewConsentResult, error) {
	var zero OverviewConsentResult
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") || identity == nil {
		return zero, ErrConfiguration
	}
	if _, _, ok := identity(); !ok {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.complete() {
		return zero, ErrConfiguration
	}
	lease, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer lease.Close()
	if mode == "enable" {
		if overviewInitializationState(m) != nil {
			return zero, ErrState
		}
		expected, _ := json.Marshal(overviewConsentFor(m))
		consentPath := filepath.Join(m.config.StateDirectory, overviewConsentName)
		consentExisted := false
		if _, e := os.Lstat(consentPath); e == nil {
			consentExisted = true
			if !readOverviewConsent(m) {
				return zero, ErrState
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return zero, ErrState
		}
		absent := 0
		for _, section := range []string{"processes", "volumes"} {
			if _, e := os.Lstat(overviewStateDirectory(m.config, section)); errors.Is(e, os.ErrNotExist) {
				absent++
			} else if e != nil {
				return zero, ErrState
			}
		}
		if absent == 1 || consentExisted && absent != 0 {
			return zero, ErrState
		}
		if absent == 2 {
			if e = beginOverviewInitialization(m); e != nil {
				return zero, e
			}
			for _, section := range []string{"processes", "volumes"} {
				state, e := overviewstate.InitializeNew(overviewStateDirectory(m.config, section), m.binding, m.config.AgentID, section)
				if e != nil {
					return zero, ErrState
				}
				if state.Close() != nil {
					return zero, ErrState
				}
			}
			// Publish consent only after both fresh domains are durably initialized.
			if e = writeOverviewConsent(m, expected); e != nil {
				return zero, e
			}
			if e = finishOverviewInitialization(m); e != nil {
				return zero, e
			}
		} else {
			for _, section := range []string{"processes", "volumes"} {
				if overviewstate.ValidateExisting(overviewStateDirectory(m.config, section), m.binding, m.config.AgentID, section) != nil {
					return zero, ErrState
				}
			}
			if e = writeOverviewConsent(m, expected); e != nil {
				return zero, e
			}
		}
	} else if mode == "disable" {
		// Disable remains possible even if extension initialization is incomplete.
		// Stored bytes/floors stay dormant and cannot be sent without fresh consent.
		if e = removeOverviewConsent(m); e != nil {
			return zero, e
		}
	}
	enabled := readOverviewConsent(m)
	if mode == "enable" && !enabled || mode == "disable" && enabled {
		return zero, ErrState
	}
	if lease.Close() != nil {
		return zero, ErrState
	}
	return OverviewConsentResult{"tracebolt.complete-overview-consent-result.v1", mode, completeoverview.SchemaVersion, overviewConsentScope, overviewDisclosure, 60, enabled, true}, nil
}
