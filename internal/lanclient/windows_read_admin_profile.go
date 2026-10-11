package lanclient

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsvolumes"
	"reflect"
)

// V5 is a new exact read-admin choice, never an interpretation of an old receipt.
// It grants local read scopes only; it does not change the service token or ACLs.
const WindowsCapabilityConsentVersionV5 = "tracebolt.windows-capability-consent.v5"

func WindowsReadAdminScopes() []string {
	return []string{enrollmentcrypto.CollectionProfileWindowsInventory, windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope, windowsnetwork.Scope, windowsmanaged.ServiceStartupScope, windowsfullservices.Scope, windowsfullsoftware.Scope, windowsadapters.Scope, windowspatchcontext.Scope, windowssecurity.Scope, windowssessions.Scope}
}

func validWindowsReadAdminConsent(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV5 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopes())
}

// Provider requirements are a source manifest, not a native preflight result.
// An administrator's ability to query a provider never proves LocalService access.
type WindowsReadAdminGroup struct {
	Name                 string   `json:"name"`
	Summary              string   `json:"summary"`
	Scopes               []string `json:"scopes"`
	Prerequisites        string   `json:"prerequisites"`
	ProviderAvailability string   `json:"providerAvailability"`
	ServiceTokenAccess   string   `json:"serviceTokenAccess"`
}

func WindowsReadAdminGroups() []WindowsReadAdminGroup {
	return []WindowsReadAdminGroup{
		{"Device and activity", "Bounded inventory, event headers, volumes, process CPU and memory.", []string{enrollmentcrypto.CollectionProfileWindowsInventory, windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope}, "Supported Windows amd64/arm64; local system, process, volume and Application/System Event Log APIs. Access-denied fields stay unknown.", "not_checked", "not_verified"},
		{"Services and software", "Complete caller-visible Win32 service and HKLM software generations; configured startup metadata for bounded service rows.", []string{windowsmanaged.ServiceStartupScope, windowsfullservices.Scope, windowsfullsoftware.Scope}, "Local SCM enumeration/configuration query rights and readable HKLM 32/64-bit uninstall registrations. Drivers, hidden services, per-user and Store/MSIX software are excluded.", "not_checked", "not_verified"},
		{"Network", "Numeric TCP/UDP endpoints plus adapter link, DNS-server and gateway configuration.", []string{windowsnetwork.Scope, windowsadapters.Scope}, "Local IP Helper APIs. No DNS resolution, probes, traffic capture or network changes.", "not_checked", "not_verified"},
		{"Updates and security", "Build, retained update history, reboot indicators, Defender status and local Firewall profile configuration.", []string{windowspatchcontext.Scope, windowssecurity.Scope}, "Fixed machine registry, local WUA COM, Defender WMI namespace and Firewall COM providers. Providers may be absent or denied; availability does not prove protection, compliance or effective policy. No online scan or installation.", "not_checked", "not_verified"},
		{"Users and sessions", "Caller-visible session IDs, personal user/domain labels, state and Console/RDP protocol; local domain/workgroup join name.", []string{windowssessions.Scope}, "Local WTS and NetGetJoinInformation APIs under the existing service token. No directory query, account enumeration, impersonation or session actions.", "not_checked", "not_verified"},
	}
}

func WindowsReadAdminNotices(insecure bool) []string {
	notices := []string{windowsmanaged.ServiceStartupPrivacy, windowsfullservices.Privacy, windowsfullsoftware.Privacy, windowsadapters.Privacy, windowspatchcontext.Privacy, windowssecurity.Privacy, windowssessions.Privacy}
	if insecure {
		notices = append(notices, windowsmanaged.ServiceStartupHTTPPrivacy, windowsfullservices.HTTPPrivacy, windowsfullsoftware.HTTPPrivacy, windowsadapters.HTTPPrivacy, windowspatchcontext.HTTPPrivacy, windowssecurity.HTTPPrivacy, windowssessions.HTTPPrivacy)
	}
	return notices
}
