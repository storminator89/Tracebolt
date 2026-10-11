package lanclient

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsvolumes"
	"reflect"
)

// V5 retains its historical exact twelve-scope contract, including serialized
// consent and receipt bindings. It never authorizes hardware serial metadata.
const WindowsCapabilityConsentVersionV5 = "tracebolt.windows-capability-consent.v5"

// WindowsReadAdminScopes is the historical V5 ordered scope set. Fresh Setup
// uses WindowsReadAdminScopesV12; this contract is never expanded in place.
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

// V6 is the fresh thirteen-scope profile. Hardware identifiers require a new
// acknowledgement; historical V5 consent and receipt bytes remain unchanged.
const WindowsCapabilityConsentVersionV6 = "tracebolt.windows-capability-consent.v6"

func WindowsReadAdminScopesV6() []string {
	return append(WindowsReadAdminScopes(), windowshardware.Scope)
}

func validWindowsReadAdminConsentV6(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV6 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV6())
}

func WindowsReadAdminGroupsV6() []WindowsReadAdminGroup {
	groups := WindowsReadAdminGroups()
	groups[0].Summary = "Bounded inventory, event headers, volumes, process CPU and memory; manufacturer/model, physical chassis serial (Win32_SystemEnclosure) and BIOS serial metadata, firmware vendor/version/date, and power/battery."
	groups[0].Scopes = append(groups[0].Scopes, windowshardware.Scope)
	groups[0].Prerequisites += " Fixed local hardware WMI classes and power status API under the existing service token. Identifying serial metadata is explicitly included; no provider installation, remote queries or configuration changes."
	return groups
}

func WindowsReadAdminNoticesV6(insecure bool) []string {
	notices := append(WindowsReadAdminNotices(insecure), windowshardware.Privacy)
	if insecure {
		notices = append(notices, windowshardware.HTTPPrivacy)
	}
	return notices
}

// V7 adds an independently consented storage scope. Historical V1-V6 bytes remain exact.
const WindowsCapabilityConsentVersionV7 = "tracebolt.windows-capability-consent.v7"

func WindowsReadAdminScopesV7() []string {
	return append(WindowsReadAdminScopesV6(), windowsstorage.Scope)
}
func validWindowsReadAdminConsentV7(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV7 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV7())
}
func WindowsReadAdminGroupsV7() []WindowsReadAdminGroup {
	groups := WindowsReadAdminGroupsV6()
	groups = append(groups, WindowsReadAdminGroup{"Storage", "Local drive letters and exact volume GUID mapping; storage-provider device identifiers/friendly labels, media, bus, size and provider health/status.", []string{windowsstorage.Scope}, "Local volume APIs and fixed MSFT_PhysicalDisk WMI under the same service token. No physical serial/unique IDs, SMART, remote shares or guessed physical joins; RAID, virtual and unsupported/denied visibility remains explicit.", "not_checked", "not_verified"})
	return groups
}
func WindowsReadAdminNoticesV7(insecure bool) []string {
	notices := append(WindowsReadAdminNoticesV6(insecure), windowsstorage.Privacy)
	if insecure {
		notices = append(notices, windowsstorage.HTTPPrivacy)
	}
	return notices
}

// V8 adds Security Center AV registration/status and public TPM presence/version.
// All earlier consent/profile bytes retain their exact authority.
const WindowsCapabilityConsentVersionV8 = "tracebolt.windows-capability-consent.v8"

func WindowsReadAdminScopesV8() []string {
	return append(WindowsReadAdminScopesV7(), windowssecuritycoverage.Scope)
}
func validWindowsReadAdminConsentV8(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV8 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV8())
}
func WindowsReadAdminGroupsV8() []WindowsReadAdminGroup {
	g := WindowsReadAdminGroupsV7()
	g[3].Summary += " Security Center registered antivirus product names/state/signature status on supported Windows clients; TPM supported-device presence/version."
	g[3].Scopes = append(g[3].Scopes, windowssecuritycoverage.Scope)
	g[3].Prerequisites += " Security Center COM is unsupported on Windows Server; TPM Base Services reports only public device presence/version. No TPM readiness or BitLocker protection is inferred. BitLocker status requires separately designed access and remains unavailable under this profile."
	return g
}
func WindowsReadAdminNoticesV8(insecure bool) []string {
	n := append(WindowsReadAdminNoticesV7(insecure), windowssecuritycoverage.Privacy)
	if insecure {
		n = append(n, windowssecuritycoverage.HTTPPrivacy)
	}
	return n
}

// V9 adds the complete Toolhelp process snapshot independently of bounded metrics.
// Earlier scope lists and consent bytes are never promoted.
const WindowsCapabilityConsentVersionV9 = "tracebolt.windows-capability-consent.v9"

func WindowsReadAdminScopesV9() []string {
	return append(WindowsReadAdminScopesV8(), windowsfullprocesses.Scope)
}
func validWindowsReadAdminConsentV9(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV9 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV9())
}
func WindowsReadAdminGroupsV9() []WindowsReadAdminGroup {
	g := WindowsReadAdminGroupsV8()
	g[0].Summary += " Complete caller-visible Toolhelp process inventory: PID, parent PID, executable name with availability and thread count."
	g[0].Scopes = append(g[0].Scopes, windowsfullprocesses.Scope)
	g[0].Prerequisites += " Fixed local Toolhelp process snapshot under the existing token. No process handles, owners, paths, command lines, filesystem reads, CPU or RAM are included in complete process inventory; separately consented bounded process metrics remain unchanged."
	return g
}
func WindowsReadAdminNoticesV9(insecure bool) []string {
	n := append(WindowsReadAdminNoticesV8(insecure), windowsfullprocesses.Privacy)
	if insecure {
		n = append(n, windowsfullprocesses.HTTPPrivacy)
	}
	return n
}

// V10 adds independent local route and interface raw counter generations.
// Historical profiles never authorize this scope or acquire its aliases/counters.
const WindowsCapabilityConsentVersionV10 = "tracebolt.windows-capability-consent.v10"

func WindowsReadAdminScopesV10() []string {
	return append(WindowsReadAdminScopesV9(), windowsnetworkcontext.Scope)
}
func validWindowsReadAdminConsentV10(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV10 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV10())
}
func WindowsReadAdminGroupsV10() []WindowsReadAdminGroup {
	g := WindowsReadAdminGroupsV9()
	g[2].Summary += " Local route prefixes, next-hop addresses, interface indices, metrics, protocol/origin; interface aliases and exact raw unsigned 64-bit octet, error and discard counters."
	g[2].Scopes = append(g[2].Scopes, windowsnetworkcontext.Scope)
	g[2].Prerequisites += " Fixed local IP Helper GetIpForwardTable2 and GetIfTable2Ex(MibIfTableRaw) under the existing service token. Independent capture labels are not joins; raw counters have no rate or since-boot meaning. No MACs, GUIDs, packets, DNS, probes, remote reads, grants or network changes."
	return g
}
func WindowsReadAdminNoticesV10(insecure bool) []string {
	n := append(WindowsReadAdminNoticesV9(insecure), windowsnetworkcontext.Privacy)
	if insecure {
		n = append(n, windowsnetworkcontext.HTTPPrivacy)
	}
	return n
}

// V11 adds source-labeled CPU and memory capacity context. Earlier profile,
// consent, grant and receipt bytes retain their exact authority.
const WindowsCapabilityConsentVersionV11 = "tracebolt.windows-capability-consent.v11"

func WindowsReadAdminScopesV11() []string {
	return append(WindowsReadAdminScopesV10(), windowsresourcecontext.Scope)
}
func validWindowsReadAdminConsentV11(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV11 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV11())
}
func WindowsReadAdminGroupsV11() []WindowsReadAdminGroup {
	g := WindowsReadAdminGroupsV10()
	g[0].Summary += " CPU model/architecture and source-labeled processor counts; installed SMBIOS RAM separately from OS-usable RAM; system commit current/limit and remaining capacity; aggregate pagefile allocated/in-use capacity."
	g[0].Scopes = append(g[0].Scopes, windowsresourcecontext.Scope)
	g[0].Prerequisites += " Fixed local Win32_Processor, GetPhysicallyInstalledSystemMemory, GetPerformanceInfo and aggregate EnumPageFilesW sources under the same service token. Pagefile names and paths are excluded. Remaining commit capacity is not paging I/O, thrashing or a health verdict; the existing CPU utilization sampler is unchanged. Firmware-reported installed RAM is not OS-usable RAM, and independent source counts are never silently equated."
	return g
}
func WindowsReadAdminNoticesV11(insecure bool) []string {
	n := append(WindowsReadAdminNoticesV10(insecure), windowsresourcecontext.Privacy)
	if insecure {
		n = append(n, windowsresourcecontext.HTTPPrivacy)
	}
	return n
}

// V12 adds aggregate local PerfDisk I/O under an independent grant. Historical
// scope sets, consent and receipt bytes remain exact.
const WindowsCapabilityConsentVersionV12 = "tracebolt.windows-capability-consent.v12"

func WindowsReadAdminScopesV12() []string {
	return append(WindowsReadAdminScopesV11(), windowsstorageio.Scope)
}
func validWindowsReadAdminConsentV12(c WindowsCapabilityConsent) bool {
	return c.SchemaVersion == WindowsCapabilityConsentVersionV12 && c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && c.Acknowledged && reflect.DeepEqual(c.Scopes, WindowsReadAdminScopesV12())
}
func WindowsReadAdminGroupsV12() []WindowsReadAdminGroup {
	g := WindowsReadAdminGroupsV11()
	g[5].Summary += " Aggregate local PerfDisk (_Total) read/write throughput, operations per second, latency and queue lengths, with the measured sample window."
	g[5].Scopes = append(g[5].Scopes, windowsstorageio.Scope)
	g[5].Prerequisites += " Eight fixed local PDH PhysicalDisk(_Total) counters sampled twice under the existing token. Counter validity and unavailable sources remain explicit; idle latency is unavailable. No per-disk completeness, joins to drives/volumes/provider disks, SMART, paging-I/O attribution, health verdict, remote reads or configuration changes."
	return g
}
func WindowsReadAdminNoticesV12(insecure bool) []string {
	n := append(WindowsReadAdminNoticesV11(insecure), windowsstorageio.Privacy)
	if insecure {
		n = append(n, windowsstorageio.HTTPPrivacy)
	}
	return n
}
