package windowsbasic_test

import (
	"localrmm/internal/actionwire"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/inventorywire"
	"localrmm/internal/journalwire"
	"localrmm/internal/lanstore"
	"localrmm/internal/overviewwire"
	"localrmm/internal/rustcompat"
	"localrmm/internal/systemwire"
	"localrmm/internal/windowsactionwire"
	"localrmm/internal/windowsbasic"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowsfullprocesseswire"
	"localrmm/internal/windowsfullserviceswire"
	"localrmm/internal/windowsfullsoftwarewire"
	"localrmm/internal/windowshistorywire"
	"localrmm/internal/windowsnetworkcontextwire"
	"localrmm/internal/windowsusersoftwarewire"
	"testing"
	"time"
)

func TestOnlyExactBasicProfileAndRoutePassTheInertPolicy(t *testing.T) {
	if !windowsbasic.ProfileAllowsRoute(windowsbasic.CollectionProfile, "windows", "tls", "POST", windowsbasic.TelemetryPath) {
		t.Fatal("exact proposed contract denied")
	}
	for _, profile := range []string{
		"", "unknown", enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileWindowsInventory,
		enrollmentcrypto.CollectionProfileMacOSInventory, enrollmentcrypto.CollectionProfileOperational,
		enrollmentcrypto.CollectionProfilePackages, enrollmentcrypto.CollectionProfileComplete,
		"rust-windows-basic-v1", "windows-basic-metrics-v2", "Windows-basic-metrics-v1", windowsbasic.CollectionProfile + " ",
	} {
		if windowsbasic.ProfileAllowsRoute(profile, "windows", "tls", "POST", windowsbasic.TelemetryPath) {
			t.Fatal("existing/claimed profile promoted to Basic", profile)
		}
	}
	for _, platform := range []string{"", "linux", "darwin", "macos", "unknown", "Windows", "windows "} {
		if windowsbasic.ProfileAllowsRoute(windowsbasic.CollectionProfile, platform, "tls", "POST", windowsbasic.TelemetryPath) {
			t.Fatal("other platform admitted", platform)
		}
	}
	for _, transport := range []string{"", "http", "http-test", "TLS", "tls "} {
		if windowsbasic.ProfileAllowsRoute(windowsbasic.CollectionProfile, "windows", transport, "POST", windowsbasic.TelemetryPath) {
			t.Fatal("non-TLS transport admitted", transport)
		}
	}
	for _, method := range []string{"", "GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE", "post", "POST "} {
		if windowsbasic.ProfileAllowsRoute(windowsbasic.CollectionProfile, "windows", "tls", method, windowsbasic.TelemetryPath) {
			t.Fatal("other method admitted", method)
		}
	}
}

// These are profile-policy tests, not HTTP/credential-authorization evidence.
// Include actual route constants where exported; the executor prefixes below
// are currently private to enrollmenttransport and must remain explicitly denied.
func TestAllCurrentExpandedAgentRouteFamiliesAreDenied(t *testing.T) {
	paths := []string{
		"/v1/agent/telemetry", "/v1/windows/agent/telemetry", "/v1/macos/telemetry",
		windowsactionwire.CapabilitiesPath, windowsactionwire.PeekPath, windowsactionwire.ClaimPath, windowsactionwire.ResultPath,
		windowseventwire.CapabilityPath, windowseventwire.PeekPath, windowseventwire.ClaimPath, windowseventwire.ResultPath, windowseventwire.StatusPath,
		windowshistorywire.CapabilityPath, windowshistorywire.PeekPath, windowshistorywire.ClaimPath, windowshistorywire.ResultPath, windowshistorywire.StatusPath,
		actionwire.CapabilitiesPath, actionwire.CapabilitiesPathV2, actionwire.PeekPath, actionwire.ClaimPath, actionwire.ResultPath,
		journalwire.PeekPath, journalwire.ClaimPath, journalwire.ResultPath, journalwire.StatusPath, journalwire.GenerationPath,
		systemwire.Path,
	}
	for _, prefix := range []string{windowsfullserviceswire.PathPrefix, windowsfullsoftwarewire.PathPrefix, windowsusersoftwarewire.PathPrefix, windowsfullprocesseswire.PathPrefix, windowsnetworkcontextwire.PathPrefix} {
		for _, operation := range []string{"scope", "chunk", "failure"} {
			paths = append(paths, prefix+operation)
		}
	}
	for _, operation := range []string{"poll", "readiness-claim", "install-claim", "download-claim", "retire-claim", "report"} {
		paths = append(paths, "/v1/windows-update-jobs/"+operation)
	}
	for _, operation := range []string{"poll", "readiness-claim", "install-claim", "report"} {
		paths = append(paths, "/v1/windows-software-jobs/"+operation)
	}
	for _, operation := range []string{"poll", "chunk", "report"} {
		paths = append(paths, "/v1/windows-managed-msi/"+operation)
	}
	for _, prefix := range []string{inventorywire.PathPrefix, inventorywire.CachedUpdatesPathPrefix, overviewwire.PathPrefix} {
		for _, operation := range []string{"begin", "chunk", "finalize", "failure"} {
			paths = append(paths, prefix+operation)
		}
	}
	// Future/unknown endpoints, path aliases and prefix matching are never grants.
	paths = append(paths, "", "/", windowsbasic.TelemetryPath+"/", windowsbasic.TelemetryPath+"/actions", windowsbasic.TelemetryPath+"?scope=inventory", windowsbasic.TelemetryPath+"#actions", "/v1/windows/basic/../agent/telemetry", "/v1/windows/basic/%74elemetry", "/v1/windows/basic/unknown", "/v99/windows/agent/full-inventory")
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			for _, method := range []string{"POST", "GET", "DELETE"} {
				if windowsbasic.ProfileAllowsRoute(windowsbasic.CollectionProfile, "windows", "tls", method, path) {
					t.Fatal("Basic policy admitted expanded or unknown route", method, path)
				}
			}
		})
	}
}

func TestFoundationCannotBeAdvertisedOrEnrolledAsRuntimeSupport(t *testing.T) {
	if enrollmentcrypto.ValidCollectionProfile(windowsbasic.CollectionProfile) || enrollmentcrypto.ValidPlatformCollectionProfile("windows", "tls", windowsbasic.CollectionProfile) {
		t.Fatal("inert foundation accidentally became an enrollable domain before runtime integration")
	}
	capability := rustcompat.Expected("https://manager.test", "https://agent.test", true)
	if capability.CollectionProfile == windowsbasic.CollectionProfile || capability.TelemetryFrame == windowsbasic.FrameVersion {
		t.Fatal("inert contract was falsely advertised as runtime support")
	}
	raw := []byte(`{"schemaVersion":"tracebolt.agent-telemetry.windows-basic.v1","sequence":1,"collectedAt":"2026-10-31T12:00:00Z","cpuPercent":12.5,"physicalMemoryPercent":50,"systemVolumeUsedPercent":75,"uptimeSeconds":3600}`)
	if _, err := lanstore.ValidateFrame(raw, time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("existing broad runtime parser adopted the new contract")
	}
}
