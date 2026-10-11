package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/packagecollector"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowshardwareworker"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowspatchworker"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowsresourceworker"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssecuritycoverageworker"
	"localrmm/internal/windowssecurityworker"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowssessionworker"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsstorageioworker"
	"localrmm/internal/windowsstorageworker"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsupdateworker"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"os"
	"runtime"
	"time"
)

type frame struct {
	WindowsStorageIO        *windowsstorageio.Snapshot             `json:"windowsStorageIO,omitempty"`
	WindowsResourceContext  *windowsresourcecontext.Snapshot       `json:"windowsResourceContext,omitempty"`
	WindowsHardwareContext  *windowshardware.Snapshot              `json:"windowsHardwareContext,omitempty"`
	WindowsStorageContext   *windowsstorage.Snapshot               `json:"windowsStorageContext,omitempty"`
	WindowsSecurityCoverage *windowssecuritycoverage.Snapshot      `json:"windowsSecurityCoverage,omitempty"`
	WindowsSessionContext   *windowssessions.Snapshot              `json:"windowsSessionContext,omitempty"`
	WindowsSecurityPosture  *windowssecurity.Snapshot              `json:"windowsSecurityPosture,omitempty"`
	SchemaVersion           string                                 `json:"schemaVersion"`
	Sequence                uint64                                 `json:"sequence"`
	Observation             bundle.Bundle                          `json:"observation"`
	Operational             *operational.Snapshot                  `json:"operational,omitempty"`
	Packages                *linuxpackages.Snapshot                `json:"packages,omitempty"`
	WindowsInventory        *windowsmanaged.Snapshot               `json:"windowsInventory,omitempty"`
	WindowsEvents           *windowseventhealth.Snapshot           `json:"windowsEvents,omitempty"`
	WindowsVolumes          *windowsvolumes.Snapshot               `json:"windowsVolumes,omitempty"`
	WindowsProcessMetrics   *windowsprocessmetrics.Snapshot        `json:"windowsProcessMetrics,omitempty"`
	WindowsNetwork          *windowsnetwork.Snapshot               `json:"windowsNetwork,omitempty"`
	WindowsServiceStartup   *windowsmanaged.ServiceStartupSnapshot `json:"windowsServiceStartup,omitempty"`
	WindowsUpdates          *windowsupdates.Snapshot               `json:"windowsUpdates,omitempty"`
	WindowsPatchContext     *windowspatchcontext.Snapshot          `json:"windowsPatchContext,omitempty"`
	WindowsAdapterContext   *windowsadapters.Snapshot              `json:"windowsAdapterContext,omitempty"`
}
type receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	AgentID       string    `json:"agentId"`
	Sequence      uint64    `json:"sequence"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	Duplicate     bool      `json:"duplicate"`
}
type Report struct {
	WindowsFullProcessesStatus      string `json:"windowsFullProcessesStatus,omitempty"`
	WindowsFullProcessesSequence    uint64 `json:"windowsFullProcessesSequence,omitempty"`
	WindowsFullProcessesOperations  uint8  `json:"windowsFullProcessesOperations,omitempty"`
	WindowsNetworkContextStatus     string `json:"windowsNetworkContextStatus,omitempty"`
	WindowsNetworkContextSequence   uint64 `json:"windowsNetworkContextSequence,omitempty"`
	WindowsNetworkContextOperations uint8  `json:"windowsNetworkContextOperations,omitempty"`

	WindowsFullServicesStatus     string `json:"windowsFullServicesStatus,omitempty"`
	WindowsFullServicesSequence   uint64 `json:"windowsFullServicesSequence,omitempty"`
	WindowsFullServicesOperations uint8  `json:"windowsFullServicesOperations,omitempty"`
	WindowsFullSoftwareStatus     string `json:"windowsFullSoftwareStatus,omitempty"`
	WindowsFullSoftwareSequence   uint64 `json:"windowsFullSoftwareSequence,omitempty"`
	WindowsFullSoftwareOperations uint8  `json:"windowsFullSoftwareOperations,omitempty"`
	WindowsEventContentStatus     string `json:"windowsEventContentStatus,omitempty"`
	CachedUpdatesStatus           string `json:"cachedUpdatesStatus,omitempty"`
	CachedUpdatesSequence         uint64 `json:"cachedUpdatesSequence,omitempty"`
	CachedUpdatesOperations       uint8  `json:"cachedUpdatesOperations,omitempty"`
	ProcessesStatus               string `json:"processesStatus,omitempty"`
	ProcessesSequence             uint64 `json:"processesSequence,omitempty"`
	VolumesStatus                 string `json:"volumesStatus,omitempty"`
	VolumesSequence               uint64 `json:"volumesSequence,omitempty"`
	OverviewOperations            uint8  `json:"overviewOperations,omitempty"`
	JournalStatus                 string `json:"journalStatus,omitempty"`
	SchemaVersion                 string `json:"schemaVersion"`
	Status                        string `json:"status"`
	Profile                       string `json:"profile"`
	Sequence                      uint64 `json:"sequence,omitempty"`
	Duplicate                     bool   `json:"duplicate"`
	RetriedPending                bool   `json:"retriedPending"`
	DiscardedUnconsented          bool   `json:"discardedUnconsented,omitempty"`
	DiscardedStale                bool   `json:"discardedStale"`
	AvailablePercentageFields     int    `json:"availablePercentageFields"`
	UnavailablePercentageFields   int    `json:"unavailablePercentageFields"`
	InventoryStatus               string `json:"inventoryStatus,omitempty"`
	InventorySequence             uint64 `json:"inventorySequence,omitempty"`
	InventoryOperations           uint8  `json:"inventoryOperations,omitempty"`
	SystemStatus                  string `json:"systemStatus,omitempty"`
	SystemSequence                uint64 `json:"systemSequence,omitempty"`
	SystemRetriedPending          bool   `json:"systemRetriedPending,omitempty"`
	SystemDiscardedStale          bool   `json:"systemDiscardedStale,omitempty"`
}

// Run preserves the legacy one-shot collection/delivery behavior. The explicitly
// complete profile adds serialized system/package work with separate cooperative
// stage budgets. Separate full-update consent adds a 20s/64-operation burst;
// explicit overview consent adds one shared 20s/64-operation
// process-and-volume burst before the existing journal stage. The caller's own
// deadline still bounds the one-shot call; these stage budgets are not a hard
// overall cycle deadline. Pending bytes and original source times survive retry.
// This path never switches origin, enrolls or installs.
func Run(ctx context.Context, m Material) (Report, error) {
	report := Report{SchemaVersion: "tracebolt.agent-run.v1", Status: "failed", Profile: m.config.Profile}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !m.valid() || !m.config.platformAllowed(runtime.GOOS) {
		return report, ErrConfiguration
	}
	report.Profile = m.config.Profile
	state, e := openSenderState(m)
	if e != nil {
		return report, ErrState
	}
	defer state.Close()
	var inventory *inventorySender
	var system *systemSender
	if m.config.complete() {
		inventory, e = openInventorySender(m)
		if e != nil {
			return report, e
		}
		defer inventory.Close()
		system, e = openSystemSender(m)
		if e != nil {
			return report, e
		}
		defer system.Close()
	}
	if inventory == nil {
		// Preserve the preexisting one-shot caller-context contract. Legacy
		// foreground attempts retain their original20s budget separately.
		events := openWindowsEventContentSender(m)
		defer events.Close()
		fullServices, fullErr := openWindowsFullServicesSender(m, state)
		if fullErr != nil {
			return report, fullErr
		}
		defer fullServices.Close()
		fullSoftware, fullErr := openWindowsFullSoftwareSender(m, state)
		if fullErr != nil {
			return report, fullErr
		}
		defer fullSoftware.Close()
		fullProcesses, fullErr := openWindowsFullProcessesSender(m, state)
		if fullErr != nil {
			return report, fullErr
		}
		defer fullProcesses.Close()
		networkContext, fullErr := openWindowsNetworkContextSender(m, state)
		if fullErr != nil {
			return report, fullErr
		}
		defer networkContext.Close()
		report, err := runUsingState(ctx, m, state)
		if ctx.Err() == nil {
			report.WindowsEventContentStatus = runWindowsEventContentAttempt(ctx, events)
			if e := runWindowsFullServicesAttempt(ctx, fullServices, &report); e != nil {
				return report, e
			}
			if e := runWindowsFullSoftwareAttempt(ctx, fullSoftware, &report); e != nil {
				return report, e
			}
			if e := runWindowsFullProcessesAttempt(ctx, fullProcesses, &report); e != nil {
				return report, e
			}
			if e := runWindowsNetworkContextAttempt(ctx, networkContext, &report); e != nil {
				return report, e
			}
		}
		return report, err
	}
	updates, e := openCompleteUpdatesSender(m)
	if e != nil {
		return report, e
	}
	defer updates.Close()
	overview, e := openOverviewSender(m)
	if e != nil {
		return report, e
	}
	defer overview.Close()
	journal := openJournalSender(m)
	defer journal.Close()
	report, err := runPreparedAttemptWithSystem(ctx, m, state, system, inventory, runUsingState)
	if err == nil {
		err = runCompleteUpdatesAttempt(ctx, updates, &report)
	}
	if err == nil {
		err = runOverviewAndJournal(ctx, overview, &report, func(parent context.Context) string { return runJournalAttempt(parent, journal) })
	}
	return report, err
}

// Complete-profile work is serialized: a bounded metric attempt followed by a
// bounded inventory burst. The caller retains both locks across this function.
// Normal chunk-budget exhaustion is pending progress, not exponential backoff.
func runPreparedAttempt(ctx context.Context, m Material, state *lanclientstate.State, inventory *inventorySender, metrics func(context.Context, Material, *lanclientstate.State) (Report, error)) (Report, error) {
	return runPreparedAttemptWithSystem(ctx, m, state, nil, inventory, metrics)
}
func runPreparedAttemptWithSystem(ctx context.Context, m Material, state *lanclientstate.State, system *systemSender, inventory *inventorySender, metrics func(context.Context, Material, *lanclientstate.State) (Report, error)) (Report, error) {
	metricCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	report, err := metrics(metricCtx, m, state)
	cancel()
	if err != nil {
		return report, err
	}
	if system != nil {
		systemCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		status, e := system.Run(systemCtx)
		cancel()
		report.SystemStatus, report.SystemSequence = status.Status, status.Sequence
		report.SystemRetriedPending, report.SystemDiscardedStale = status.RetriedPending, status.DiscardedStale
		if e != nil {
			return report, e
		}
	}
	if inventory == nil {
		return report, nil
	}
	burstCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	status, inventoryErr := inventory.Burst(burstCtx)
	cancel()
	report.InventoryStatus = status.Status
	report.InventorySequence = status.Sequence
	report.InventoryOperations = uint8(status.Operations)
	if errors.Is(inventoryErr, ErrInventoryPending) {
		inventoryErr = nil
	}
	return report, inventoryErr
}

// runUsingState preserves one exclusive ledger lock across foreground attempts.
func runUsingState(ctx context.Context, m Material, state *lanclientstate.State) (Report, error) {
	return runUsingStateWithCollectors(ctx, m, state, operational.Collect, packagecollector.Collect)
}

// The collector is a per-attempt dependency, never an asynchronous background job.
func runUsingStateWithCollector(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot) (Report, error) {
	return runUsingStateWithCollectors(ctx, m, state, collectOperations, packagecollector.Collect)
}

func runUsingStateWithCollectors(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (Report, error) {
	return runUsingStateWithSources(ctx, m, state, collectOperations, collectPackages, collector.Snapshot)
}

// All dependencies are private per-attempt values. Tests can exercise staging
// and transport without reading any production observation source.
func runUsingStateWithSources(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device) (Report, error) {
	return runUsingStateWithCurrentDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindowsForProcessMetrics, nil)
}

// Dependencies are per-attempt and private: fixture transports never open listeners.
func runUsingStateWithCurrentDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error)) (Report, error) {
	return runUsingStateWithStorageIOAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, func() (windowseventhealth.Consent, bool) { return readWindowsEventConsent(m) }, windowseventhealth.Collect, func() (windowsvolumes.Consent, bool) { return readWindowsVolumeConsent(m) }, windowsvolumes.Collect, func() (windowsprocessmetrics.Consent, bool) { return readWindowsProcessMetricsConsent(m) }, nativeProcessMetricCollector(m.processSampler), func() (windowsnetwork.Consent, bool) { return readWindowsNetworkConsent(m) }, windowsnetwork.Collect, func() (windowsmanaged.ServiceStartupConsent, bool) { return readWindowsServiceStartupConsent(m) }, windowsmanaged.CollectServiceStartup, func() (windowsupdates.Consent, bool) { return readWindowsUpdatesConsent(m) }, windowsupdateworker.Collect, func() (windowsadapters.Consent, bool) { return readWindowsAdapterContextConsent(m) }, windowsadapters.Collect, func() (windowspatchcontext.Consent, bool) { return readWindowsPatchContextConsent(m) }, windowspatchworker.Collect, func() (windowssecurity.Consent, bool) { return readWindowsSecurityPostureConsent(m) }, windowssecurityworker.Collect, func() (windowssessions.Consent, bool) { return readWindowsSessionContextConsent(m) }, windowssessionworker.Collect, func() (windowshardware.Consent, bool) { return readWindowsHardwareContextConsent(m) }, windowshardwareworker.Collect, func() (windowsstorage.Consent, bool) { return readWindowsStorageContextConsent(m) }, windowsstorageworker.Collect, func() (windowssecuritycoverage.Consent, bool) { return readWindowsSecurityCoverageConsent(m) }, windowssecuritycoverageworker.Collect, func() (windowsresourcecontext.Consent, bool) { return readWindowsResourceContextConsent(m) }, windowsresourceworker.Collect, func() (windowsstorageio.Consent, bool) { return readWindowsStorageIOConsent(m) }, windowsstorageioworker.Collect, func() bool { return currentWindowsContextMaterial(m, Load) })
}

func runUsingStateWithSessionContextAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, currentMaterial func() bool) (Report, error) {
	return runUsingStateWithHardwareContextAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, readConsent, collectEvents, readVolumes, collectVolumes, readProcessMetrics, collectProcessMetrics, readNetwork, collectNetwork, readServiceStartup, collectServiceStartup, readUpdates, collectUpdates, readAdapterContext, collectAdapterContext, readPatchContext, collectPatchContext, readSecurityPosture, collectSecurityPosture, readSessionContext, collectSessionContext, nil, nil, currentMaterial)
}

func runUsingStateWithHardwareContextAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, readHardwareContext func() (windowshardware.Consent, bool), collectHardwareContext hardwareContextCollector, currentMaterial func() bool) (Report, error) {
	return runUsingStateWithStorageContextAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, readConsent, collectEvents, readVolumes, collectVolumes, readProcessMetrics, collectProcessMetrics, readNetwork, collectNetwork, readServiceStartup, collectServiceStartup, readUpdates, collectUpdates, readAdapterContext, collectAdapterContext, readPatchContext, collectPatchContext, readSecurityPosture, collectSecurityPosture, readSessionContext, collectSessionContext, readHardwareContext, collectHardwareContext, nil, nil, currentMaterial)
}

func runUsingStateWithStorageContextAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, readHardwareContext func() (windowshardware.Consent, bool), collectHardwareContext hardwareContextCollector, readStorageContext func() (windowsstorage.Consent, bool), collectStorageContext storageContextCollector, currentMaterial func() bool) (Report, error) {
	return runUsingStateWithSecurityCoverageAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, readConsent, collectEvents, readVolumes, collectVolumes, readProcessMetrics, collectProcessMetrics, readNetwork, collectNetwork, readServiceStartup, collectServiceStartup, readUpdates, collectUpdates, readAdapterContext, collectAdapterContext, readPatchContext, collectPatchContext, readSecurityPosture, collectSecurityPosture, readSessionContext, collectSessionContext, readHardwareContext, collectHardwareContext, readStorageContext, collectStorageContext, nil, nil, currentMaterial)
}

func runUsingStateWithSecurityCoverageAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, readHardwareContext func() (windowshardware.Consent, bool), collectHardwareContext hardwareContextCollector, readStorageContext func() (windowsstorage.Consent, bool), collectStorageContext storageContextCollector, readSecurityCoverage func() (windowssecuritycoverage.Consent, bool), collectSecurityCoverage securityCoverageCollector, currentMaterial func() bool) (Report, error) {
	return runUsingStateWithResourceContextAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, readConsent, collectEvents, readVolumes, collectVolumes, readProcessMetrics, collectProcessMetrics, readNetwork, collectNetwork, readServiceStartup, collectServiceStartup, readUpdates, collectUpdates, readAdapterContext, collectAdapterContext, readPatchContext, collectPatchContext, readSecurityPosture, collectSecurityPosture, readSessionContext, collectSessionContext, readHardwareContext, collectHardwareContext, readStorageContext, collectStorageContext, readSecurityCoverage, collectSecurityCoverage, nil, nil, currentMaterial)
}

func runUsingStateWithResourceContextAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, readHardwareContext func() (windowshardware.Consent, bool), collectHardwareContext hardwareContextCollector, readStorageContext func() (windowsstorage.Consent, bool), collectStorageContext storageContextCollector, readSecurityCoverage func() (windowssecuritycoverage.Consent, bool), collectSecurityCoverage securityCoverageCollector, readResourceContext func() (windowsresourcecontext.Consent, bool), collectResourceContext resourceContextCollector, currentMaterial func() bool) (Report, error) {
	return runUsingStateWithStorageIOAuthorityDependencies(ctx, m, state, collectOperations, collectPackages, collectBasic, collectWindows, send, readConsent, collectEvents, readVolumes, collectVolumes, readProcessMetrics, collectProcessMetrics, readNetwork, collectNetwork, readServiceStartup, collectServiceStartup, readUpdates, collectUpdates, readAdapterContext, collectAdapterContext, readPatchContext, collectPatchContext, readSecurityPosture, collectSecurityPosture, readSessionContext, collectSessionContext, readHardwareContext, collectHardwareContext, readStorageContext, collectStorageContext, readSecurityCoverage, collectSecurityCoverage, readResourceContext, collectResourceContext, nil, nil, currentMaterial)
}

func runUsingStateWithStorageIOAuthorityDependencies(ctx context.Context, m Material, state *lanclientstate.State, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector, send func(*http.Request) (*http.Response, error), readConsent func() (windowseventhealth.Consent, bool), collectEvents eventCollector, readVolumes func() (windowsvolumes.Consent, bool), collectVolumes volumeCollector, readProcessMetrics func() (windowsprocessmetrics.Consent, bool), collectProcessMetrics processMetricCollector, readNetwork func() (windowsnetwork.Consent, bool), collectNetwork networkCollector, readServiceStartup func() (windowsmanaged.ServiceStartupConsent, bool), collectServiceStartup serviceStartupCollector, readUpdates func() (windowsupdates.Consent, bool), collectUpdates updatesCollector, readAdapterContext func() (windowsadapters.Consent, bool), collectAdapterContext adapterContextCollector, readPatchContext func() (windowspatchcontext.Consent, bool), collectPatchContext patchContextCollector, readSecurityPosture func() (windowssecurity.Consent, bool), collectSecurityPosture securityPostureCollector, readSessionContext func() (windowssessions.Consent, bool), collectSessionContext sessionContextCollector, readHardwareContext func() (windowshardware.Consent, bool), collectHardwareContext hardwareContextCollector, readStorageContext func() (windowsstorage.Consent, bool), collectStorageContext storageContextCollector, readSecurityCoverage func() (windowssecuritycoverage.Consent, bool), collectSecurityCoverage securityCoverageCollector, readResourceContext func() (windowsresourcecontext.Consent, bool), collectResourceContext resourceContextCollector, readStorageIO func() (windowsstorageio.Consent, bool), collectStorageIO storageIOCollector, currentMaterial func() bool) (Report, error) {
	report := Report{SchemaVersion: "tracebolt.agent-run.v1", Status: "failed", Profile: m.config.Profile}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !m.valid() {
		return report, ErrConfiguration
	}
	currentAuthority := func() bool { return !m.config.windowsInventory() || currentMaterial != nil && currentMaterial() }
	if !currentAuthority() {
		return report, ErrState
	}
	consent, enabled := windowseventhealth.Consent{}, false
	if m.config.windowsInventory() && readConsent != nil {
		consent, enabled = readConsent()
		enabled = enabled && validEventConsent(consent, m.binding)
	}
	volumeConsent, volumesEnabled := windowsvolumes.Consent{}, false
	if m.config.windowsInventory() && readVolumes != nil {
		volumeConsent, volumesEnabled = readVolumes()
		volumesEnabled = volumesEnabled && validVolumeConsent(volumeConsent, m.binding)
	}
	processConsent, processEnabled := windowsprocessmetrics.Consent{}, false
	if m.config.windowsInventory() && readProcessMetrics != nil {
		processConsent, processEnabled = readProcessMetrics()
		processEnabled = processEnabled && validProcessMetricConsent(processConsent, m.binding)
	}
	if !processEnabled && m.processSampler != nil {
		m.processSampler.Reset()
	}
	networkConsent, networkEnabled := windowsnetwork.Consent{}, false
	if m.config.windowsInventory() && readNetwork != nil {
		networkConsent, networkEnabled = readNetwork()
		networkEnabled = networkEnabled && validNetworkConsent(networkConsent, m.binding)
	}
	startupConsent, startupEnabled := windowsmanaged.ServiceStartupConsent{}, false
	if m.config.windowsInventory() && readServiceStartup != nil {
		startupConsent, startupEnabled = readServiceStartup()
		startupEnabled = startupEnabled && validServiceStartupConsent(startupConsent, m.binding)
	}
	updatesConsent, updatesEnabled := windowsupdates.Consent{}, false
	if m.config.windowsInventory() && readUpdates != nil {
		updatesConsent, updatesEnabled = readUpdates()
		updatesEnabled = updatesEnabled && validUpdatesConsent(updatesConsent, m.binding)
	}
	adapterConsent, adapterEnabled := windowsadapters.Consent{}, false
	if m.config.windowsInventory() && readAdapterContext != nil {
		adapterConsent, adapterEnabled = readAdapterContext()
		adapterEnabled = adapterEnabled && validAdapterContextConsent(adapterConsent, m.binding)
	}
	patchConsent, patchEnabled := windowspatchcontext.Consent{}, false
	if m.config.windowsInventory() && readPatchContext != nil {
		patchConsent, patchEnabled = readPatchContext()
		patchEnabled = patchEnabled && validPatchContextConsent(patchConsent, m.binding)
	}
	securityConsent, securityEnabled := windowssecurity.Consent{}, false
	if m.config.windowsInventory() && readSecurityPosture != nil {
		securityConsent, securityEnabled = readSecurityPosture()
		securityEnabled = securityEnabled && validSecurityPostureConsent(securityConsent, m.binding)
	}
	sessionConsent, sessionEnabled := windowssessions.Consent{}, false
	if m.config.windowsInventory() && readSessionContext != nil {
		sessionConsent, sessionEnabled = readSessionContext()
		sessionEnabled = sessionEnabled && validSessionContextConsent(sessionConsent, m.binding)
	}
	if sessionEnabled {
		collectSessionContext = sessionContextWithBudget(collectSessionContext)
	}
	hardwareConsent, hardwareEnabled := windowshardware.Consent{}, false
	if m.config.windowsInventory() && readHardwareContext != nil {
		hardwareConsent, hardwareEnabled = readHardwareContext()
		hardwareEnabled = hardwareEnabled && validHardwareContextConsent(hardwareConsent, m.binding)
	}
	if hardwareEnabled {
		collectHardwareContext = hardwareContextWithBudget(collectHardwareContext)
	}
	storageConsent, storageEnabled := windowsstorage.Consent{}, false
	if m.config.windowsInventory() && readStorageContext != nil {
		storageConsent, storageEnabled = readStorageContext()
		storageEnabled = storageEnabled && validStorageContextConsent(storageConsent, m.binding)
	}
	if storageEnabled {
		collectStorageContext = storageContextWithBudget(collectStorageContext)
	}
	coverageConsent, coverageEnabled := windowssecuritycoverage.Consent{}, false
	if m.config.windowsInventory() && readSecurityCoverage != nil {
		coverageConsent, coverageEnabled = readSecurityCoverage()
		coverageEnabled = coverageEnabled && validSecurityCoverageConsent(coverageConsent, m.binding)
	}
	if coverageEnabled {
		collectSecurityCoverage = securityCoverageWithBudget(collectSecurityCoverage)
	}
	resourceConsent, resourceEnabled := windowsresourcecontext.Consent{}, false
	if m.config.windowsInventory() && readResourceContext != nil {
		resourceConsent, resourceEnabled = readResourceContext()
		resourceEnabled = resourceEnabled && validResourceContextConsent(resourceConsent, m.binding)
	}
	if resourceEnabled {
		collectResourceContext = resourceContextWithBudget(collectResourceContext)
	}
	storageIOConsent, storageIOEnabled := windowsstorageio.Consent{}, false
	if m.config.windowsInventory() && readStorageIO != nil {
		storageIOConsent, storageIOEnabled = readStorageIO()
		storageIOEnabled = storageIOEnabled && validStorageIOConsent(storageIOConsent, m.binding)
	}
	if storageIOEnabled {
		collectStorageIO = storageIOWithBudget(collectStorageIO)
	}
	if securityEnabled {
		collectSecurityPosture = securityPostureWithBudget(collectSecurityPosture)
	}
	if patchEnabled || securityEnabled || sessionEnabled || hardwareEnabled || storageEnabled || coverageEnabled || resourceEnabled || storageIOEnabled {
		collectUpdates = updatesWithPatchBudget(collectUpdates)
		collectPatchContext = patchContextWithBudget(collectPatchContext)
	}
	// An identity-losing reader must not be mistaken for an ordinary disabled scope.
	if !currentAuthority() {
		return report, ErrState
	}
	pending, e := state.Pending()
	if e != nil {
		return report, ErrState
	}
	var f frame
	var body []byte
	if pending != nil {
		f, e = decodeFrameForConfig(pending.Body(), pending.Sequence, m.config)
		if e != nil {
			return report, ErrState
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		unconsented := f.WindowsEvents != nil && (!enabled || f.WindowsEvents.GrantID != consent.GrantID) || f.WindowsVolumes != nil && (!volumesEnabled || f.WindowsVolumes.GrantID != volumeConsent.GrantID) || f.WindowsProcessMetrics != nil && (!processEnabled || f.WindowsProcessMetrics.GrantID != processConsent.GrantID) || f.WindowsNetwork != nil && (!networkEnabled || f.WindowsNetwork.GrantID != networkConsent.GrantID) || f.WindowsServiceStartup != nil && (!startupEnabled || f.WindowsServiceStartup.GrantID != startupConsent.GrantID) || f.WindowsUpdates != nil && (!updatesEnabled || f.WindowsUpdates.GrantID != updatesConsent.GrantID) || f.WindowsAdapterContext != nil && (!adapterEnabled || f.WindowsAdapterContext.GrantID != adapterConsent.GrantID) || f.WindowsPatchContext != nil && (!patchEnabled || f.WindowsPatchContext.GrantID != patchConsent.GrantID) || f.WindowsSecurityPosture != nil && (!securityEnabled || f.WindowsSecurityPosture.GrantID != securityConsent.GrantID) || f.WindowsSessionContext != nil && (!sessionEnabled || f.WindowsSessionContext.GrantID != sessionConsent.GrantID) || f.WindowsHardwareContext != nil && (!hardwareEnabled || f.WindowsHardwareContext.GrantID != hardwareConsent.GrantID) || f.WindowsStorageContext != nil && (!storageEnabled || f.WindowsStorageContext.GrantID != storageConsent.GrantID) || f.WindowsSecurityCoverage != nil && (!coverageEnabled || f.WindowsSecurityCoverage.GrantID != coverageConsent.GrantID) || f.WindowsResourceContext != nil && (!resourceEnabled || f.WindowsResourceContext.GrantID != resourceConsent.GrantID) || f.WindowsStorageIO != nil && (!storageIOEnabled || f.WindowsStorageIO.GrantID != storageIOConsent.GrantID)
		if !currentAuthority() {
			return report, ErrState
		}
		if stale(f, time.Now().UTC()) || unconsented {
			if state.Discard(pending.Digest) != nil {
				return report, ErrState
			}
			pending = nil
			report.DiscardedStale = !unconsented
			report.DiscardedUnconsented = unconsented
		} else {
			report.RetriedPending = true
		}
	}
	if pending == nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if !currentAuthority() {
			return report, ErrState
		}
		sequence, e := state.NextSequence()
		if e != nil {
			return report, ErrState
		}
		if (m.config.managed() || m.config.windowsInventory()) && sequence > operational.MaxSafeInteger {
			return report, ErrState
		}
		// Self retention is local to a fresh, explicitly consented capture.
		// Pending retries never select a PID, collect, or refit their durable bytes.
		selfPID := uint32(0)
		if processEnabled {
			selfPID = uint32(os.Getpid())
		}
		captureCtx := withProcessMetricSelfPID(ctx, selfPID)
		f, body, e = collectFrameWithDependencies(captureCtx, m.config, sequence, collectOperations, collectPackages, collectBasic, collectWindows)
		if e != nil {
			return report, e
		}
		if storageIOEnabled {
			// Fresh v16 only. Reserve before PID selection or service digest
			// capture; never refit a pending body or a row-bound snapshot.
			if !currentAuthority() || !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
				return report, ErrState
			}
			bounded, err := windowsmanaged.FitPreviewBudgetWithSelfPID(*f.WindowsInventory, windowsStorageIOBaseBytes, selfPID)
			if err != nil {
				return report, ErrObservation
			}
			f.WindowsInventory = &bounded
		} else if resourceEnabled {
			// Fresh v15 only. Reserve before PID selection or service digest
			// capture; never refit a pending body or a row-bound snapshot.
			if !currentAuthority() || !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) {
				return report, ErrState
			}
			bounded, err := windowsmanaged.FitPreviewBudgetWithSelfPID(*f.WindowsInventory, windowsResourceContextBaseBytes, selfPID)
			if err != nil {
				return report, ErrObservation
			}
			f.WindowsInventory = &bounded
		}
		earlierJobs := []func(context.Context) error{}
		if patchEnabled || securityEnabled || sessionEnabled || hardwareEnabled || storageEnabled || coverageEnabled || resourceEnabled || storageIOEnabled {
			collectEvents = eventsWithPrimaryReserve(collectEvents, f.WindowsInventory.CollectedAt)
			collectVolumes = volumesWithPrimaryReserve(collectVolumes, f.WindowsInventory.CollectedAt)
			collectProcessMetrics = processMetricsWithPrimaryReserve(collectProcessMetrics)
			collectNetwork = networkWithPrimaryReserve(collectNetwork)
			collectServiceStartup = serviceStartupWithPrimaryReserve(collectServiceStartup)
			collectAdapterContext = adapterContextWithPrimaryReserve(collectAdapterContext)

			if enabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameEventConsent(readConsent, consent, m.binding) {
						return ErrState
					}
					if collectEvents == nil {
						return ErrConfiguration
					}

					snapshot, err := collectEvents(sourceCtx, f.WindowsInventory.GenerationID, consent, m.binding)
					if !currentAuthority() || !sameEventConsent(readConsent, consent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectEvents = func(context.Context, string, windowseventhealth.Consent, string) (windowseventhealth.Snapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}

			if volumesEnabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameVolumeConsent(readVolumes, volumeConsent, m.binding) {
						return ErrState
					}
					if collectVolumes == nil {
						return ErrConfiguration
					}

					snapshot, err := collectVolumes(sourceCtx, f.WindowsInventory.GenerationID, volumeConsent, m.binding)
					if !currentAuthority() || !sameVolumeConsent(readVolumes, volumeConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectVolumes = func(context.Context, string, windowsvolumes.Consent, string) (windowsvolumes.Snapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}

			if processEnabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameProcessMetricConsent(readProcessMetrics, processConsent, m.binding) {
						return ErrState
					}
					if collectProcessMetrics == nil {
						return ErrConfiguration
					}
					pids := make([]uint32, 0, len(f.WindowsInventory.Processes.Rows))
					for _, row := range f.WindowsInventory.Processes.Rows {
						pids = append(pids, row.PID)
					}
					snapshot, err := collectProcessMetrics(sourceCtx, pids, f.WindowsInventory.GenerationID, processConsent.GrantID, f.WindowsInventory.CollectedAt)
					if !currentAuthority() || !sameProcessMetricConsent(readProcessMetrics, processConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectProcessMetrics = func(context.Context, []uint32, string, string, time.Time) (windowsprocessmetrics.Snapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}

			if networkEnabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameNetworkConsent(readNetwork, networkConsent, m.binding) {
						return ErrState
					}
					if collectNetwork == nil {
						return ErrConfiguration
					}

					snapshot, err := collectNetwork(sourceCtx, f.WindowsInventory.GenerationID, networkConsent.GrantID, time.Now().UTC())
					if !currentAuthority() || !sameNetworkConsent(readNetwork, networkConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectNetwork = func(context.Context, string, string, time.Time) (windowsnetwork.Snapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}

			if startupEnabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameServiceStartupConsent(readServiceStartup, startupConsent, m.binding) {
						return ErrState
					}
					if collectServiceStartup == nil {
						return ErrConfiguration
					}
					rows := append([]windowsmanaged.Service{}, f.WindowsInventory.Services.Rows...)
					snapshot, err := collectServiceStartup(sourceCtx, rows, f.WindowsInventory.GenerationID, startupConsent.GrantID, f.WindowsInventory.CollectedAt)
					if !currentAuthority() || !sameServiceStartupConsent(readServiceStartup, startupConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectServiceStartup = func(context.Context, []windowsmanaged.Service, string, string, time.Time) (windowsmanaged.ServiceStartupSnapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}

			if adapterEnabled {
				earlierJobs = append(earlierJobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameAdapterContextConsent(readAdapterContext, adapterConsent, m.binding) {
						return ErrState
					}
					if collectAdapterContext == nil {
						return ErrConfiguration
					}

					snapshot, err := collectAdapterContext(sourceCtx, f.WindowsInventory.GenerationID, adapterConsent.GrantID, f.WindowsInventory.CollectedAt)
					if !currentAuthority() || !sameAdapterContextConsent(readAdapterContext, adapterConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectAdapterContext = func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) {
						return snapshot, nil
					}
					return nil
				})
			}
		}
		// Alternate the first group on fresh sequences. Existing providers retain
		// their original first opportunity on odd sequences; isolated contexts
		// get it on even sequences. Retries never collect or advance this order.
		// Serialization still follows the original canonical wire order.
		if sequence%2 == 0 && (patchEnabled || securityEnabled || sessionEnabled || hardwareEnabled || storageEnabled || coverageEnabled || resourceEnabled || storageIOEnabled) {
			jobs := []func(context.Context) error{}
			if updatesEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameUpdatesConsent(readUpdates, updatesConsent, m.binding) {
						return ErrState
					}
					if collectUpdates == nil {
						return ErrConfiguration
					}
					snapshot, err := collectUpdates(sourceCtx, windowsupdates.Request{Consent: updatesConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameUpdatesConsent(readUpdates, updatesConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectUpdates = func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) { return snapshot, err }
					return nil
				})
			}
			if patchEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !samePatchContextConsent(readPatchContext, patchConsent, m.binding) {
						return ErrState
					}
					if collectPatchContext == nil {
						return ErrConfiguration
					}
					snapshot, err := collectPatchContext(sourceCtx, windowspatchcontext.Request{Consent: patchConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !samePatchContextConsent(readPatchContext, patchConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectPatchContext = func(context.Context, windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
						return snapshot, err
					}
					return nil
				})
			}
			if securityEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) {
						return ErrState
					}
					if collectSecurityPosture == nil {
						return ErrConfiguration
					}
					snapshot, err := collectSecurityPosture(sourceCtx, windowssecurity.Request{Consent: securityConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectSecurityPosture = func(context.Context, windowssecurity.Request) (windowssecurity.Snapshot, error) { return snapshot, err }
					return nil
				})
			}
			if sessionEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) {
						return ErrState
					}
					if collectSessionContext == nil {
						return ErrConfiguration
					}
					snapshot, err := collectSessionContext(sourceCtx, windowssessions.Request{Consent: sessionConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectSessionContext = func(context.Context, windowssessions.Request) (windowssessions.Snapshot, error) { return snapshot, err }
					return nil
				})
			}
			if hardwareEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) {
						return ErrState
					}
					if collectHardwareContext == nil {
						return ErrConfiguration
					}
					snapshot, err := collectHardwareContext(sourceCtx, windowshardware.Request{Consent: hardwareConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectHardwareContext = func(context.Context, windowshardware.Request) (windowshardware.Snapshot, error) { return snapshot, err }
					return nil
				})
			}
			if storageEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) {
						return ErrState
					}
					if collectStorageContext == nil {
						return ErrConfiguration
					}
					snapshot, err := collectStorageContext(sourceCtx, windowsstorage.Request{Consent: storageConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectStorageContext = func(context.Context, windowsstorage.Request) (windowsstorage.Snapshot, error) { return snapshot, err }
					return nil
				})
			}
			if coverageEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) {
						return ErrState
					}
					if collectSecurityCoverage == nil {
						return ErrConfiguration
					}
					snapshot, err := collectSecurityCoverage(sourceCtx, windowssecuritycoverage.Request{Consent: coverageConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectSecurityCoverage = func(context.Context, windowssecuritycoverage.Request) (windowssecuritycoverage.Snapshot, error) {
						return snapshot, err
					}
					return nil
				})
			}
			if resourceEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) {
						return ErrState
					}
					if collectResourceContext == nil {
						return ErrConfiguration
					}
					snapshot, err := collectResourceContext(sourceCtx, windowsresourcecontext.Request{Consent: resourceConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectResourceContext = func(context.Context, windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
						return snapshot, err
					}
					return nil
				})
			}
			if storageIOEnabled {
				jobs = append(jobs, func(sourceCtx context.Context) error {
					if !currentAuthority() || !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
						return ErrState
					}
					if collectStorageIO == nil {
						return ErrConfiguration
					}
					snapshot, err := collectStorageIO(sourceCtx, windowsstorageio.Request{Consent: storageIOConsent, SenderBinding: m.binding, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: f.WindowsInventory.CollectedAt})
					if !currentAuthority() || !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
						return ErrState
					}
					if sourceCtx.Err() != nil {
						return sourceCtx.Err()
					}
					if err != nil {
						return ErrObservation
					}
					collectStorageIO = func(context.Context, windowsstorageio.Request) (windowsstorageio.Snapshot, error) {
						return snapshot, err
					}
					return nil
				})
			}
			if e = collectWindowsContextGroup(captureCtx, sequence, jobs); e != nil {
				return report, e
			}
		}
		// Earlier sources rotate within their own group too. Their read results
		// are cached only for this attempt; assembly retains exact base row/PID
		// bindings and the original canonical append order.
		if e = collectWindowsContextGroup(captureCtx, sequence, earlierJobs); e != nil {
			return report, e
		}
		if enabled {
			f, body, e = appendWindowsEvents(captureCtx, m, f, consent, collectEvents)
			if e != nil {
				return report, e
			}
		}
		if volumesEnabled {
			f, body, e = appendWindowsVolumes(captureCtx, m, f, volumeConsent, collectVolumes)
			if e != nil {
				return report, e
			}
		}
		if processEnabled {
			f, body, e = appendWindowsProcessMetrics(captureCtx, m, f, processConsent, collectProcessMetrics)
			if e != nil {
				return report, e
			}
		}
		if networkEnabled {
			f, body, e = appendWindowsNetwork(captureCtx, m, f, networkConsent, collectNetwork)
			if e != nil {
				return report, e
			}
		}
		if startupEnabled {
			// Base and other optional captures can take time. Recheck this grant
			// immediately before the first service-configuration read as well.
			if !sameServiceStartupConsent(readServiceStartup, startupConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsServiceStartup(captureCtx, m, f, startupConsent, collectServiceStartup)
			if e != nil {
				return report, e
			}
		}
		if updatesEnabled {
			if !sameUpdatesConsent(readUpdates, updatesConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsUpdates(captureCtx, m, f, updatesConsent, collectUpdates)
			if e != nil {
				return report, e
			}
		}
		if adapterEnabled {
			if !sameAdapterContextConsent(readAdapterContext, adapterConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsAdapterContext(captureCtx, m, f, adapterConsent, collectAdapterContext)
			if e != nil {
				return report, e
			}
		}

		if patchEnabled {
			if !samePatchContextConsent(readPatchContext, patchConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsPatchContext(captureCtx, m, f, patchConsent, collectPatchContext)
			if e != nil {
				return report, e
			}
		}
		if securityEnabled {
			if !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsSecurityPosture(captureCtx, m, f, securityConsent, collectSecurityPosture)
			if e != nil {
				return report, e
			}
		}
		if sessionEnabled {
			if !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsSessionContext(captureCtx, m, f, sessionConsent, collectSessionContext)
			if e != nil {
				return report, e
			}
		}
		if hardwareEnabled {
			if !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsHardwareContext(captureCtx, m, f, hardwareConsent, collectHardwareContext)
			if e != nil {
				return report, e
			}
		}

		if storageEnabled {
			if !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsStorageContext(captureCtx, m, f, storageConsent, collectStorageContext)
			if e != nil {
				return report, e
			}
		}
		if coverageEnabled {
			if !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsSecurityCoverage(captureCtx, m, f, coverageConsent, collectSecurityCoverage)
			if e != nil {
				return report, e
			}
		}
		if resourceEnabled {
			if !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsResourceContext(captureCtx, m, f, resourceConsent, collectResourceContext)
			if e != nil {
				return report, e
			}
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if storageIOEnabled {
			if !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
				return report, ErrState
			}
			f, body, e = appendWindowsStorageIO(captureCtx, m, f, storageIOConsent, collectStorageIO)
			if e != nil {
				return report, e
			}
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if f.WindowsEvents != nil && !sameEventConsent(readConsent, consent, m.binding) || f.WindowsVolumes != nil && !sameVolumeConsent(readVolumes, volumeConsent, m.binding) || f.WindowsProcessMetrics != nil && !sameProcessMetricConsent(readProcessMetrics, processConsent, m.binding) || f.WindowsNetwork != nil && !sameNetworkConsent(readNetwork, networkConsent, m.binding) || f.WindowsServiceStartup != nil && !sameServiceStartupConsent(readServiceStartup, startupConsent, m.binding) || f.WindowsUpdates != nil && !sameUpdatesConsent(readUpdates, updatesConsent, m.binding) || f.WindowsAdapterContext != nil && !sameAdapterContextConsent(readAdapterContext, adapterConsent, m.binding) || f.WindowsPatchContext != nil && !samePatchContextConsent(readPatchContext, patchConsent, m.binding) || f.WindowsSecurityPosture != nil && !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) || f.WindowsSessionContext != nil && !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) || f.WindowsHardwareContext != nil && !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) || f.WindowsStorageContext != nil && !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) || f.WindowsSecurityCoverage != nil && !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) || f.WindowsResourceContext != nil && !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) || f.WindowsStorageIO != nil && !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
			return report, ErrState
		}
		if !currentAuthority() {
			return report, ErrState
		}
		p, e := state.Stage(sequence, body)
		if e != nil {
			return report, ErrState
		}
		pending = &p
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if f.WindowsEvents != nil && !sameEventConsent(readConsent, consent, m.binding) || f.WindowsVolumes != nil && !sameVolumeConsent(readVolumes, volumeConsent, m.binding) || f.WindowsProcessMetrics != nil && !sameProcessMetricConsent(readProcessMetrics, processConsent, m.binding) || f.WindowsNetwork != nil && !sameNetworkConsent(readNetwork, networkConsent, m.binding) || f.WindowsServiceStartup != nil && !sameServiceStartupConsent(readServiceStartup, startupConsent, m.binding) || f.WindowsUpdates != nil && !sameUpdatesConsent(readUpdates, updatesConsent, m.binding) || f.WindowsAdapterContext != nil && !sameAdapterContextConsent(readAdapterContext, adapterConsent, m.binding) || f.WindowsPatchContext != nil && !samePatchContextConsent(readPatchContext, patchConsent, m.binding) || f.WindowsSecurityPosture != nil && !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) || f.WindowsSessionContext != nil && !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) || f.WindowsHardwareContext != nil && !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) || f.WindowsStorageContext != nil && !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) || f.WindowsSecurityCoverage != nil && !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) || f.WindowsResourceContext != nil && !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) || f.WindowsStorageIO != nil && !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
		return report, ErrState
	}
	report.Sequence = pending.Sequence
	for _, v := range []bool{f.Observation.Observation.CPU.Value != nil && f.Observation.Observation.CPU.Quality == "healthy", f.Observation.Observation.Memory.Value != nil && f.Observation.Observation.Memory.Quality == "healthy", f.Observation.Observation.Disk.Value != nil && f.Observation.Observation.Disk.Quality == "healthy"} {
		if v {
			report.AvailablePercentageFields++
		} else {
			report.UnavailablePercentageFields++
		}
	}
	report.Status = "pending_retained"
	var req *http.Request
	if m.config.Profile == "http-test" {
		req, e = signedhttp.NewSignedRequestForPath(ctx, m.config.ManagerOrigin, telemetryPath(m.config), m.certificate, pending.Sequence, f.Observation.GeneratedAt, pending.Body())
	} else {
		req, e = http.NewRequestWithContext(ctx, "POST", m.config.ManagerOrigin+telemetryPath(m.config), bytes.NewReader(pending.Body()))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return report, ErrConfiguration
	}
	if send == nil {
		client := newHTTPClient(m.tlsConfig, m.config.Profile == "http-test")
		defer client.CloseIdleConnections()
		send = client.Do
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !currentAuthority() {
		return report, ErrState
	}
	if f.WindowsSecurityPosture != nil && !sameSecurityPostureConsent(readSecurityPosture, securityConsent, m.binding) || f.WindowsSessionContext != nil && !sameSessionContextConsent(readSessionContext, sessionConsent, m.binding) || f.WindowsHardwareContext != nil && !sameHardwareContextConsent(readHardwareContext, hardwareConsent, m.binding) || f.WindowsStorageContext != nil && !sameStorageContextConsent(readStorageContext, storageConsent, m.binding) || f.WindowsSecurityCoverage != nil && !sameSecurityCoverageConsent(readSecurityCoverage, coverageConsent, m.binding) || f.WindowsResourceContext != nil && !sameResourceContextConsent(readResourceContext, resourceConsent, m.binding) || f.WindowsStorageIO != nil && !sameStorageIOConsent(readStorageIO, storageIOConsent, m.binding) {
		return report, ErrState
	}
	response, e := send(req)
	if e != nil {
		return report, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return report, ErrTransport
	}
	if len(response.Header.Values("Content-Encoding")) > 0 {
		return report, ErrReceipt
	}
	if len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return report, ErrReceipt
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return report, ErrReceipt
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return report, ErrReceipt
	}
	var acknowledged receipt
	if lanconfig.StrictObject(raw, &acknowledged, "schemaVersion", "agentId", "sequence", "collectedAt", "receivedAt", "duplicate") != nil {
		return report, ErrReceipt
	}
	now := time.Now().UTC()
	if acknowledged.SchemaVersion != "tracebolt.agent-receipt.v1" || acknowledged.AgentID != m.config.AgentID || acknowledged.Sequence != pending.Sequence || !acknowledged.CollectedAt.Equal(f.Observation.Observation.LastSeen) || acknowledged.ReceivedAt.IsZero() || acknowledged.ReceivedAt.After(now.Add(30*time.Second)) || acknowledged.ReceivedAt.Before(acknowledged.CollectedAt.Add(-30*time.Second)) {
		return report, ErrReceipt
	}
	if state.Acknowledge(pending.Digest) != nil {
		return report, ErrState
	}
	report.Status = "acknowledged"
	report.Duplicate = acknowledged.Duplicate
	return report, nil
}

// collectFrame keeps the basic bundle unchanged and collects it after operations,
// so its generated-at timestamp also bounds the operational collection start.
func collectFrame(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot) (frame, []byte, error) {
	return collectFrameWithCollectors(ctx, c, sequence, collectOperations, packagecollector.Collect)
}

func collectFrameWithCollectors(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (frame, []byte, error) {
	return collectFrameWithSources(ctx, c, sequence, collectOperations, collectPackages, collector.Snapshot)
}

func collectFrameWithSources(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device) (frame, []byte, error) {
	return collectFrameWithDependencies(ctx, c, sequence, collectOperations, collectPackages, collectBasic, windowsmanaged.Collect)
}

func collectFrameWithDependencies(ctx context.Context, c Config, sequence uint64, collectOperations func(context.Context, time.Time) operational.Snapshot, collectPackages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error), collectBasic func() model.Device, collectWindows windowsCollector) (frame, []byte, error) {
	if c.SchemaVersion == WindowsInventoryConfigVersion || c.SchemaVersion == WindowsRenewalConfigVersion || c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
		return collectWindowsFrame(ctx, c, sequence, collectWindows)
	}
	f := frame{SchemaVersion: FrameVersion, Sequence: sequence}
	if c.packages() && c.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
		return f, nil, ErrConfiguration
	}
	if ctx.Err() != nil {
		return f, nil, ctx.Err()
	}
	if c.managed() {
		if sequence == 0 || sequence > operational.MaxSafeInteger {
			return f, nil, ErrState
		}
		snapshot := collectOperations(ctx, time.Now().UTC())
		if ctx.Err() != nil {
			return f, nil, ctx.Err()
		}
		if operational.Validate(snapshot) != nil {
			return f, nil, ErrObservation
		}
		f.SchemaVersion, f.Operational = FrameOperationalVersion, &snapshot
		if c.packages() {
			bounded, err := operational.TrimForPackageFrame(snapshot)
			if err != nil {
				return f, nil, ErrObservation
			}
			packages, err := collectPackages(ctx, bounded.GenerationID, bounded.CollectedAt)
			if ctx.Err() != nil {
				return f, nil, ctx.Err()
			}
			if err != nil || linuxpackages.Validate(packages) != nil || packages.GenerationID != bounded.GenerationID || !packages.CollectedAt.Equal(bounded.CollectedAt) {
				return f, nil, ErrObservation
			}
			f.SchemaVersion, f.Operational, f.Packages = FramePackagesVersion, &bounded, &packages
		}
	}
	raw, err := bundle.Encode(collectBasic())
	if ctx.Err() != nil {
		return f, nil, ctx.Err()
	}
	if err != nil || json.Unmarshal(raw, &f.Observation) != nil {
		return f, nil, ErrObservation
	}
	body, err := json.Marshal(f)
	if err != nil || len(body) > MaxFrameBytes {
		return f, nil, ErrObservation
	}
	if f.Operational != nil && stale(f, time.Now().UTC()) {
		return f, nil, ErrObservation
	}
	if _, err := decodeFrameForConfig(body, sequence, c); err != nil {
		return f, nil, ErrObservation
	}
	return f, body, nil
}

func decodeFrame(raw []byte, sequence uint64) (frame, error) {
	return decodeFrameForConfig(raw, sequence, Config{SchemaVersion: ConfigVersion})
}
func decodeFrameForConfig(raw []byte, sequence uint64, c Config) (frame, error) {
	var f frame
	if len(raw) == 0 || len(raw) > MaxFrameBytes || rejectDuplicateJSON(raw) != nil {
		return f, ErrState
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return f, ErrState
	}
	want := 3
	if c.operational() || c.complete() || c.windowsInventory() {
		want = 4
	} else if c.packages() {
		want = 5
	}
	if c.windowsInventory() && len(fields["windowsEvents"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsVolumes"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsProcessMetrics"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsNetwork"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsServiceStartup"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsUpdates"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsSessionContext"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsHardwareContext"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsStorageContext"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsSecurityCoverage"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsResourceContext"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsStorageIO"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsSecurityPosture"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsPatchContext"]) > 0 {
		want++
	}
	if c.windowsInventory() && len(fields["windowsAdapterContext"]) > 0 {
		want++
	}
	if len(fields) != want {
		return f, ErrState
	}
	for _, key := range []string{"schemaVersion", "sequence", "observation"} {
		if len(fields[key]) == 0 || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return f, ErrState
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF {
		return f, ErrState
	}
	if c.SchemaVersion == WindowsInventoryConfigVersion || c.SchemaVersion == WindowsRenewalConfigVersion || c.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
		if validateWindowsFrame(f, fields, c) != nil {
			return f, ErrState
		}
	} else if f.WindowsInventory != nil || f.WindowsEvents != nil || f.WindowsVolumes != nil || f.WindowsProcessMetrics != nil || f.WindowsNetwork != nil || f.WindowsServiceStartup != nil || f.WindowsUpdates != nil || f.WindowsAdapterContext != nil || f.WindowsPatchContext != nil || f.WindowsSecurityPosture != nil || f.WindowsSessionContext != nil || f.WindowsHardwareContext != nil || f.WindowsStorageContext != nil || f.WindowsSecurityCoverage != nil || f.WindowsResourceContext != nil {
		return f, ErrState
	} else if c.operational() || c.complete() {
		if f.Packages != nil || f.SchemaVersion != FrameOperationalVersion || f.Sequence == 0 || f.Sequence > operational.MaxSafeInteger || (c.CollectionProfile != operational.CollectionProfile && !c.complete()) || f.Operational == nil || len(fields["operational"]) > operational.MaxSnapshotBytes || exactOperationalJSON(fields["operational"]) != nil || operational.Validate(*f.Operational) != nil || f.Observation.Platform != "linux" || f.Operational.CollectedAt.After(f.Observation.GeneratedAt) {
			return f, ErrState
		}
	} else if c.packages() {
		if c.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || f.SchemaVersion != FramePackagesVersion || f.Sequence == 0 || f.Sequence > operational.MaxSafeInteger || f.Operational == nil || f.Packages == nil || f.Observation.Platform != "linux" || exactPackageFrameJSON(raw) != nil || len(fields["observation"]) > MaxPackageObservationBytes || len(fields["operational"]) > operational.MaxPackageFrameSnapshotBytes || operational.Validate(*f.Operational) != nil || f.Operational.CollectedAt.After(f.Observation.GeneratedAt) {
			return f, ErrState
		}
		d := f.Observation.Observation
		for _, at := range []time.Time{d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt} {
			if at.After(d.LastSeen) {
				return f, ErrState
			}
		}
		for _, evidence := range d.Evidence {
			if evidence.CollectedAt.After(d.LastSeen) {
				return f, ErrState
			}
		}
		p, err := linuxpackages.Decode(fields["packages"])
		if err != nil || p.GenerationID != f.Operational.GenerationID || !p.CollectedAt.Equal(f.Operational.CollectedAt) {
			return f, ErrState
		}
		op, err := json.Marshal(f.Operational)
		if err != nil || len(op) > operational.MaxPackageFrameSnapshotBytes {
			return f, ErrState
		}
		canonical, err := json.Marshal(f)
		if err != nil || len(canonical) > MaxFrameBytes || len(f.Observation.Version) == 0 || len(f.Observation.Version) > 64 || len(f.Observation.Architecture) == 0 || len(f.Observation.Architecture) > 32 || len(f.Observation.Privacy) > 16 {
			return f, ErrState
		}
	} else if f.SchemaVersion != FrameVersion || f.Operational != nil || f.Packages != nil {
		return f, ErrState
	}
	if f.Sequence != sequence || f.Observation.SchemaVersion != bundle.SchemaVersion || f.Observation.Product != "Tracebolt" || f.Observation.Platform != f.Observation.Observation.Platform || f.Observation.Scope != "single-read-only-local-observation" {
		return f, ErrState
	}
	if e := bundle.ValidateObservation(f.Observation.Observation); e != nil {
		return f, ErrState
	}
	encoded, e := json.Marshal(f.Observation)
	if e != nil || len(encoded) > bundle.MaxBytes || (c.packages() && len(encoded) > MaxPackageObservationBytes || c.windowsInventory() && len(encoded) > MaxWindowsObservationBytes) {
		return f, ErrState
	}
	return f, nil
}
func stale(f frame, now time.Time) bool {
	d := f.Observation.Observation
	times := []time.Time{f.Observation.GeneratedAt, d.LastSeen, d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt}
	if f.Operational != nil {
		times = append(times, f.Operational.CollectedAt)
	}
	if f.Packages != nil {
		times = append(times, f.Packages.CollectedAt)
	}
	if f.WindowsInventory != nil {
		times = append(times, f.WindowsInventory.CollectedAt)
	}
	if f.WindowsEvents != nil {
		times = append(times, f.WindowsEvents.CollectedAt)
	}
	if f.WindowsVolumes != nil {
		times = append(times, f.WindowsVolumes.CollectedAt)
	}
	if f.WindowsProcessMetrics != nil {
		times = append(times, f.WindowsProcessMetrics.CollectedAt)
	}
	if f.WindowsNetwork != nil {
		times = append(times, f.WindowsNetwork.CollectedAt)
	}
	if f.WindowsServiceStartup != nil {
		times = append(times, f.WindowsServiceStartup.CollectedAt)
	}
	if f.WindowsUpdates != nil {
		times = append(times, f.WindowsUpdates.CollectedAt)
	}
	if f.WindowsSessionContext != nil {
		times = append(times, f.WindowsSessionContext.CollectedAt)
	}
	if f.WindowsHardwareContext != nil {
		times = append(times, f.WindowsHardwareContext.CollectedAt)
	}
	if f.WindowsStorageContext != nil {
		times = append(times, f.WindowsStorageContext.CollectedAt)
	}
	if f.WindowsSecurityCoverage != nil {
		times = append(times, f.WindowsSecurityCoverage.CollectedAt)
	}
	if f.WindowsResourceContext != nil {
		times = append(times, f.WindowsResourceContext.CollectedAt)
	}
	if f.WindowsSecurityPosture != nil {
		times = append(times, f.WindowsSecurityPosture.CollectedAt)
	}
	if f.WindowsPatchContext != nil {
		times = append(times, f.WindowsPatchContext.CollectedAt)
	}
	if f.WindowsAdapterContext != nil {
		times = append(times, f.WindowsAdapterContext.CollectedAt)
	}
	for _, e := range d.Evidence {
		times = append(times, e.CollectedAt)
	}
	for _, at := range times {
		if at.IsZero() || now.Sub(at) > 2*time.Minute || at.Sub(now) > 30*time.Second || at.After(f.Observation.GeneratedAt) {
			return true
		}
	}
	return false
}
