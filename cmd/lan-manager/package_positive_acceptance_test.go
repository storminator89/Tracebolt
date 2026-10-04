//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/operational"
	"os"
	"strings"
	"testing"
	"time"
)

const packageUbuntu2404PositiveOptIn = "TRACEBOLT_PACKAGE_UBUNTU2404_TEST"

// This separate opt-in strengthens the existing real three-binary flow. It does
// not call a second collector or accept a fixture in place of a native report.
// Default test runs stop before starting binaries or reading any host source.
func TestPackageUbuntu2404PositiveNative(t *testing.T) {
	enabled, err := packagePositiveGateSelection(os.Getenv(packageUbuntu2404PositiveOptIn), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("explicit Ubuntu 24.04 positive native gate is not enabled")
	}
	checked := 0
	runPackageThreeBinaryEnrollmentAndForeground(t, func(t *testing.T, packages enrollmentstore.PackageView, observed enrollmentstore.OperationalView) {
		t.Helper()
		evidence, err := packageUbuntu2404PositiveEvidence(packages, observed)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		t.Log(evidence)
	})
	// Both sequential profiles must actually deliver both positive samples. A
	// future skipped/filtered subtest must not turn required acceptance green.
	if checked != 4 {
		t.Fatal("positive_native_requires_four_delivered_samples")
	}
}

// Selection is pure so invalid opt-ins and the nonprivileged requirement can be
// tested without running the native gate, even in a privileged test container.
func packagePositiveGateSelection(value string, euid int) (bool, error) {
	if value == "" {
		return false, nil
	}
	if value != "1" {
		return false, errors.New("positive_native_invalid_opt_in")
	}
	if euid <= 0 {
		return false, errors.New("positive_native_requires_nonprivileged_execution")
	}
	return true, nil
}

// Only fixed failure codes or validated status/count evidence leave this pure
// helper. No package values, paths, names, process identifiers, raw errors or
// serialized observations are included, including on malformed input.
func packageUbuntu2404PositiveEvidence(packages enrollmentstore.PackageView, observed enrollmentstore.OperationalView) (string, error) {
	fail := func(code string) (string, error) { return "", errors.New(code) }
	if packages.SchemaVersion != "tracebolt.package-view.v1" || observed.SchemaVersion != "tracebolt.operational-view.v1" ||
		packages.Status != "fresh" || observed.Status != "fresh" || packages.Snapshot == nil || observed.Snapshot == nil ||
		packages.DeviceID == "" || packages.DeviceID != observed.DeviceID ||
		packages.Sequence == nil || observed.Sequence == nil || *packages.Sequence == 0 || *packages.Sequence != *observed.Sequence ||
		packages.ReceivedAt == nil || observed.ReceivedAt == nil || packages.ReceivedAt.IsZero() || !packages.ReceivedAt.Equal(*observed.ReceivedAt) {
		return fail("positive_native_view_unavailable_or_unbound")
	}
	p, o := packages.Snapshot, observed.Snapshot
	if linuxpackages.Validate(*p) != nil || operational.Validate(*o) != nil ||
		p.GenerationID != o.GenerationID || !p.CollectedAt.Equal(o.CollectedAt) {
		return fail("positive_native_snapshot_invalid_or_unbound")
	}
	operationalBytes, err := json.Marshal(o)
	if err != nil || len(operationalBytes) > operational.MaxPackageFrameSnapshotBytes {
		return fail("positive_native_operational_reservation_exceeded")
	}
	if p.Release.Quality != linuxpackages.Healthy || p.Release.Reason != linuxpackages.ReasonNone || p.Release.Fields.Target() != linuxpackages.Ubuntu2404 {
		return fail("positive_native_exact_ubuntu2404_release_required")
	}
	x := p.Inventory
	if x.Quality != linuxpackages.Healthy || !x.CountExact || x.ObservedCount == nil || x.InstalledCount == nil ||
		*x.ObservedCount == 0 || *x.InstalledCount == 0 || len(x.Items) == 0 || len(x.Items) > linuxpackages.MaxExportRows {
		return fail("positive_native_positive_exact_inventory_required")
	}
	selectedInstalled := 0
	for _, row := range x.Items {
		if row.InstallState == "installed" {
			selectedInstalled++
		}
	}
	if selectedInstalled == 0 {
		return fail("positive_native_selected_installed_rows_required")
	}
	// Validate above enforces complete/truncated/reason/count consistency. A
	// successfully parsed full source may export a bounded, incomplete prefix.
	// Never require complete=true or replace full-source counts with row counts.
	v := o.Sections
	for _, section := range []struct {
		meta  operational.SectionMeta
		count int
	}{
		{v.Volumes.Meta, len(v.Volumes.Items)},
		{v.Network.Meta, len(v.Network.Items)},
		{v.Processes.Meta, len(v.Processes.Items)},
	} {
		if section.meta.Quality != operational.Healthy || section.count == 0 || section.count > section.meta.ItemLimit {
			return fail("positive_native_operational_selected_rows_required")
		}
	}
	// Mount discovery is positive evidence; measurement may be unavailable.
	// Unmeasured mounts sort before measured local disks and can fill the cap.
	// No volume-wide completeness or disk-capacity claim is made here.
	if v.Network.Meta.Complete {
		return fail("positive_native_network_missing_coverage_hidden")
	}
	measuredInterfaces := 0
	for _, row := range v.Network.Items {
		if row.RXBytes != nil && row.TXBytes != nil && row.RXErrors != nil && row.TXErrors != nil {
			measuredInterfaces++
		}
		// This provider intentionally does not enumerate addresses.
		if row.IPv4Count != nil || row.IPv6Count != nil {
			return fail("positive_native_network_missing_coverage_hidden")
		}
	}
	if measuredInterfaces == 0 {
		return fail("positive_native_interface_counters_required")
	}
	measuredProcesses := 0
	for _, row := range v.Processes.Items {
		if row.ParentPID != nil && row.RSSBytes != nil && row.CPUTimeSeconds != nil && row.Threads != nil {
			measuredProcesses++
		}
	}
	if measuredProcesses == 0 {
		return fail("positive_native_process_metrics_required")
	}
	return fmt.Sprintf("positive native observation: release=healthy target=ubuntu-24.04-noble inventory=healthy observedRows=%d installedRows=%d selectedRows=%d selectedInstalledRows=%d countExact=%t complete=%t truncated=%t reason=%s; volumes=%s selectedRows=%d complete=%t truncated=%t; network=%s selectedRows=%d complete=%t truncated=%t measuredRows=%d; processes=%s selectedRows=%d complete=%t truncated=%t measuredRows=%d; services=%s selectedRows=%d complete=%t truncated=%t; events=%s selectedRows=%d complete=%t truncated=%t",
		*x.ObservedCount, *x.InstalledCount, len(x.Items), selectedInstalled, x.CountExact, x.Complete, x.Truncated, x.Reason,
		v.Volumes.Meta.Quality, len(v.Volumes.Items), v.Volumes.Meta.Complete, v.Volumes.Meta.Truncated,
		v.Network.Meta.Quality, len(v.Network.Items), v.Network.Meta.Complete, v.Network.Meta.Truncated, measuredInterfaces,
		v.Processes.Meta.Quality, len(v.Processes.Items), v.Processes.Meta.Complete, v.Processes.Meta.Truncated, measuredProcesses,
		v.Services.Meta.Quality, len(v.Services.Items), v.Services.Meta.Complete, v.Services.Meta.Truncated,
		v.Events.Meta.Quality, len(v.Events.Items), v.Events.Meta.Complete, v.Events.Meta.Truncated), nil
}

func TestPackagePositiveGateSelection(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		euid        int
		enabled     bool
		failure     string
	}{
		{"default", "", 1000, false, ""},
		{"default-root", "", 0, false, ""},
		{"enabled", "1", 1000, true, ""},
		{"invalid-opt-in", "true", 1000, false, "positive_native_invalid_opt_in"},
		{"root", "1", 0, false, "positive_native_requires_nonprivileged_execution"},
		{"unknown-identity", "1", -1, false, "positive_native_requires_nonprivileged_execution"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, err := packagePositiveGateSelection(tc.value, tc.euid)
			if enabled != tc.enabled || err == nil && tc.failure != "" || err != nil && err.Error() != tc.failure {
				t.Fatal("positive native opt-in contract changed")
			}
		})
	}
}

func TestPackagePositiveEvidenceAcceptsBoundedObservations(t *testing.T) {
	for _, reason := range []linuxpackages.Reason{linuxpackages.ReasonNone, linuxpackages.ReasonItemLimit, linuxpackages.ReasonByteLimit} {
		t.Run(string(reason), func(t *testing.T) {
			p, o := packagePositiveFixture()
			if reason != linuxpackages.ReasonNone {
				p.Snapshot.Inventory.Complete = false
				p.Snapshot.Inventory.Truncated = true
				p.Snapshot.Inventory.Reason = reason
				p.Snapshot.Inventory.ObservedCount = positivePointer(uint64(300))
				p.Snapshot.Inventory.InstalledCount = positivePointer(uint64(297))
			}
			evidence, err := packageUbuntu2404PositiveEvidence(p, o)
			if err != nil || !strings.Contains(evidence, "selectedRows=1") || !strings.Contains(evidence, "network=healthy selectedRows=1 complete=false") || !strings.Contains(evidence, "events=denied selectedRows=0 complete=false") {
				t.Fatal("valid positive observation rejected or coverage hidden")
			}
			if reason != linuxpackages.ReasonNone && (!strings.Contains(evidence, "observedRows=300 installedRows=297") || !strings.Contains(evidence, "complete=false truncated=true reason="+string(reason))) {
				t.Fatal("bounded export lost exact full-source counts or partial flags")
			}
		})
	}
}

func TestPackagePositiveEvidenceAcceptsRealExporterCaps(t *testing.T) {
	p, o := packagePositiveFixture()
	row := p.Snapshot.Inventory.Items[0]
	p.Snapshot.Inventory.Items = make([]linuxpackages.PackageRow, 300)
	for i := range p.Snapshot.Inventory.Items {
		p.Snapshot.Inventory.Items[i] = row
		p.Snapshot.Inventory.Items[i].Name = fmt.Sprintf("fixture-binary-%04d", i)
	}
	p.Snapshot.Inventory.ObservedCount = positivePointer(uint64(300))
	p.Snapshot.Inventory.InstalledCount = positivePointer(uint64(300))
	trimmed, err := linuxpackages.Trim(*p.Snapshot)
	if err != nil || trimmed.Inventory.Complete || !trimmed.Inventory.Truncated || len(trimmed.Inventory.Items) == 0 || len(trimmed.Inventory.Items) > linuxpackages.MaxExportRows {
		t.Fatal("synthetic exporter fixture failed")
	}
	p.Snapshot = &trimmed
	if evidence, err := packageUbuntu2404PositiveEvidence(p, o); err != nil || !strings.Contains(evidence, "observedRows=300 installedRows=300") {
		t.Fatal("actual bounded exporter output rejected or source counts lost")
	}
	// Operational selected rows can also remain positive with explicitly partial
	// discovery or an export cap. Exact full-source counts are required only for
	// the package component, never invented for a bounded process directory scan.
	for _, meta := range []*operational.SectionMeta{&o.Snapshot.Sections.Volumes.Meta, &o.Snapshot.Sections.Network.Meta, &o.Snapshot.Sections.Processes.Meta} {
		meta.Complete, meta.Truncated, meta.CountExact, meta.Reason, meta.ObservedCount = false, true, false, operational.ReasonItemLimit, 100
	}
	if _, err := packageUbuntu2404PositiveEvidence(p, o); err != nil {
		t.Fatal("truthful positive operational partial sample rejected")
	}
}

func TestPackagePositiveEvidenceAcceptsMixedOperationalMeasurements(t *testing.T) {
	p, o := packagePositiveFixture()
	network := &o.Snapshot.Sections.Network
	network.Items = append(network.Items, operational.NetworkInterface{Name: "unmeasured-fixture-nic", State: "unknown"})
	network.Meta.ObservedCount = 2
	processes := &o.Snapshot.Sections.Processes
	processes.Items = append(processes.Items, operational.Process{PID: 6789, Name: "unmeasured-fixture-process", State: "unknown"})
	processes.Meta.ObservedCount, processes.Meta.Complete, processes.Meta.Reason = 2, false, operational.ReasonReadFailed
	evidence, err := packageUbuntu2404PositiveEvidence(p, o)
	if err != nil || !strings.Contains(evidence, "network=healthy selectedRows=2 complete=false truncated=false measuredRows=1") ||
		!strings.Contains(evidence, "processes=healthy selectedRows=2 complete=false truncated=false measuredRows=1") {
		t.Fatal("mixed operational measurements lost positive evidence or partial rows")
	}
	if len(network.Items) != 2 || len(processes.Items) != 2 || processes.Items[1].RSSBytes != nil || network.Items[1].RXBytes != nil {
		t.Fatal("positive assertion rewrote unavailable selected metrics")
	}
	processes.Items[0].RSSBytes = nil
	if evidence, err := packageUbuntu2404PositiveEvidence(p, o); evidence != "" || err == nil || err.Error() != "positive_native_process_metrics_required" {
		t.Fatal("all-unmeasured processes passed positive gate")
	}
	processes.Items[0].RSSBytes = positivePointer(uint64(4096))
	network.Items[0].RXBytes = nil
	if evidence, err := packageUbuntu2404PositiveEvidence(p, o); evidence != "" || err == nil || err.Error() != "positive_native_interface_counters_required" {
		t.Fatal("all-unmeasured interfaces passed positive gate")
	}
}

func TestPackagePositiveEvidenceRejectsPackageExportCaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rows    int
		version string
	}{
		{"rows", linuxpackages.MaxExportRows + 1, "1.0"},
		{"bytes", 20, "1." + strings.Repeat("a", 510)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, o := packagePositiveFixture()
			row := p.Snapshot.Inventory.Items[0]
			row.Version, row.SourceVersion = tc.version, tc.version
			p.Snapshot.Inventory.Items = make([]linuxpackages.PackageRow, tc.rows)
			for i := range p.Snapshot.Inventory.Items {
				p.Snapshot.Inventory.Items[i] = row
				p.Snapshot.Inventory.Items[i].Name = fmt.Sprintf("fixture-binary-%04d", i)
			}
			p.Snapshot.Inventory.ObservedCount = positivePointer(uint64(tc.rows))
			p.Snapshot.Inventory.InstalledCount = positivePointer(uint64(tc.rows))
			if evidence, err := packageUbuntu2404PositiveEvidence(p, o); evidence != "" || err == nil || err.Error() != "positive_native_snapshot_invalid_or_unbound" {
				t.Fatal("unbounded selected package export accepted")
			}
		})
	}
}

func TestPackagePositiveEvidenceRejectsMissingOrInvalidFacts(t *testing.T) {
	const invalidView = "positive_native_view_unavailable_or_unbound"
	const invalidSnapshot = "positive_native_snapshot_invalid_or_unbound"
	const wrongRelease = "positive_native_exact_ubuntu2404_release_required"
	const noInventory = "positive_native_positive_exact_inventory_required"
	for _, tc := range []struct {
		name, failure string
		change        func(*enrollmentstore.PackageView, *enrollmentstore.OperationalView)
	}{
		{"missing-package", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) { p.Snapshot = nil }},
		{"missing-operational", invalidView, func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) { o.Snapshot = nil }},
		{"stale", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) { p.Status = "stale" }},
		{"different-device", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) { p.DeviceID = "other" }},
		{"null-sequence", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) { p.Sequence = nil }},
		{"different-sequence", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Sequence = positivePointer(uint64(2))
		}},
		{"null-receipt", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) { p.ReceivedAt = nil }},
		{"different-receipt", invalidView, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.ReceivedAt = positivePointer(p.ReceivedAt.Add(time.Second))
		}},
		{"different-generation", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.GenerationID = "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"different-collection", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.CollectedAt = p.Snapshot.CollectedAt.Add(time.Second)
		}},
		{"release-unavailable", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}
		}},
		{"release-missing", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields.ID = nil
		}},
		{"release-empty", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields.VersionCodename = positivePointer("")
		}},
		{"release-derivative", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields.ID = positivePointer("derivative")
		}},
		{"release-point-version", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields.VersionID = positivePointer("24.04.1")
		}},
		{"release-inconsistent", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields.VersionCodename = positivePointer("jammy")
		}},
		{"release-debian", wrongRelease, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Release.Fields = linuxpackages.ReleaseFields{ID: positivePointer("debian"), VersionID: positivePointer("13"), VersionCodename: positivePointer("trixie")}
		}},
		{"inventory-unavailable", noInventory, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing, Items: []linuxpackages.PackageRow{}}
		}},
		{"inventory-denied", noInventory, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied, Items: []linuxpackages.PackageRow{}}
		}},
		{"null-observed", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.ObservedCount = nil
		}},
		{"null-installed", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.InstalledCount = nil
		}},
		{"approximate-count", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.CountExact = false
		}},
		{"empty-valid-source", noInventory, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Items = []linuxpackages.PackageRow{}
			p.Snapshot.Inventory.ObservedCount, p.Snapshot.Inventory.InstalledCount = positivePointer(uint64(0)), positivePointer(uint64(0))
		}},
		{"no-installed-source", noInventory, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Items[0].InstallState = "incomplete"
			p.Snapshot.Inventory.InstalledCount = positivePointer(uint64(0))
		}},
		{"empty-selected-prefix", noInventory, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Items = []linuxpackages.PackageRow{}
			p.Snapshot.Inventory.Complete, p.Snapshot.Inventory.Truncated, p.Snapshot.Inventory.Reason = false, true, linuxpackages.ReasonByteLimit
		}},
		{"only-incomplete-selected", "positive_native_selected_installed_rows_required", func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Items[0].InstallState = "incomplete"
			p.Snapshot.Inventory.ObservedCount = positivePointer(uint64(2))
			p.Snapshot.Inventory.Complete, p.Snapshot.Inventory.Truncated, p.Snapshot.Inventory.Reason = false, true, linuxpackages.ReasonByteLimit
		}},
		{"hidden-truncation", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.ObservedCount = positivePointer(uint64(2))
		}},
		{"partial-without-reason", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Complete = false
		}},
		{"invalid-package-row", invalidSnapshot, func(p *enrollmentstore.PackageView, _ *enrollmentstore.OperationalView) {
			p.Snapshot.Inventory.Items[0].SourceMapping = "inferred"
		}},
		{"unavailable-volumes", "positive_native_operational_selected_rows_required", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Volumes = operational.VolumeSection{Meta: positiveUnavailableMeta(o.Snapshot, operational.VolumeLimit, operational.ReasonPermissionDenied), Items: []operational.Volume{}}
		}},
		{"unavailable-network", "positive_native_operational_selected_rows_required", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Network = operational.NetworkSection{Meta: positiveUnavailableMeta(o.Snapshot, operational.NetworkLimit, operational.ReasonSourceMissing), Items: []operational.NetworkInterface{}}
		}},
		{"unavailable-processes", "positive_native_operational_selected_rows_required", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Processes = operational.ProcessSection{Meta: positiveUnavailableMeta(o.Snapshot, operational.ProcessLimit, operational.ReasonSourceMissing), Items: []operational.Process{}}
		}},
		{"missing-interface-counter", "positive_native_interface_counters_required", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Network.Items[0].RXBytes = nil
		}},
		{"invented-address-count", "positive_native_network_missing_coverage_hidden", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Network.Items[0].IPv4Count = positivePointer(uint64(0))
		}},
		{"missing-process-metric", "positive_native_process_metrics_required", func(_ *enrollmentstore.PackageView, o *enrollmentstore.OperationalView) {
			o.Snapshot.Sections.Processes.Meta.Complete, o.Snapshot.Sections.Processes.Meta.Reason = false, operational.ReasonReadFailed
			o.Snapshot.Sections.Processes.Items[0].RSSBytes = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, o := packagePositiveFixture()
			tc.change(&p, &o)
			evidence, err := packageUbuntu2404PositiveEvidence(p, o)
			if evidence != "" || err == nil || err.Error() != tc.failure {
				t.Fatal("invalid positive observation did not fail with expected fixed status")
			}
		})
	}
}

func TestPackagePositiveEvidenceDoesNotExposeSourceValues(t *testing.T) {
	p, o := packagePositiveFixture()
	evidence, err := packageUbuntu2404PositiveEvidence(p, o)
	if err != nil {
		t.Fatal("privacy fixture rejected")
	}
	for _, private := range []string{p.DeviceID, p.Snapshot.GenerationID, p.Snapshot.Inventory.Items[0].Name, p.Snapshot.Inventory.Items[0].Version,
		p.Snapshot.Inventory.Items[0].Architecture, p.Snapshot.Inventory.Items[0].SourcePackage, p.Snapshot.Inventory.Items[0].SourceVersion,
		o.Snapshot.Sections.Volumes.Items[0].MountPoint, o.Snapshot.Sections.Network.Items[0].Name, o.Snapshot.Sections.Processes.Items[0].Name} {
		if strings.Contains(evidence, private) {
			t.Fatal("source value escaped count/status evidence")
		}
	}
	p.Snapshot.Inventory.Reason = "private diagnostic /sensitive-path"
	evidence, err = packageUbuntu2404PositiveEvidence(p, o)
	if evidence != "" || err == nil || err.Error() != "positive_native_snapshot_invalid_or_unbound" {
		t.Fatal("malformed source text escaped fixed failure status")
	}
}

func positivePointer[T any](value T) *T { return &value }

// All rows and identifiers below are invented. This fixture performs no source
// reads, command execution, random identity generation or native collection.
func packagePositiveFixture() (enrollmentstore.PackageView, enrollmentstore.OperationalView) {
	at := time.Date(2026, 10, 4, 1, 2, 3, 0, time.UTC)
	generation := "sample_0123456789abcdef0123456789abcdef"
	p := linuxpackages.Snapshot{
		SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: generation, CollectedAt: at,
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Fields: linuxpackages.ReleaseFields{ID: positivePointer("ubuntu"), VersionID: positivePointer("24.04"), VersionCodename: positivePointer("noble")}},
		Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true,
			ObservedCount: positivePointer(uint64(1)), InstalledCount: positivePointer(uint64(1)),
			Items: []linuxpackages.PackageRow{{Name: "private-fixture-binary", Version: "1:2.0~rc1-7+b1", Architecture: "amd64", SourcePackage: "private-fixture-source", SourceVersion: "1:2.0~rc1-7", SourceMapping: "source-field", InstallState: "installed"}}},
	}
	o := operational.Snapshot{SchemaVersion: operational.SchemaVersion, CollectionProfile: operational.CollectionProfile, GenerationID: generation, CollectedAt: at}
	meta := func(limit int, reason operational.Reason) operational.SectionMeta {
		return operational.SectionMeta{GenerationID: generation, Quality: operational.Healthy, Reason: reason, ObservedAt: at, Complete: reason == operational.ReasonNone, CountExact: true, ObservedCount: 1, ItemLimit: limit}
	}
	o.Sections.Volumes = operational.VolumeSection{Meta: meta(operational.VolumeLimit, operational.ReasonNotSupported), Items: []operational.Volume{
		{ID: "mount_456", MountPoint: "/private-fixture-mount", Filesystem: "proc", Kind: "virtual", MeasurementQuality: operational.Unknown, MeasurementReason: operational.ReasonNotSupported},
	}}
	o.Sections.Network = operational.NetworkSection{Meta: meta(operational.NetworkLimit, operational.ReasonNotImplemented), Items: []operational.NetworkInterface{
		{Name: "private-fixture-nic", State: "unknown", MTU: positivePointer(uint64(1500)), RXBytes: positivePointer(uint64(5)), TXBytes: positivePointer(uint64(8)), RXErrors: positivePointer(uint64(0)), TXErrors: positivePointer(uint64(0))},
	}}
	o.Sections.Processes = operational.ProcessSection{Meta: meta(operational.ProcessLimit, operational.ReasonNone), Items: []operational.Process{
		{PID: 5678, ParentPID: positivePointer(uint64(1234)), Name: "private-fixture-process", State: "sleeping", RSSBytes: positivePointer(uint64(4096)), CPUTimeSeconds: positivePointer(1.25), Threads: positivePointer(uint64(1))},
	}}
	o.Sections.Services = operational.ServiceSection{Meta: positiveUnavailableMeta(&o, operational.ServiceLimit, operational.ReasonNotSupported), Items: []operational.Service{}}
	o.Sections.Software = operational.SoftwareSection{Meta: positiveUnavailableMeta(&o, operational.SoftwareLimit, operational.ReasonByteLimit), Items: []operational.Software{}}
	o.Sections.Events = operational.EventSection{Meta: positiveUnavailableMeta(&o, operational.EventLimit, operational.ReasonPermissionDenied), Items: []operational.Event{}}
	return enrollmentstore.PackageView{SchemaVersion: "tracebolt.package-view.v1", DeviceID: "agent_private-fixture", Status: "fresh", ServerNow: at, ReceivedAt: positivePointer(at), Sequence: positivePointer(uint64(1)), MaxAgeSeconds: 120, Snapshot: &p},
		enrollmentstore.OperationalView{SchemaVersion: "tracebolt.operational-view.v1", DeviceID: "agent_private-fixture", Status: "fresh", ServerNow: at, ReceivedAt: positivePointer(at), Sequence: positivePointer(uint64(1)), MaxAgeSeconds: 120, Snapshot: &o}
}

func positiveUnavailableMeta(s *operational.Snapshot, limit int, reason operational.Reason) operational.SectionMeta {
	quality := operational.Unknown
	if reason == operational.ReasonPermissionDenied {
		quality = operational.Denied
	}
	return operational.SectionMeta{GenerationID: s.GenerationID, Quality: quality, Reason: reason, ObservedAt: s.CollectedAt,
		Truncated: reason == operational.ReasonByteLimit || reason == operational.ReasonItemLimit, ItemLimit: limit}
}
