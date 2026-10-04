//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/systeminventory"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Selection is pure. The positive acceptance requirement cannot turn on any
// collection without the base runtime opt-in, nor silently skip on root/typos.
func completeMVPGateSelection(base, positive string, euid int) (bool, bool, error) {
	if base != "" && base != "1" || positive != "" && positive != "1" {
		return false, false, errors.New("complete_runtime_invalid_opt_in")
	}
	if positive == "1" && base != "1" {
		return false, false, errors.New("complete_positive_requires_runtime_opt_in")
	}
	if base == "" {
		return false, false, nil
	}
	if euid <= 0 {
		return false, false, errors.New("complete_runtime_requires_nonprivileged_execution")
	}
	return true, positive == "1", nil
}

// This helper consumes only the actual manager-delivered manifest and latest
// section summaries. It collects nothing and cannot substitute synthetic data
// for the opt-in flow. Only fixed errors or validated status/count evidence leave
// it. Socket-owner attribution is deliberately not a completeness prerequisite.
func completeMVPUbuntu2404Evidence(p completeMVPPackageView, s enrollmentstore.SystemView) (string, error) {
	fail := func(code string) (string, error) { return "", errors.New(code) }
	if p.SchemaVersion != "tracebolt.complete-package-view.v1" || p.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || p.Status != "available" || p.Complete == nil || p.Complete.State != "complete" || p.Failure != nil {
		return fail("complete_positive_package_required")
	}
	m := p.Complete.Manifest
	if m.Release.Quality != linuxpackages.Healthy || m.Release.Reason != linuxpackages.ReasonNone || m.Release.Fields.Target() != linuxpackages.Ubuntu2404 {
		return fail("complete_positive_ubuntu2404_required")
	}
	digest, err := fullinventory.ManifestDigest(m)
	sequence, sequenceErr := strconv.ParseUint(p.Complete.Binding.Sequence, 10, 64)
	if err != nil || sequenceErr != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != p.Complete.Binding.Sequence || m.ObservedCount == 0 || m.InstalledCount == 0 || p.Complete.Binding.ManifestHash != digest || p.Complete.Binding.GenerationID != m.GenerationID || p.Complete.CompletedAt.IsZero() || p.Complete.CompletedAt.Before(m.CollectedAt) || !p.Complete.RetainedUntil.After(p.Complete.CompletedAt) {
		return fail("complete_positive_manifest_invalid_or_empty")
	}
	if s.SchemaVersion != "tracebolt.system-inventory-view.v1" || s.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || s.Status != "fresh" || p.DeviceID == "" || p.DeviceID != s.DeviceID || s.Sequence == nil || *s.Sequence == 0 || s.ReceivedAt == nil || s.ReceivedAt.IsZero() || s.Latest == nil || s.Latest.Scope != systeminventory.SnapshotScope || s.Latest.CollectedAt.IsZero() {
		return fail("complete_positive_system_unavailable_or_unbound")
	}
	valid := func(meta systeminventory.SectionMeta, limit uint64) bool {
		return meta.Coverage == systeminventory.Complete && meta.Reason == systeminventory.ReasonNone && meta.CountExact && meta.ObservedCount != nil && *meta.ObservedCount > 0 && *meta.ObservedCount <= limit && meta.GenerationID == s.Latest.GenerationID && meta.ObservedAt.Equal(s.Latest.CollectedAt) && systeminventory.ValidateSectionMeta(meta, int(*meta.ObservedCount)) == nil
	}
	if !valid(s.Latest.Services, systeminventory.MaxServiceRows) {
		return fail("complete_positive_services_required")
	}
	if !valid(s.Latest.Sockets, systeminventory.MaxSocketRows) {
		return fail("complete_positive_sockets_required")
	}
	return fmt.Sprintf("positive complete native observation: target=ubuntu-24.04-noble packages=complete observedRows=%d installedRows=%d chunks=%d services=complete countExact=true observedRows=%d sockets=complete countExact=true observedRows=%d", m.ObservedCount, m.InstalledCount, m.ChunkCount, *s.Latest.Services.ObservedCount, *s.Latest.Sockets.ObservedCount), nil
}

func TestCompleteMVPGateSelection(t *testing.T) {
	for _, tc := range []struct {
		name, base, positive string
		euid                 int
		enabled, strict      bool
		failure              string
	}{
		{"default", "", "", 1000, false, false, ""},
		{"default-root", "", "", 0, false, false, ""},
		{"base", "1", "", 1000, true, false, ""},
		{"positive", "1", "1", 1000, true, true, ""},
		{"base-invalid", "true", "", 1000, false, false, "complete_runtime_invalid_opt_in"},
		{"positive-invalid", "1", "true", 1000, false, false, "complete_runtime_invalid_opt_in"},
		{"positive-invalid-without-base", "", "true", 1000, false, false, "complete_runtime_invalid_opt_in"},
		{"positive-without-base", "", "1", 1000, false, false, "complete_positive_requires_runtime_opt_in"},
		{"base-root", "1", "", 0, false, false, "complete_runtime_requires_nonprivileged_execution"},
		{"positive-root", "1", "1", 0, false, false, "complete_runtime_requires_nonprivileged_execution"},
		{"positive-unknown-identity", "1", "1", -1, false, false, "complete_runtime_requires_nonprivileged_execution"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, strict, err := completeMVPGateSelection(tc.base, tc.positive, tc.euid)
			if enabled != tc.enabled || strict != tc.strict || err == nil && tc.failure != "" || err != nil && err.Error() != tc.failure {
				t.Fatal("complete_positive_selection_contract_changed")
			}
		})
	}
}

func TestCompleteMVPPositiveEvidence(t *testing.T) {
	p, s := completeMVPPositiveFixture(t)
	evidence, err := completeMVPUbuntu2404Evidence(p, s)
	if err != nil || !strings.Contains(evidence, "packages=complete observedRows=1 installedRows=1 chunks=1") || !strings.Contains(evidence, "services=complete countExact=true observedRows=1 sockets=complete countExact=true observedRows=1") {
		t.Fatal("complete_positive_valid_fixture_rejected")
	}
	for _, tc := range []struct {
		name, failure string
		mutate        func(*completeMVPPackageView, *enrollmentstore.SystemView)
	}{
		{"missing-complete", "complete_positive_package_required", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) { p.Complete = nil }},
		{"wrong-release", "complete_positive_ubuntu2404_required", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) {
			p.Complete.Manifest.Release.Fields.ID = completeMVPPtr("debian")
		}},
		{"unknown-release", "complete_positive_ubuntu2404_required", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) {
			p.Complete.Manifest.Release.Quality = linuxpackages.Unknown
		}},
		{"no-installed", "complete_positive_manifest_invalid_or_empty", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) { p.Complete.Manifest.InstalledCount = 0 }},
		{"no-observed", "complete_positive_manifest_invalid_or_empty", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) { p.Complete.Manifest.ObservedCount = 0 }},
		{"wrong-manifest-binding", "complete_positive_manifest_invalid_or_empty", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) {
			p.Complete.Binding.ManifestHash = strings.Repeat("0", 64)
		}},
		{"expired-generation", "complete_positive_package_required", func(p *completeMVPPackageView, _ *enrollmentstore.SystemView) { p.Complete.State = "expired" }},
		{"system-stale", "complete_positive_system_unavailable_or_unbound", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) { s.Status = "stale" }},
		{"wrong-device", "complete_positive_system_unavailable_or_unbound", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.DeviceID = "different-synthetic-device"
		}},
		{"missing-system", "complete_positive_system_unavailable_or_unbound", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) { s.Latest = nil }},
		{"failed-services", "complete_positive_services_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.Latest.Services.Coverage = systeminventory.Failed
			s.Latest.Services.ObservedCount = nil
			s.Latest.Services.CountExact = false
		}},
		{"empty-services", "complete_positive_services_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.Latest.Services.ObservedCount = completeMVPPtr(uint64(0))
		}},
		{"inexact-services", "complete_positive_services_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) { s.Latest.Services.CountExact = false }},
		{"failed-sockets", "complete_positive_sockets_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.Latest.Sockets.Coverage = systeminventory.Failed
			s.Latest.Sockets.ObservedCount = nil
			s.Latest.Sockets.CountExact = false
		}},
		{"empty-sockets", "complete_positive_sockets_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.Latest.Sockets.ObservedCount = completeMVPPtr(uint64(0))
		}},
		{"inexact-sockets", "complete_positive_sockets_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) { s.Latest.Sockets.CountExact = false }},
		{"unbound-sockets", "complete_positive_sockets_required", func(_ *completeMVPPackageView, s *enrollmentstore.SystemView) {
			s.Latest.Sockets.GenerationID = "sample_" + strings.Repeat("e", 32)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s := completeMVPPositiveFixture(t)
			tc.mutate(&p, &s)
			evidence, err := completeMVPUbuntu2404Evidence(p, s)
			if evidence != "" || err == nil || err.Error() != tc.failure {
				t.Fatal("complete_positive_invalid_fixture_accepted_or_error_not_fixed")
			}
		})
	}
}

// Pure fixture uses the same manifest builder, with no collectors or host I/O.
func completeMVPPositiveFixture(t *testing.T) (completeMVPPackageView, enrollmentstore.SystemView) {
	t.Helper()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	id := "sample_" + strings.Repeat("1", 32)
	m, _, err := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: id, CollectedAt: at,
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: completeMVPPtr("ubuntu"), VersionID: completeMVPPtr("24.04"), VersionCodename: completeMVPPtr("noble")}},
		Rows:    []linuxpackages.PackageRow{{Name: "synthetic-package", Version: "1.0-1", Architecture: "amd64", SourcePackage: "synthetic-package", SourceVersion: "1.0-1", SourceMapping: "binary-default", InstallState: "installed"}}}, nil)
	if err != nil {
		t.Fatal("complete_positive_fixture_build")
	}
	hash, err := fullinventory.ManifestDigest(m)
	if err != nil {
		t.Fatal("complete_positive_fixture_digest")
	}
	device := "agent_" + strings.Repeat("2", 32)
	raw, _ := json.Marshal(map[string]any{"schemaVersion": "tracebolt.complete-package-view.v1", "deviceId": device, "collectionProfile": enrollmentcrypto.CollectionProfileComplete, "status": "available", "complete": map[string]any{"binding": map[string]string{"sequence": "1", "generationId": id, "manifestHash": hash}, "manifest": m, "state": "complete", "completedAt": at.Add(time.Second), "retainedUntil": at.Add(24 * time.Hour)}})
	var p completeMVPPackageView
	if json.Unmarshal(raw, &p) != nil {
		t.Fatal("complete_positive_fixture_view")
	}
	meta := systeminventory.SectionMeta{GenerationID: id, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: completeMVPPtr(uint64(1)), CountExact: true}
	s := enrollmentstore.SystemView{SchemaVersion: "tracebolt.system-inventory-view.v1", CollectionProfile: enrollmentcrypto.CollectionProfileComplete, DeviceID: device, Status: "fresh", Sequence: completeMVPPtr(uint64(1)), ReceivedAt: completeMVPPtr(at.Add(time.Second)), Latest: &enrollmentstore.SystemSnapshotSummary{GenerationID: id, CollectedAt: at, Scope: systeminventory.SnapshotScope, Services: meta, Sockets: meta}}
	return p, s
}

func completeMVPPtr[T any](v T) *T { return &v }
