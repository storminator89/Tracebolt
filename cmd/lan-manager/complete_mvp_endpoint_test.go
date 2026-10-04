//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanclient"
	"localrmm/internal/systemwire"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Pure selection extends the existing opt-ins without widening their defaults.
// All checks run before builds, listeners, enrollment, or actual OS collection.
func completeMVPEndpointGateSelection(base, positive, endpoint string, euid int) (bool, bool, bool, error) {
	if endpoint != "" && endpoint != "1" {
		return false, false, false, errors.New("complete_endpoint_invalid_opt_in")
	}
	if endpoint == "1" && (base != "1" || positive != "1") {
		return false, false, false, errors.New("complete_endpoint_requires_runtime_and_positive_opt_ins")
	}
	enabled, strict, err := completeMVPGateSelection(base, positive, euid)
	return enabled, strict, endpoint == "1" && err == nil, err
}

func completeMVPEndpointServiceIdentity() string {
	return strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
}

// Only the opted-in real-binary gate calls this helper. Both preview and writes
// use the production CLI, with its original identity and quiescence guards.
func completeMVPEndpointConsent(t *testing.T, ctx context.Context, binary, config, enrollmentState, senderState, mode string, enabled bool) {
	t.Helper()
	if mode != "preview" && mode != "enable" && mode != "disable" || enabled != (mode == "enable") {
		t.Fatal("complete_endpoint_invalid_consent_test_mode")
	}
	before := completeMVPEndpointProtectedState(t, enrollmentState, senderState)
	args := []string{"--config", config, "--service-identity", completeMVPEndpointServiceIdentity(), "--endpoint-identity-consent", mode}
	if mode == "enable" {
		args = append(args, "--ack-endpoint-identity")
	}
	command := packageGateCommand(ctx, binary, args...)
	var output packageGateBuffer
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil {
		t.Fatal("complete_endpoint_consent_cli_failed")
	}
	raw := output.Bytes()
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result lanclient.EndpointConsentResult
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.SchemaVersion != "tracebolt.endpoint-identity-consent-result.v1" || result.Mode != mode || result.ExtensionVersion != endpointidentity.SchemaVersion || result.Scope != endpointidentity.Scope || result.Enabled != enabled || !result.ExistingStatePreserved {
		t.Fatal("complete_endpoint_consent_cli_contract")
	}
	if completeMVPEndpointProtectedState(t, enrollmentState, senderState) != before || lanclient.ValidateGuidedHandoff(config) != nil {
		t.Fatal("complete_endpoint_consent_changed_existing_state")
	}
	if !enabled {
		if _, err := os.Lstat(filepath.Join(senderState, "endpoint-identity-consent.json")); !os.IsNotExist(err) {
			t.Fatal("complete_endpoint_consent_sidecar_not_absent")
		}
	}
	t.Logf("endpoint identity consent: stage=%s enabled=%t existingState=unchanged", mode, enabled)
}

// Hashes stay private. Checking complete bytes catches ledger changes that a
// sequence-only assertion would miss, while excluding the opt-in sidecar.
func completeMVPEndpointProtectedState(t *testing.T, enrollmentState, senderState string) [4][sha256.Size]byte {
	t.Helper()
	var out [4][sha256.Size]byte
	out[0] = completeMVPIdentity(t, enrollmentState)
	for n, name := range []string{"state.json", "system/system-state.json", "inventory/ledger.json"} {
		raw, err := os.ReadFile(filepath.Join(senderState, name))
		if err != nil {
			t.Fatal("complete_endpoint_protected_state_unavailable")
		}
		out[n+1] = sha256.Sum256(raw)
		clear(raw)
	}
	return out
}

func completeMVPEndpointNotCollected(t *testing.T, get func(string, any), device string) {
	t.Helper()
	var view enrollmentstore.EndpointIdentityView
	get("/api/devices/"+device+"/inventory/endpoint-identity", &view)
	if view.SchemaVersion != "tracebolt.endpoint-identity-view.v1" || view.DeviceID != device || view.Status != "not_collected" || view.ServerNow.IsZero() || view.MaxAgeSeconds != 120 || view.Sequence != nil || view.ReceivedAt != nil || view.ExpiresAt != nil || view.Latest != nil {
		t.Fatal("complete_endpoint_collected_before_sender")
	}
}

func completeMVPEndpointRead(t *testing.T, get func(string, any), system enrollmentstore.SystemView, stage string) enrollmentstore.EndpointIdentityView {
	t.Helper()
	if stage != "first" && stage != "restart" {
		t.Fatal("complete_endpoint_invalid_evidence_stage")
	}
	var view enrollmentstore.EndpointIdentityView
	get("/api/devices/"+system.DeviceID+"/inventory/endpoint-identity", &view)
	evidence, err := completeMVPEndpointEvidence(view, system)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("endpoint identity observation: stage=%s %s", stage, evidence)
	return view
}

// Pure evidence projection: success must come from manager-delivered values.
// Coverage can be complete with zero addresses in one family, but the total
// assigned-address evidence must be positive. No primary or reachable IP is
// inferred, and no hostname, interface name, address, generation or ID is logged.
func completeMVPEndpointEvidence(v enrollmentstore.EndpointIdentityView, s enrollmentstore.SystemView) (string, error) {
	fail := func(code string) (string, error) { return "", errors.New(code) }
	if v.SchemaVersion != "tracebolt.endpoint-identity-view.v1" || v.Status != "fresh" || v.MaxAgeSeconds != 120 || v.DeviceID == "" || v.DeviceID != s.DeviceID || v.Sequence == nil || *v.Sequence == 0 || s.Sequence == nil || *v.Sequence != *s.Sequence || s.Latest == nil || v.Latest == nil || v.ReceivedAt == nil || v.ReceivedAt.IsZero() || v.ExpiresAt == nil || v.ServerNow.IsZero() {
		return fail("complete_endpoint_view_unavailable_or_unbound")
	}
	latest := v.Latest
	generation, err := systemwire.GenerationID(v.DeviceID, *v.Sequence)
	if err != nil || endpointidentity.Validate(*latest) != nil || latest.GenerationID != generation || latest.GenerationID != s.Latest.GenerationID || !latest.CollectedAt.Equal(s.Latest.CollectedAt) || v.ReceivedAt.Before(latest.CollectedAt) || v.ServerNow.Before(*v.ReceivedAt) || v.ServerNow.Sub(latest.CollectedAt) > 120*time.Second || !v.ExpiresAt.Equal(latest.CollectedAt.Add(enrollmentstore.SystemRetention)) {
		return fail("complete_endpoint_snapshot_invalid_or_unbound")
	}
	if latest.ReportedHostname.Coverage != endpointidentity.Complete || latest.ReportedHostname.Reason != endpointidentity.ReasonNone || latest.ReportedHostname.Value == nil || *latest.ReportedHostname.Value == "" {
		return fail("complete_endpoint_hostname_required")
	}
	if latest.Interfaces.Meta.Coverage != endpointidentity.Complete || len(latest.Interfaces.Items) == 0 {
		return fail("complete_endpoint_interfaces_required")
	}
	ipv4, ipv6 := 0, 0
	for _, row := range latest.Interfaces.Items {
		if row.Addresses.IPv4.Meta.Coverage != endpointidentity.Complete || row.Addresses.IPv6.Meta.Coverage != endpointidentity.Complete {
			return fail("complete_endpoint_addresses_required")
		}
		ipv4 += len(row.Addresses.IPv4.Items)
		ipv6 += len(row.Addresses.IPv6.Items)
	}
	if ipv4+ipv6 == 0 {
		return fail("complete_endpoint_addresses_required")
	}
	return fmt.Sprintf("hostname=complete interfaces=complete countExact=true observedRows=%d addresses=complete countExact=true ipv4Rows=%d ipv6Rows=%d assignedRows=%d", len(latest.Interfaces.Items), ipv4, ipv6, ipv4+ipv6), nil
}

func completeMVPEndpointAdvanced(before, after enrollmentstore.EndpointIdentityView, trackedSequence uint64) error {
	if before.Sequence == nil || after.Sequence == nil || before.Latest == nil || after.Latest == nil || before.ReceivedAt == nil || after.ReceivedAt == nil || *after.Sequence != trackedSequence || *after.Sequence <= *before.Sequence || after.Latest.GenerationID == before.Latest.GenerationID || !after.Latest.CollectedAt.After(before.Latest.CollectedAt) || !after.ReceivedAt.After(*before.ReceivedAt) {
		return errors.New("complete_endpoint_restart_did_not_advance_generation_time_and_sequence")
	}
	return nil
}

func completeMVPEndpointRetained(before, after enrollmentstore.EndpointIdentityView, ordinary enrollmentstore.SystemView, trackedSequence uint64) error {
	fail := func() error { return errors.New("complete_endpoint_disabled_restart_refreshed_or_replaced_metadata") }
	if before.Sequence == nil || before.Latest == nil || before.ReceivedAt == nil || before.ExpiresAt == nil || after.Sequence == nil || after.Latest == nil || after.ReceivedAt == nil || after.ExpiresAt == nil || ordinary.Sequence == nil || ordinary.Latest == nil {
		return fail()
	}
	if after.SchemaVersion != before.SchemaVersion || after.DeviceID != before.DeviceID || after.DeviceID != ordinary.DeviceID || after.MaxAgeSeconds != before.MaxAgeSeconds || *after.Sequence != *before.Sequence || !after.ReceivedAt.Equal(*before.ReceivedAt) || !after.ExpiresAt.Equal(*before.ExpiresAt) || !reflect.DeepEqual(after.Latest, before.Latest) || !after.ServerNow.After(before.ServerNow) || *ordinary.Sequence != trackedSequence || *ordinary.Sequence <= *before.Sequence || !ordinary.Latest.CollectedAt.After(before.Latest.CollectedAt) || ordinary.Latest.GenerationID == before.Latest.GenerationID {
		return fail()
	}
	status := "fresh"
	if after.ServerNow.Sub(before.Latest.CollectedAt) > 120*time.Second {
		status = "stale"
	}
	if after.Status != status || !after.ServerNow.Before(*before.ExpiresAt) {
		return fail()
	}
	return nil
}

func TestCompleteMVPEndpointGateSelection(t *testing.T) {
	for _, tc := range []struct {
		name, base, positive, endpoint string
		euid                           int
		enabled, strict, identity      bool
		failure                        string
	}{
		{"default", "", "", "", 1000, false, false, false, ""},
		{"default-root", "", "", "", 0, false, false, false, ""},
		{"old-base", "1", "", "", 1000, true, false, false, ""},
		{"old-positive", "1", "1", "", 1000, true, true, false, ""},
		{"endpoint", "1", "1", "1", 1000, true, true, true, ""},
		{"endpoint-invalid", "1", "1", "true", 1000, false, false, false, "complete_endpoint_invalid_opt_in"},
		{"endpoint-invalid-no-base", "", "", "true", 1000, false, false, false, "complete_endpoint_invalid_opt_in"},
		{"endpoint-without-base", "", "1", "1", 1000, false, false, false, "complete_endpoint_requires_runtime_and_positive_opt_ins"},
		{"endpoint-without-positive", "1", "", "1", 1000, false, false, false, "complete_endpoint_requires_runtime_and_positive_opt_ins"},
		{"endpoint-only", "", "", "1", 1000, false, false, false, "complete_endpoint_requires_runtime_and_positive_opt_ins"},
		{"endpoint-root", "1", "1", "1", 0, false, false, false, "complete_runtime_requires_nonprivileged_execution"},
		{"endpoint-unknown-identity", "1", "1", "1", -1, false, false, false, "complete_runtime_requires_nonprivileged_execution"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, strict, identity, err := completeMVPEndpointGateSelection(tc.base, tc.positive, tc.endpoint, tc.euid)
			if enabled != tc.enabled || strict != tc.strict || identity != tc.identity || err == nil && tc.failure != "" || err != nil && err.Error() != tc.failure {
				t.Fatal("complete_endpoint_selection_contract_changed")
			}
		})
	}
}

func TestCompleteMVPEndpointEvidence(t *testing.T) {
	v, s := completeMVPEndpointFixture(t, 1)
	want := "hostname=complete interfaces=complete countExact=true observedRows=1 addresses=complete countExact=true ipv4Rows=1 ipv6Rows=1 assignedRows=2"
	if evidence, err := completeMVPEndpointEvidence(v, s); err != nil || evidence != want {
		t.Fatal("complete_endpoint_valid_fixture_rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*enrollmentstore.EndpointIdentityView)
	}{
		{"missing-view", func(v *enrollmentstore.EndpointIdentityView) { v.Latest = nil }},
		{"wrong-device", func(v *enrollmentstore.EndpointIdentityView) { v.DeviceID = "agent_" + strings.Repeat("9", 32) }},
		{"missing-sequence", func(v *enrollmentstore.EndpointIdentityView) { v.Sequence = nil }},
		{"wrong-sequence", func(v *enrollmentstore.EndpointIdentityView) { *v.Sequence++ }},
		{"wrong-generation", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.GenerationID = "sample_" + strings.Repeat("9", 32)
		}},
		{"wrong-time", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.CollectedAt = v.Latest.CollectedAt.Add(time.Second)
		}},
		{"future-receipt", func(v *enrollmentstore.EndpointIdentityView) { *v.ReceivedAt = v.ServerNow.Add(time.Second) }},
		{"wrong-expiry", func(v *enrollmentstore.EndpointIdentityView) { *v.ExpiresAt = v.ExpiresAt.Add(time.Second) }},
		{"false-fresh", func(v *enrollmentstore.EndpointIdentityView) { v.ServerNow = v.ServerNow.Add(3 * time.Minute) }},
		{"disabled-attestation", func(v *enrollmentstore.EndpointIdentityView) { v.Status = "disabled" }},
		{"hostname-failed", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Failed, Reason: endpointidentity.ReasonReadFailed}
		}},
		{"hostname-empty", func(v *enrollmentstore.EndpointIdentityView) { v.Latest.ReportedHostname.Value = completeMVPPtr("") }},
		{"interfaces-empty", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.Interfaces.Items = []endpointidentity.Interface{}
			v.Latest.Interfaces.Meta = completeMVPEndpointMeta(0)
		}},
		{"interface-inexact", func(v *enrollmentstore.EndpointIdentityView) { v.Latest.Interfaces.Meta.CountExact = false }},
		{"family-failed", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.Interfaces.Items[0].Addresses.IPv6 = endpointidentity.AddressSection{Meta: endpointidentity.SectionMeta{Coverage: endpointidentity.Failed, Reason: endpointidentity.ReasonReadFailed}, Items: []endpointidentity.Address{}}
			v.Latest.Interfaces.Meta.Coverage = endpointidentity.Partial
			v.Latest.Interfaces.Meta.Reason = endpointidentity.ReasonAddressUnavailable
		}},
		{"addresses-empty", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.Interfaces.Items[0].Addresses = endpointidentity.AddressSet{IPv4: endpointidentity.AddressSection{Meta: completeMVPEndpointMeta(0), Items: []endpointidentity.Address{}}, IPv6: endpointidentity.AddressSection{Meta: completeMVPEndpointMeta(0), Items: []endpointidentity.Address{}}}
		}},
		{"address-invalid", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.Interfaces.Items[0].Addresses.IPv4.Items[0].Address = "not-an-address"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, s := completeMVPEndpointFixture(t, 1)
			tc.mutate(&v)
			if evidence, err := completeMVPEndpointEvidence(v, s); evidence != "" || err == nil || !strings.HasPrefix(err.Error(), "complete_endpoint_") {
				t.Fatal("complete_endpoint_invalid_fixture_accepted_or_evidence_not_fixed")
			}
		})
	}
}

func TestCompleteMVPEndpointRestartAndRetainedAge(t *testing.T) {
	first, _ := completeMVPEndpointFixture(t, 1)
	second, _ := completeMVPEndpointFixture(t, 2)
	if completeMVPEndpointAdvanced(first, second, 2) != nil || completeMVPEndpointAdvanced(first, first, 2) == nil {
		t.Fatal("complete_endpoint_restart_fixture_contract")
	}
	_, ordinary := completeMVPEndpointFixture(t, 3)
	for _, tc := range []struct {
		name   string
		mutate func(*enrollmentstore.EndpointIdentityView)
	}{
		{"sequence", func(v *enrollmentstore.EndpointIdentityView) { *v.Sequence++ }},
		{"receipt", func(v *enrollmentstore.EndpointIdentityView) { *v.ReceivedAt = v.ReceivedAt.Add(time.Second) }},
		{"expiry", func(v *enrollmentstore.EndpointIdentityView) { *v.ExpiresAt = v.ExpiresAt.Add(time.Second) }},
		{"payload", func(v *enrollmentstore.EndpointIdentityView) {
			v.Latest.ReportedHostname.Value = completeMVPPtr("different-fixture")
		}},
		{"missing-payload", func(v *enrollmentstore.EndpointIdentityView) { v.Latest = nil }},
		{"disabled-attestation", func(v *enrollmentstore.EndpointIdentityView) { v.Status = "disabled" }},
		{"time-not-advanced", func(v *enrollmentstore.EndpointIdentityView) { v.ServerNow = second.ServerNow }},
		{"false-fresh", func(v *enrollmentstore.EndpointIdentityView) { v.ServerNow = v.ServerNow.Add(3 * time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retained, _ := completeMVPEndpointFixture(t, 2)
			retained.ServerNow = retained.ServerNow.Add(time.Second)
			if completeMVPEndpointRetained(second, retained, ordinary, 3) != nil {
				t.Fatal("complete_endpoint_retained_fixture_rejected")
			}
			tc.mutate(&retained)
			if completeMVPEndpointRetained(second, retained, ordinary, 3) == nil {
				t.Fatal("complete_endpoint_refreshed_fixture_accepted")
			}
		})
	}
	retained, _ := completeMVPEndpointFixture(t, 2)
	retained.ServerNow = retained.ServerNow.Add(3 * time.Minute)
	retained.Status = "stale"
	if completeMVPEndpointRetained(second, retained, ordinary, 3) != nil {
		t.Fatal("complete_endpoint_original_age_stale_fixture_rejected")
	}
}

// Entirely inert fixtures. They never invoke any endpoint provider, binary,
// listener, filesystem state, or actual hostname/interface source.
func completeMVPEndpointFixture(t *testing.T, sequence uint64) (enrollmentstore.EndpointIdentityView, enrollmentstore.SystemView) {
	t.Helper()
	_, system := completeMVPPositiveFixture(t)
	generation, err := systemwire.GenerationID(system.DeviceID, sequence)
	if err != nil {
		t.Fatal("complete_endpoint_fixture_generation")
	}
	at := system.Latest.CollectedAt.Add(time.Duration(sequence) * time.Second)
	system.Sequence = completeMVPPtr(sequence)
	system.Latest.GenerationID = generation
	system.Latest.CollectedAt = at
	latest := endpointidentity.Snapshot{SchemaVersion: endpointidentity.SchemaVersion, GenerationID: generation, CollectedAt: at, Scope: endpointidentity.Scope, ReportedHostname: endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: completeMVPPtr("synthetic-fixture-host")}, Interfaces: endpointidentity.InterfaceSection{Meta: completeMVPEndpointMeta(1), Items: []endpointidentity.Interface{{Index: 1, Name: "fixture0", Up: true, Loopback: true, HardwareKind: "unknown", Addresses: endpointidentity.AddressSet{IPv4: endpointidentity.AddressSection{Meta: completeMVPEndpointMeta(1), Items: []endpointidentity.Address{{Family: "ipv4", Address: "127.0.0.1", Scope: "loopback"}}}, IPv6: endpointidentity.AddressSection{Meta: completeMVPEndpointMeta(1), Items: []endpointidentity.Address{{Family: "ipv6", Address: "::1", Scope: "loopback"}}}}}}}}
	view := enrollmentstore.EndpointIdentityView{SchemaVersion: "tracebolt.endpoint-identity-view.v1", DeviceID: system.DeviceID, Status: "fresh", ServerNow: at.Add(2 * time.Second), MaxAgeSeconds: 120, Sequence: completeMVPPtr(sequence), ReceivedAt: completeMVPPtr(at.Add(time.Second)), ExpiresAt: completeMVPPtr(at.Add(enrollmentstore.SystemRetention)), Latest: &latest}
	return view, system
}

func completeMVPEndpointMeta(n uint32) endpointidentity.SectionMeta {
	return endpointidentity.SectionMeta{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, ObservedCount: completeMVPPtr(n), CountExact: true}
}
