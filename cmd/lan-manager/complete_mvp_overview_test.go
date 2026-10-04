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
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Selection is pure and precedes all effects. With the fourth flag absent,
// behavior and errors are delegated unchanged to the existing endpoint gate.
func completeMVPOverviewGateSelection(base, positive, endpoint, overview string, euid int) (bool, bool, bool, bool, error) {
	if overview != "" && overview != "1" {
		return false, false, false, false, errors.New("complete_overview_invalid_opt_in")
	}
	if overview == "1" && (base != "1" || positive != "1" || endpoint != "1") {
		return false, false, false, false, errors.New("complete_overview_requires_runtime_positive_endpoint_opt_ins")
	}
	enabled, strict, identity, err := completeMVPEndpointGateSelection(base, positive, endpoint, euid)
	return enabled, strict, identity, overview == "1" && err == nil, err
}

type completeMVPOverviewBinding struct{ Section, Sequence, GenerationID, ManifestHash string }
type completeMVPOverviewComplete struct {
	Binding                    completeMVPOverviewBinding
	Manifest                   overviewgeneration.Manifest
	State                      string
	CompletedAt, RetainedUntil time.Time
}
type completeMVPOverviewTransfer struct {
	Binding                           completeMVPOverviewBinding
	Manifest                          overviewgeneration.Manifest
	State                             string
	DeclaredRows, AcceptedRows        uint64
	ExpectedChunks, AcceptedChunks    uint32
	CollectedAt, StartedAt, ExpiresAt time.Time
}
type completeMVPOverviewFailure struct {
	Sequence, GenerationID, Reason string
	AttemptedAt, ReceivedAt        time.Time
}
type completeMVPOverviewSection struct {
	Status   string
	Complete *completeMVPOverviewComplete
	Transfer *completeMVPOverviewTransfer
	Failure  *completeMVPOverviewFailure
}
type completeMVPOverviewView struct {
	SchemaVersion, DeviceID, CollectionProfile, Status string
	ServerNow                                          time.Time
	Processes, Volumes                                 completeMVPOverviewSection
}
type completeMVPOverviewPage struct {
	SchemaVersion, DeviceID, Section        string
	ServerNow                               time.Time
	Binding                                 completeMVPOverviewBinding
	Manifest                                overviewgeneration.Manifest
	CollectedAt, CompletedAt, RetainedUntil time.Time
	TotalRows                               uint64
	Items                                   []overviewgeneration.Row
	ScannedRows                             int
	Exhausted, SearchIncomplete             bool
	NextCursor                              string
	CursorExpiresAt                         time.Time
}
type completeMVPOverviewObservation struct {
	view                      completeMVPOverviewView
	processPages, volumePages int
}

// Only the four-flag native gate calls this command helper. The sender is
// stopped, and the production CLI rechecks original identity/ownership guards.
func completeMVPOverviewConsent(t *testing.T, ctx context.Context, binary, config, enrollmentState, senderState, mode string, enabled bool) {
	t.Helper()
	if mode != "preview" && mode != "enable" && mode != "disable" || enabled != (mode == "enable") {
		t.Fatal("complete_overview_invalid_consent_mode")
	}
	before := completeMVPEndpointProtectedState(t, enrollmentState, senderState)
	endpointRaw, e := os.ReadFile(filepath.Join(senderState, "endpoint-identity-consent.json"))
	if e != nil {
		t.Fatal("complete_overview_requires_existing_endpoint_consent")
	}
	endpointHash := sha256.Sum256(endpointRaw)
	clear(endpointRaw)
	var domains [2][sha256.Size]byte
	for i, section := range []string{"processes", "volumes"} {
		raw, e := os.ReadFile(filepath.Join(senderState, "overview-"+section, "ledger.json"))
		if mode == "disable" {
			if e != nil {
				t.Fatal("complete_overview_domain_missing")
			}
			domains[i] = sha256.Sum256(raw)
		} else if !os.IsNotExist(e) {
			t.Fatal("complete_overview_expected_fresh_domains")
		}
		clear(raw)
	}
	args := []string{"--config", config, "--service-identity", completeMVPEndpointServiceIdentity(), "--complete-overview-consent", mode}
	if enabled {
		args = append(args, "--ack-complete-overview")
	}
	command := packageGateCommand(ctx, binary, args...)
	var output packageGateBuffer
	command.Stdout = &output
	command.Stderr = io.Discard
	if command.Run() != nil {
		t.Fatal("complete_overview_consent_cli_failed")
	}
	raw := output.Bytes()
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result lanclient.OverviewConsentResult
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.SchemaVersion != "tracebolt.complete-overview-consent-result.v1" || result.Mode != mode || result.ExtensionVersion != completeoverview.SchemaVersion || result.Scope != "full-agent-visible-processes-and-mounted-filesystems" || result.CaptureIntervalSeconds != 60 || result.Enabled != enabled || !result.ExistingStatePreserved || !strings.Contains(result.Disclosure, "sensitive") || !strings.Contains(result.Disclosure, "namespaces") {
		t.Fatal("complete_overview_consent_cli_contract")
	}
	if completeMVPEndpointProtectedState(t, enrollmentState, senderState) != before || lanclient.ValidateGuidedHandoff(config) != nil {
		t.Fatal("complete_overview_consent_changed_existing_state")
	}
	endpointRaw, e = os.ReadFile(filepath.Join(senderState, "endpoint-identity-consent.json"))
	if e != nil || sha256.Sum256(endpointRaw) != endpointHash {
		t.Fatal("complete_overview_consent_changed_endpoint_consent")
	}
	clear(endpointRaw)
	for i, section := range []string{"processes", "volumes"} {
		raw, e := os.ReadFile(filepath.Join(senderState, "overview-"+section, "ledger.json"))
		if mode == "preview" {
			if !os.IsNotExist(e) {
				t.Fatal("complete_overview_preview_created_domain")
			}
		} else {
			var state struct {
				Section, Phase string
				Floor          uint64
			}
			if e != nil || json.Unmarshal(raw, &state) != nil || state.Section != section {
				t.Fatal("complete_overview_domain_contract")
			}
			if mode == "enable" && (state.Floor != 0 || state.Phase != "idle") {
				t.Fatal("complete_overview_enable_collected_before_sender")
			}
			if mode == "disable" && sha256.Sum256(raw) != domains[i] {
				t.Fatal("complete_overview_disable_changed_consumed_floor")
			}
		}
		clear(raw)
	}
	if !enabled {
		if _, e := os.Lstat(filepath.Join(senderState, "complete-overview-consent.json")); !os.IsNotExist(e) {
			t.Fatal("complete_overview_consent_sidecar_not_absent")
		}
	}
	t.Logf("complete overview consent: stage=%s enabled=%t existingState=unchanged", mode, enabled)
}
func completeMVPOverviewNotCollected(t *testing.T, get func(string, any), device string) {
	t.Helper()
	var view completeMVPOverviewView
	get("/api/devices/"+device+"/inventory/overview", &view)
	if view.SchemaVersion != "tracebolt.complete-overview-view.v1" || view.DeviceID != device || view.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || view.ServerNow.IsZero() || view.Status != "awaiting" {
		t.Fatal("complete_overview_precollection_view_contract")
	}
	for _, section := range []completeMVPOverviewSection{view.Processes, view.Volumes} {
		if section.Status != "awaiting" || section.Complete != nil || section.Transfer != nil || section.Failure != nil {
			t.Fatal("complete_overview_collected_before_sender")
		}
	}
}
func completeMVPOverviewReady(t *testing.T, get func(string, any), device string) bool {
	t.Helper()
	var view completeMVPOverviewView
	get("/api/devices/"+device+"/inventory/overview", &view)
	if view.SchemaVersion != "tracebolt.complete-overview-view.v1" || view.DeviceID != device || view.Processes.Failure != nil || view.Volumes.Failure != nil {
		t.Fatal("complete_overview_positive_capture_required")
	}
	return view.Processes.Complete != nil && view.Volumes.Complete != nil
}

// Pure projection validates delivered metadata. All failures are fixed codes;
// process identities, names, mount paths and generation IDs are never printed.
func completeMVPOverviewEvidence(v completeMVPOverviewView) (string, error) {
	bad := func() (string, error) { return "", errors.New("complete_overview_delivered_metadata_invalid") }
	if v.SchemaVersion != "tracebolt.complete-overview-view.v1" || v.DeviceID == "" || v.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || v.Status != "available" || v.ServerNow.IsZero() {
		return bad()
	}
	for _, pair := range []struct {
		section string
		view    completeMVPOverviewSection
	}{{"processes", v.Processes}, {"volumes", v.Volumes}} {
		s := pair.view
		if s.Status != "available" || s.Complete == nil || s.Transfer == nil || s.Failure != nil {
			return bad()
		}
		c, tr := s.Complete, s.Transfer
		m := c.Manifest
		hash, e := overviewgeneration.ManifestDigest(m)
		seq, se := strconv.ParseUint(c.Binding.Sequence, 10, 64)
		id, ie := overviewwire.GenerationID(v.DeviceID, pair.section, seq)
		meta := m.SelectedMeta()
		if e != nil || se != nil || ie != nil || seq == 0 || strconv.FormatUint(seq, 10) != c.Binding.Sequence || c.Binding.Section != pair.section || c.Binding.GenerationID != id || m.GenerationID != id || m.Section != pair.section || c.Binding.ManifestHash != hash || m.ObservedCount == 0 || m.ChunkCount == 0 || meta.Coverage != completeoverview.Complete || meta.Reason != completeoverview.ReasonNone || !meta.CountExact || meta.ObservedCount == nil || *meta.ObservedCount != m.ObservedCount || c.State != "complete" || c.CompletedAt.Before(m.CaptureFinishedAt) || c.CompletedAt.After(v.ServerNow) || !c.RetainedUntil.Equal(m.CollectedAt.Add(overviewledger.ObservationTTL)) || !v.ServerNow.Before(c.RetainedUntil) {
			return bad()
		}
		if tr.State != "complete" || tr.Binding != c.Binding || !reflect.DeepEqual(tr.Manifest, m) || tr.DeclaredRows != m.ObservedCount || tr.AcceptedRows != m.ObservedCount || tr.ExpectedChunks != m.ChunkCount || tr.AcceptedChunks != m.ChunkCount || !tr.CollectedAt.Equal(m.CollectedAt) || tr.StartedAt.Before(m.CaptureFinishedAt) || tr.StartedAt.After(c.CompletedAt) || !tr.ExpiresAt.Equal(c.RetainedUntil) {
			return bad()
		}
	}
	p, vv := v.Processes.Complete.Manifest, v.Volumes.Complete.Manifest
	if p.CaptureGenerationID != vv.CaptureGenerationID || !p.CaptureStartedAt.Equal(vv.CaptureStartedAt) || !p.CaptureFinishedAt.Equal(vv.CaptureFinishedAt) || !reflect.DeepEqual(p.Processes, vv.Processes) || !reflect.DeepEqual(p.Volumes, vv.Volumes) || p.CanonicalSnapshotBytes != vv.CanonicalSnapshotBytes {
		return bad()
	}
	return fmt.Sprintf("processes=complete countExact=true processRows=%d volumes=complete countExact=true volumeRows=%d", p.ObservedCount, vv.ObservedCount), nil
}

func completeMVPOverviewRead(t *testing.T, get func(string, any), call func(string, any, string) (int, []byte), csrf, device string) completeMVPOverviewObservation {
	t.Helper()
	var view completeMVPOverviewView
	get("/api/devices/"+device+"/inventory/overview", &view)
	evidence, e := completeMVPOverviewEvidence(view)
	if e != nil {
		t.Fatal(e)
	}
	processes, pp := completeMVPOverviewRows(t, call, csrf, view, "processes", view.Processes.Complete)
	volumes, vp := completeMVPOverviewRows(t, call, csrf, view, "volumes", view.Volumes.Complete)
	if e = completeMVPOverviewValidateRows(view, processes, volumes); e != nil {
		t.Fatal(e)
	}
	t.Logf("complete overview observation: stage=first %s processPages=%d volumePages=%d manifest=validated", evidence, pp, vp)
	return completeMVPOverviewObservation{view, pp, vp}
}
func completeMVPOverviewRows(t *testing.T, call func(string, any, string) (int, []byte), csrf string, view completeMVPOverviewView, section string, complete *completeMVPOverviewComplete) ([]overviewgeneration.Row, int) {
	t.Helper()
	rows := []overviewgeneration.Row{}
	cursor := ""
	seen := map[string]bool{}
	pages := 0
	totalBytes := 0
	for {
		status, raw := call("/api/devices/"+view.DeviceID+"/inventory/overview/query", map[string]any{"section": section, "generationId": complete.Binding.GenerationID, "cursor": cursor, "search": "", "limit": 100}, csrf)
		var page completeMVPOverviewPage
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if status != http.StatusOK || len(raw) > 256<<10 || decoder.Decode(&page) != nil || decoder.Decode(new(any)) != io.EOF {
			clear(raw)
			t.Fatal("complete_overview_page_contract")
		}
		clear(raw)
		if e := completeMVPOverviewPageValid(view, section, complete, page); e != nil {
			t.Fatal(e)
		}
		for _, row := range page.Items {
			b, _ := json.Marshal(row)
			totalBytes += len(b) + 1
			if totalBytes > overviewgeneration.MaxCanonicalRowBytes {
				t.Fatal("complete_overview_page_bytes_exceeded")
			}
		}
		rows = append(rows, page.Items...)
		pages++
		if uint64(len(rows)) > complete.Manifest.ObservedCount || pages > int(complete.Manifest.ObservedCount) {
			t.Fatal("complete_overview_page_row_bound")
		}
		if page.Exhausted {
			if uint64(len(rows)) != complete.Manifest.ObservedCount {
				t.Fatal("complete_overview_page_count_mismatch")
			}
			return rows, pages
		}
		if seen[page.NextCursor] {
			t.Fatal("complete_overview_page_cursor_repeated")
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
}
func completeMVPOverviewPageValid(view completeMVPOverviewView, section string, c *completeMVPOverviewComplete, p completeMVPOverviewPage) error {
	bad := errors.New("complete_overview_page_metadata_invalid")
	if c == nil || p.SchemaVersion != "tracebolt.complete-overview-page.v1" || p.DeviceID != view.DeviceID || p.Section != section || p.Binding != c.Binding || !reflect.DeepEqual(p.Manifest, c.Manifest) || !p.CollectedAt.Equal(c.Manifest.CollectedAt) || !p.CompletedAt.Equal(c.CompletedAt) || !p.RetainedUntil.Equal(c.RetainedUntil) || p.TotalRows != c.Manifest.ObservedCount || p.ServerNow.Before(view.ServerNow) || !p.ServerNow.Before(p.RetainedUntil) || !p.ServerNow.Before(p.CursorExpiresAt) || p.CursorExpiresAt.After(p.RetainedUntil) || p.SearchIncomplete || p.Items == nil || len(p.Items) == 0 || len(p.Items) > 100 || p.ScannedRows != len(p.Items) || p.Exhausted != (p.NextCursor == "") || len(p.NextCursor) > overviewledger.MaxCursorBytes {
		return bad
	}
	for _, row := range p.Items {
		if overviewgeneration.ValidateRow(row) != nil || (section == "processes") != (row.Process != nil) {
			return bad
		}
	}
	return nil
}
func completeMVPOverviewValidateRows(v completeMVPOverviewView, processes, volumes []overviewgeneration.Row) error {
	bad := errors.New("complete_overview_full_rows_manifest_mismatch")
	if _, e := completeMVPOverviewEvidence(v); e != nil {
		return bad
	}
	p := v.Processes.Complete.Manifest
	source := completeoverview.Snapshot{SchemaVersion: completeoverview.SchemaVersion, GenerationID: p.CaptureGenerationID, CaptureStartedAt: p.CaptureStartedAt, CaptureFinishedAt: p.CaptureFinishedAt, Scope: p.Scope, Processes: completeoverview.ProcessSection{Meta: p.Processes, Items: []completeoverview.Process{}}, Volumes: completeoverview.VolumeSection{Meta: p.Volumes, Items: []completeoverview.Volume{}}}
	for _, row := range processes {
		if row.Process == nil || row.Volume != nil {
			return bad
		}
		source.Processes.Items = append(source.Processes.Items, *row.Process)
	}
	for _, row := range volumes {
		if row.Volume == nil || row.Process != nil {
			return bad
		}
		source.Volumes.Items = append(source.Volumes.Items, *row.Volume)
	}
	if completeoverview.Validate(source) != nil {
		return bad
	}
	for _, c := range []*completeMVPOverviewComplete{v.Processes.Complete, v.Volumes.Complete} {
		m, _, e := overviewgeneration.Build(context.Background(), source, c.Manifest.Section, c.Binding.GenerationID, nil)
		if e != nil || !reflect.DeepEqual(m, c.Manifest) {
			return bad
		}
	}
	return nil
}
func completeMVPOverviewRetained(t *testing.T, get func(string, any), device string, before completeMVPOverviewObservation, prior, ordinary completeMVPObservation, stage string, trackedSequence uint64) completeMVPOverviewObservation {
	t.Helper()
	if stage != "restart" && stage != "disabled_restart" {
		t.Fatal("complete_overview_invalid_retained_stage")
	}
	var after completeMVPOverviewView
	get("/api/devices/"+device+"/inventory/overview", &after)
	if e := completeMVPOverviewRetainedEvidence(before.view, after, prior.metricSequence, ordinary.metricSequence, prior.metricAt, ordinary.metricAt, stage, trackedSequence); e != nil {
		t.Fatal(e)
	}
	t.Logf("complete overview retained: stage=%s ordinary=advanced generations=unchanged capture=original_age receipt=unchanged expiry=unchanged rows=unchanged", stage)
	return completeMVPOverviewObservation{after, before.processPages, before.volumePages}
}
func completeMVPOverviewRetainedEvidence(before, after completeMVPOverviewView, oldSeq, newSeq uint64, oldAt, newAt time.Time, stage string, trackedSequence uint64) error {
	bad := errors.New("complete_overview_restart_refreshed_or_replaced_generation")
	if stage != "restart" && stage != "disabled_restart" {
		return bad
	}
	if _, e := completeMVPOverviewEvidence(before); e != nil {
		return bad
	}
	if _, e := completeMVPOverviewEvidence(after); e != nil {
		return bad
	}
	if before.DeviceID != after.DeviceID || !after.ServerNow.After(before.ServerNow) || newSeq != trackedSequence || newSeq <= oldSeq || !newAt.After(oldAt) || !reflect.DeepEqual(before.Processes, after.Processes) || !reflect.DeepEqual(before.Volumes, after.Volumes) {
		return bad
	}
	if stage == "restart" && !after.ServerNow.Before(before.Processes.Complete.Manifest.CollectedAt.Add(time.Minute)) {
		return bad
	}
	return nil
}

func TestCompleteMVPOverviewGateSelection(t *testing.T) {
	for _, tc := range []struct {
		base, positive, endpoint string
		euid                     int
	}{{"", "", "", 0}, {"", "", "", 1000}, {"1", "", "", 1000}, {"1", "1", "", 1000}, {"1", "1", "1", 1000}, {"1", "1", "1", 0}, {"1", "1", "true", 1000}, {"true", "1", "1", 1000}} {
		a, b, c, e := completeMVPEndpointGateSelection(tc.base, tc.positive, tc.endpoint, tc.euid)
		aa, bb, cc, overview, ee := completeMVPOverviewGateSelection(tc.base, tc.positive, tc.endpoint, "", tc.euid)
		if a != aa || b != bb || c != cc || overview || fmt.Sprint(e) != fmt.Sprint(ee) {
			t.Fatal("complete_overview_changed_existing_gate_selection")
		}
	}
	for _, tc := range []struct {
		base, positive, endpoint, overview string
		euid                               int
		failure                            string
	}{{"1", "1", "1", "1", 1000, ""}, {"1", "1", "1", "true", 1000, "complete_overview_invalid_opt_in"}, {"", "1", "1", "1", 1000, "complete_overview_requires_runtime_positive_endpoint_opt_ins"}, {"1", "", "1", "1", 1000, "complete_overview_requires_runtime_positive_endpoint_opt_ins"}, {"1", "1", "", "1", 1000, "complete_overview_requires_runtime_positive_endpoint_opt_ins"}, {"1", "1", "1", "1", 0, "complete_runtime_requires_nonprivileged_execution"}, {"1", "1", "1", "1", -1, "complete_runtime_requires_nonprivileged_execution"}} {
		enabled, positive, endpoint, overview, err := completeMVPOverviewGateSelection(tc.base, tc.positive, tc.endpoint, tc.overview, tc.euid)
		if tc.failure == "" {
			if err != nil || !enabled || !positive || !endpoint || !overview {
				t.Fatal("complete_overview_opt_in_not_selected")
			}
		} else if err == nil || err.Error() != tc.failure || enabled || positive || endpoint || overview {
			t.Fatal("complete_overview_opt_in_guard_failed")
		}
	}
}

// Pure fixtures exercise inspectors only, never providers, binaries, listeners,
// enrollment, state directories or OS-source reads. They emit no native markers.
func completeMVPOverviewFixture(t *testing.T) (completeMVPOverviewView, []overviewgeneration.Row, []overviewgeneration.Row) {
	t.Helper()
	at := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	device := "agent_" + strings.Repeat("a", 32)
	capture := "sample_" + strings.Repeat("b", 32)
	n := uint64(2)
	source := completeoverview.Snapshot{SchemaVersion: completeoverview.SchemaVersion, GenerationID: capture, CaptureStartedAt: at, CaptureFinishedAt: at.Add(time.Second), Scope: completeoverview.SnapshotScope, Processes: completeoverview.ProcessSection{Meta: completeoverview.SectionMeta{GenerationID: capture, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &n, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: n}}, Items: []completeoverview.Process{{PID: 1, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}, {PID: 2, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}}}, Volumes: completeoverview.VolumeSection{Meta: completeoverview.SectionMeta{GenerationID: capture, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &n, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{NotApplicable: n}}, Items: []completeoverview.Volume{{ID: "mount_2", MountPoint: "/fixture/a", Filesystem: "proc", Kind: "virtual", FilesystemGroup: "fs_0_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}}, {ID: "mount_1", MountPoint: "/fixture/b", Filesystem: "proc", Kind: "virtual", FilesystemGroup: "fs_0_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}}}}}
	view := completeMVPOverviewView{SchemaVersion: "tracebolt.complete-overview-view.v1", DeviceID: device, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Status: "available", ServerNow: at.Add(4 * time.Second)}
	for _, section := range []string{"processes", "volumes"} {
		id, _ := overviewwire.GenerationID(device, section, 1)
		m, _, e := overviewgeneration.Build(context.Background(), source, section, id, nil)
		if e != nil {
			t.Fatal("complete_overview_fixture_build")
		}
		hash, _ := overviewgeneration.ManifestDigest(m)
		binding := completeMVPOverviewBinding{section, "1", id, hash}
		until := at.Add(overviewledger.ObservationTTL)
		s := completeMVPOverviewSection{Status: "available", Complete: &completeMVPOverviewComplete{binding, m, "complete", at.Add(3 * time.Second), until}, Transfer: &completeMVPOverviewTransfer{binding, m, "complete", m.ObservedCount, m.ObservedCount, m.ChunkCount, m.ChunkCount, at, at.Add(2 * time.Second), until}}
		if section == "processes" {
			view.Processes = s
		} else {
			view.Volumes = s
		}
	}
	processes, volumes := []overviewgeneration.Row{}, []overviewgeneration.Row{}
	for i := range source.Processes.Items {
		processes = append(processes, overviewgeneration.Row{Process: &source.Processes.Items[i]})
	}
	for i := range source.Volumes.Items {
		volumes = append(volumes, overviewgeneration.Row{Volume: &source.Volumes.Items[i]})
	}
	return view, processes, volumes
}
func TestCompleteMVPOverviewEvidence(t *testing.T) {
	view, processes, volumes := completeMVPOverviewFixture(t)
	evidence, e := completeMVPOverviewEvidence(view)
	if e != nil || evidence != "processes=complete countExact=true processRows=2 volumes=complete countExact=true volumeRows=2" || completeMVPOverviewValidateRows(view, processes, volumes) != nil {
		t.Fatal("complete_overview_valid_evidence_rejected")
	}
	for _, mutate := range []func(*completeMVPOverviewView){func(v *completeMVPOverviewView) { v.Processes.Complete = nil }, func(v *completeMVPOverviewView) { v.Processes.Complete.Binding.Sequence = "2" }, func(v *completeMVPOverviewView) { v.Volumes.Complete.Binding.Section = "processes" }, func(v *completeMVPOverviewView) { v.Processes.Complete.Manifest.ObservedCount = 0 }, func(v *completeMVPOverviewView) { v.Processes.Complete.Manifest.Processes.CountExact = false }, func(v *completeMVPOverviewView) { v.Volumes.Complete.Manifest.RowsSHA256 = strings.Repeat("0", 64) }, func(v *completeMVPOverviewView) { v.Volumes.Transfer.AcceptedRows-- }, func(v *completeMVPOverviewView) {
		v.Processes.Failure = &completeMVPOverviewFailure{Reason: "sensitive-marker"}
	}, func(v *completeMVPOverviewView) { v.Volumes.Complete.CompletedAt = v.ServerNow.Add(time.Second) }, func(v *completeMVPOverviewView) {
		v.Volumes.Complete.RetainedUntil = v.Volumes.Complete.RetainedUntil.Add(time.Second)
	}} {
		v, _, _ := completeMVPOverviewFixture(t)
		mutate(&v)
		if text, e := completeMVPOverviewEvidence(v); text != "" || e == nil || e.Error() != "complete_overview_delivered_metadata_invalid" {
			t.Fatal("complete_overview_bad_metadata_accepted_or_leaked")
		}
	}
	for _, scenario := range []string{"missing", "duplicate", "changed", "wrong-type"} {
		v, p, vol := completeMVPOverviewFixture(t)
		switch scenario {
		case "missing":
			p = p[:1]
		case "duplicate":
			p[1] = p[0]
		case "changed":
			vol[0].Volume.MountPoint = "/changed"
		case "wrong-type":
			vol[0] = p[0]
		}
		if e := completeMVPOverviewValidateRows(v, p, vol); e == nil || e.Error() != "complete_overview_full_rows_manifest_mismatch" {
			t.Fatal("complete_overview_bad_rows_accepted")
		}
	}
}
func TestCompleteMVPOverviewPageEvidence(t *testing.T) {
	fixture := func() (completeMVPOverviewView, completeMVPOverviewPage) {
		v, p, _ := completeMVPOverviewFixture(t)
		c := v.Processes.Complete
		return v, completeMVPOverviewPage{SchemaVersion: "tracebolt.complete-overview-page.v1", DeviceID: v.DeviceID, Section: "processes", ServerNow: v.ServerNow, Binding: c.Binding, Manifest: c.Manifest, CollectedAt: c.Manifest.CollectedAt, CompletedAt: c.CompletedAt, RetainedUntil: c.RetainedUntil, TotalRows: 2, Items: p, ScannedRows: 2, Exhausted: true, CursorExpiresAt: v.ServerNow.Add(time.Minute)}
	}
	v, p := fixture()
	if completeMVPOverviewPageValid(v, "processes", v.Processes.Complete, p) != nil {
		t.Fatal("complete_overview_valid_page_rejected")
	}
	for _, mutate := range []func(*completeMVPOverviewPage){func(p *completeMVPOverviewPage) { p.Section = "volumes" }, func(p *completeMVPOverviewPage) { p.TotalRows = 1 }, func(p *completeMVPOverviewPage) { p.Binding.ManifestHash = strings.Repeat("0", 64) }, func(p *completeMVPOverviewPage) { p.NextCursor = "opaque" }, func(p *completeMVPOverviewPage) { p.Items = nil }, func(p *completeMVPOverviewPage) { p.ScannedRows = 1 }, func(p *completeMVPOverviewPage) { p.SearchIncomplete = true }, func(p *completeMVPOverviewPage) { p.CollectedAt = p.CollectedAt.Add(time.Second) }} {
		v, p := fixture()
		mutate(&p)
		if completeMVPOverviewPageValid(v, "processes", v.Processes.Complete, p) == nil {
			t.Fatal("complete_overview_bad_page_accepted")
		}
	}
}
func TestCompleteMVPOverviewRetainedAge(t *testing.T) {
	before, _, _ := completeMVPOverviewFixture(t)
	oldAt := before.ServerNow
	newAt := oldAt.Add(time.Second)
	for _, stage := range []string{"restart", "disabled_restart"} {
		after, _, _ := completeMVPOverviewFixture(t)
		after.ServerNow = after.ServerNow.Add(time.Second)
		if completeMVPOverviewRetainedEvidence(before, after, 1, 2, oldAt, newAt, stage, 2) != nil {
			t.Fatal("complete_overview_original_age_rejected")
		}
	}
	for _, mutate := range []func(*completeMVPOverviewView){func(v *completeMVPOverviewView) { v.Processes.Complete.Binding.Sequence = "2" }, func(v *completeMVPOverviewView) {
		v.Volumes.Complete.CompletedAt = v.Volumes.Complete.CompletedAt.Add(time.Second)
	}, func(v *completeMVPOverviewView) {
		v.Processes.Complete.Manifest.CollectedAt = v.Processes.Complete.Manifest.CollectedAt.Add(time.Second)
	}, func(v *completeMVPOverviewView) { v.ServerNow = before.ServerNow }, func(v *completeMVPOverviewView) {
		v.ServerNow = before.Processes.Complete.Manifest.CollectedAt.Add(time.Minute)
	}} {
		after, _, _ := completeMVPOverviewFixture(t)
		after.ServerNow = after.ServerNow.Add(time.Second)
		mutate(&after)
		if completeMVPOverviewRetainedEvidence(before, after, 1, 2, oldAt, newAt, "restart", 2) == nil {
			t.Fatal("complete_overview_refreshed_or_late_restart_accepted")
		}
	}
}

func completeMVPOverviewMarkerProbe(t *testing.T) {
	t.Helper()
	view, processes, volumes := completeMVPOverviewFixture(t)
	get := func(path string, out any) {
		if path != "/api/devices/"+view.DeviceID+"/inventory/overview" {
			t.Fatal("complete_overview_probe_path")
		}
		raw, _ := json.Marshal(view)
		if json.Unmarshal(raw, out) != nil {
			t.Fatal("complete_overview_probe_decode")
		}
	}
	call := func(path string, input any, csrf string) (int, []byte) {
		if path != "/api/devices/"+view.DeviceID+"/inventory/overview/query" || csrf != "inert-fixture-csrf" {
			t.Fatal("complete_overview_probe_path")
		}
		request := input.(map[string]any)
		section := request["section"].(string)
		c, rows := view.Processes.Complete, processes
		if section == "volumes" {
			c, rows = view.Volumes.Complete, volumes
		}
		page := completeMVPOverviewPage{SchemaVersion: "tracebolt.complete-overview-page.v1", DeviceID: view.DeviceID, Section: section, ServerNow: view.ServerNow, Binding: c.Binding, Manifest: c.Manifest, CollectedAt: c.Manifest.CollectedAt, CompletedAt: c.CompletedAt, RetainedUntil: c.RetainedUntil, TotalRows: uint64(len(rows)), Items: rows, ScannedRows: len(rows), Exhausted: true, CursorExpiresAt: view.ServerNow.Add(time.Minute)}
		raw, _ := json.Marshal(page)
		return http.StatusOK, raw
	}
	observed := completeMVPOverviewRead(t, get, call, "inert-fixture-csrf", view.DeviceID)
	prior := completeMVPObservation{metricSequence: 1, metricAt: view.ServerNow}
	ordinary := completeMVPObservation{metricSequence: 2, metricAt: view.ServerNow.Add(time.Second)}
	view.ServerNow = view.ServerNow.Add(time.Second)
	observed = completeMVPOverviewRetained(t, get, view.DeviceID, observed, prior, ordinary, "restart", 2)
	prior = ordinary
	ordinary = completeMVPObservation{metricSequence: 3, metricAt: view.ServerNow.Add(time.Second)}
	view.ServerNow = view.ServerNow.Add(time.Second)
	completeMVPOverviewRetained(t, get, view.DeviceID, observed, prior, ordinary, "disabled_restart", 3)
}
