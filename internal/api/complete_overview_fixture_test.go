package api

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateOverviewFixture = flag.Bool("update-overview-fixture", false, "Regenerate the explicitly synthetic complete overview UI golden fixture")

func overviewFixturePtr[T any](v T) *T { return &v }

// This fixture is encoded by the actual Go DTO builders. Every identity and row
// is invented; no host source, subprocess or network is used. Standard tests only
// compare the checked-in file. Regeneration requires the explicit test flag.
func TestCompleteOverviewGoldenFixture(t *testing.T) {
	now := time.Date(2026, 10, 4, 18, 35, 0, 0, time.UTC)
	device := "agent_" + strings.Repeat("a", 32)
	ps := completeoverview.Empty("sample_"+strings.Repeat("b", 32), now.Add(-5*time.Minute), completeoverview.ReasonNotCollected)
	ps.CaptureFinishedAt = ps.CaptureStartedAt.Add(750 * time.Millisecond)
	ps.Processes.Items = []completeoverview.Process{
		{PID: 1, ParentPID: overviewFixturePtr(uint32(0)), Name: overviewFixturePtr("kworker/0:0"), State: overviewFixturePtr("idle"), RSSBytes: overviewFixturePtr(uint64(0)), CPUTimeSeconds: overviewFixturePtr(float64(0)), Threads: overviewFixturePtr(uint32(1)), Observation: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}},
		{PID: 20, ParentPID: overviewFixturePtr(uint32(1)), Name: overviewFixturePtr(`fixture\worker`), State: overviewFixturePtr("running"), RSSBytes: overviewFixturePtr(uint64(65536)), CPUTimeSeconds: overviewFixturePtr(1.25), Threads: overviewFixturePtr(uint32(2)), Observation: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}},
		{PID: 30, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}},
		{PID: 40, Observation: completeoverview.Observation{Status: completeoverview.Exited, Reason: completeoverview.ReasonProcessGone}},
		{PID: 50, Observation: completeoverview.Observation{Status: completeoverview.Unavailable, Reason: completeoverview.ReasonReadFailed}},
	}
	ps.Processes.Meta = completeoverview.SectionMeta{GenerationID: ps.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: overviewFixturePtr(uint64(5)), CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: 2, Denied: 1, Exited: 1, Unavailable: 1}}
	vs := completeoverview.Empty("sample_"+strings.Repeat("c", 32), now.Add(-20*time.Minute), completeoverview.ReasonPermissionDenied)
	vs.CaptureFinishedAt = vs.CaptureStartedAt.Add(400 * time.Millisecond)
	volume := func(id, path, fs, kind string, status completeoverview.Status, reason completeoverview.Reason) completeoverview.Volume {
		return completeoverview.Volume{ID: id, MountPoint: path, Filesystem: fs, Kind: kind, FilesystemGroup: "fs_8_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: status, Reason: reason}}
	}
	vs.Volumes.Items = []completeoverview.Volume{
		volume("mount_20", "/", "ext4", "local", completeoverview.Observed, completeoverview.ReasonNone),
		volume("mount_10", "/data", "ext4", "local", completeoverview.Observed, completeoverview.ReasonNone),
		volume("mount_30", "/locked", "ext4", "local", completeoverview.Denied, completeoverview.ReasonPermissionDenied),
		volume("mount_40", "/run", "tmpfs", "memory", completeoverview.Observed, completeoverview.ReasonNone),
		volume("mount_50", "/remote", "nfs4", "remote", completeoverview.Unsupported, completeoverview.ReasonRemoteFilesystemSkipped),
		volume("mount_60", "/unknown", "fixturefs", "unknown", completeoverview.Unsupported, completeoverview.ReasonNotSupported),
		volume("mount_70", "/proc", "proc", "virtual", completeoverview.NotApplicable, completeoverview.ReasonNotApplicable),
	}
	for i, values := range map[int][2]uint64{0: {1000, 400}, 1: {0, 0}, 3: {100, 75}} {
		vs.Volumes.Items[i].TotalBytes = overviewFixturePtr(values[0])
		vs.Volumes.Items[i].AvailableBytes = overviewFixturePtr(values[1])
		if values[0] > 0 {
			vs.Volumes.Items[i].UsedPercent = overviewFixturePtr(float64(values[0]-values[1]) * 100 / float64(values[0]))
		}
	}
	vs.Volumes.Meta = completeoverview.SectionMeta{GenerationID: vs.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: overviewFixturePtr(uint64(7)), CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: 3, Denied: 1, Unsupported: 2, NotApplicable: 1}}
	makeSection := func(source completeoverview.Snapshot, section string, seq uint64) (enrollmentstore.OverviewSectionStatus, completeOverviewPage) {
		id, e := overviewwire.GenerationID(device, section, seq)
		if e != nil {
			t.Fatal(e)
		}
		m, _, e := overviewgeneration.Build(context.Background(), source, section, id, nil)
		if e != nil {
			t.Fatal(e)
		}
		hash, _ := overviewgeneration.ManifestDigest(m)
		binding := enrollmentstore.OverviewBinding{Section: section, Sequence: seq, GenerationID: id, ManifestHash: hash}
		completed := source.CaptureFinishedAt.Add(time.Second)
		generation := overviewledger.GenerationStatus{Manifest: m, State: "complete", StartedAt: source.CaptureFinishedAt, CompletedAt: completed, ExpiresAt: m.CollectedAt.Add(overviewledger.ObservationTTL), AcceptedChunks: m.ChunkCount, AcceptedRows: m.ObservedCount}
		state := enrollmentstore.OverviewSectionStatus{Section: section, DeviceID: device, ServerNow: now, Sequence: seq, CompleteBinding: binding, Complete: &generation, Transfer: &generation}
		rows := []overviewgeneration.Row{}
		if section == "processes" {
			for _, r := range source.Processes.Items {
				copy := r
				rows = append(rows, overviewgeneration.Row{Process: &copy})
			}
		} else {
			for _, r := range source.Volumes.Items {
				copy := r
				rows = append(rows, overviewgeneration.Row{Volume: &copy})
			}
		}
		page := overviewPage(device, section, now, enrollmentstore.OverviewPageResult{Binding: binding, PageResult: overviewledger.PageResult{Section: section, Manifest: m, StartedAt: source.CaptureFinishedAt, CompletedAt: completed, Items: rows, TotalRows: m.ObservedCount, ScannedRows: len(rows), Exhausted: true, CursorExpiresAt: now.Add(overviewledger.CursorTTL)}})
		return state, page
	}
	processes, processPage := makeSection(ps, "processes", 4)
	volumes, volumePage := makeSection(vs, "volumes", 2)
	failureID, _ := overviewwire.GenerationID(device, "processes", 5)
	processes.Sequence = 5
	processes.Transfer = nil
	processes.Failure = &enrollmentstore.OverviewFailureReceipt{Failure: enrollmentstore.OverviewFailureReport{Section: "processes", Sequence: 5, GenerationID: failureID, AttemptedAt: now.Add(-time.Minute), Reason: "timeout"}, ReceivedAt: now.Add(-59 * time.Second)}
	view, e := overviewView(enrollmentstore.OverviewStatus{DeviceID: device, ServerNow: now, Processes: processes, Volumes: volumes})
	if e != nil {
		t.Fatal(e)
	}
	// Actual Go search semantics for Unicode U+0130: strings.ToLower maps the
	// single code point to i, unlike JavaScript's default multi-code-point lower.
	unicodeProcesses := ps
	unicodeProcesses.GenerationID = "sample_" + strings.Repeat("d", 32)
	unicodeProcesses.Processes.Meta.GenerationID = unicodeProcesses.GenerationID
	unicodeProcesses.Volumes.Meta.GenerationID = unicodeProcesses.GenerationID
	unicodeProcesses.Processes.Items = append([]completeoverview.Process(nil), ps.Processes.Items...)
	unicodeProcesses.Processes.Items[0].Name = overviewFixturePtr("İd-worker")
	unicodeVolumes := vs
	unicodeVolumes.GenerationID = "sample_" + strings.Repeat("e", 32)
	unicodeVolumes.Processes.Meta.GenerationID = unicodeVolumes.GenerationID
	unicodeVolumes.Volumes.Meta.GenerationID = unicodeVolumes.GenerationID
	unicodeVolumes.Volumes.Items = append([]completeoverview.Volume(nil), vs.Volumes.Items...)
	unicodeVolumes.Volumes.Items[1].MountPoint = "/İd"
	_, unicodeProcessPage := makeSection(unicodeProcesses, "processes", 6)
	_, unicodeVolumePage := makeSection(unicodeVolumes, "volumes", 3)
	query := "id"
	filter := func(page completeOverviewPage) completeOverviewPage {
		matches := []overviewgeneration.Row{}
		for _, row := range page.Items {
			if strings.Contains(strings.ToLower(overviewgeneration.RowSearchText(row)), query) {
				matches = append(matches, row)
			}
		}
		page.Items = matches
		return page
	}
	unicodeProcessPage, unicodeVolumePage = filter(unicodeProcessPage), filter(unicodeVolumePage)
	if len(unicodeProcessPage.Items) != 1 || len(unicodeVolumePage.Items) != 1 {
		t.Fatal("Go Unicode search fixture did not exercise U+0130")
	}
	fixture := struct {
		View          completeOverviewView `json:"view"`
		ProcessPage   completeOverviewPage `json:"processPage"`
		VolumePage    completeOverviewPage `json:"volumePage"`
		UnicodeSearch struct {
			Search      string               `json:"search"`
			ProcessPage completeOverviewPage `json:"processPage"`
			VolumePage  completeOverviewPage `json:"volumePage"`
		} `json:"unicodeSearch"`
	}{View: view, ProcessPage: processPage, VolumePage: volumePage}
	fixture.UnicodeSearch.Search = query
	fixture.UnicodeSearch.ProcessPage = unicodeProcessPage
	fixture.UnicodeSearch.VolumePage = unicodeVolumePage
	raw, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "complete-overview-synthetic.json")
	if *updateOverviewFixture {
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	expected, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatal("synthetic overview fixture differs from the actual Go DTO encoding; review before explicit regeneration")
	}
}
