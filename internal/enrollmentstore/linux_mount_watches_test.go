package enrollmentstore

import (
	"context"
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/linuxmountwatch"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"sort"
	"strings"
	"testing"
	"time"
)

func mountGeneration(t *testing.T, device string, seq uint64, at time.Time, paths []string) (OverviewBinding, overviewgeneration.Manifest, []overviewgeneration.Chunk) {
	t.Helper()
	generation, e := overviewwire.GenerationID(device, "volumes", seq)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := completeoverview.Empty(id("sample", 900), at, completeoverview.ReasonReadFailed)
	count := uint64(len(paths))
	snapshot.Volumes.Meta = completeoverview.SectionMeta{GenerationID: snapshot.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: count}}
	for i, p := range paths {
		total, available, used := uint64(1000), uint64(50), float64(95)
		snapshot.Volumes.Items = append(snapshot.Volumes.Items, completeoverview.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: p, Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_8_1", CapacityScope: "agent-mount-namespace", TotalBytes: &total, AvailableBytes: &available, UsedPercent: &used, Measurement: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}})
	}
	sort.Slice(snapshot.Volumes.Items, func(i, j int) bool {
		return snapshot.Volumes.Items[i].MountPoint < snapshot.Volumes.Items[j].MountPoint
	})
	m, c, e := overviewgeneration.Build(context.Background(), snapshot, "volumes", generation, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := overviewgeneration.ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	return OverviewBinding{"volumes", seq, generation, hash}, m, c
}
func TestLinuxMountWatchExistingCompleteVolumeProvenance(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	target := linuxmountwatch.Target{MountPoint: "/var", Filesystem: "ext4", FilesystemGroup: "fs_8_1"}
	epoch := strings.Repeat("a", 64)
	now := at
	b, m, chunks := mountGeneration(t, snap.Approval.DeviceID, 1, at, []string{"/", "/var", "/home/[redacted]"})
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	var saved linuxmountwatch.Input
	e := s.WithLinuxMountWatch(context.Background(), snap.Approval.DeviceID, &target, epoch, func() time.Time { return now }, func(in linuxmountwatch.Input, guard func(time.Time) error) error { saved = in; return guard(now) })
	if e != nil || saved.Sample == nil || len(saved.Options) != 1 || saved.Options[0] != target || saved.Sample.UsedPercent != 95 || saved.Generation.Sequence != 1 {
		t.Fatalf("%+v %v", saved, e)
	}
	// A complete duplicate location is ambiguous, never an arbitrary measured row.
	now = at.Add(time.Minute)
	b, m, chunks = mountGeneration(t, snap.Approval.DeviceID, 2, now, []string{"/var", "/var"})
	promoteOverview(t, s, snap, cert, b, m, chunks, now)
	e = s.WithLinuxMountWatch(context.Background(), snap.Approval.DeviceID, &target, epoch, func() time.Time { return now }, func(in linuxmountwatch.Input, guard func(time.Time) error) error {
		if in.Sample != nil || len(in.Options) != 0 {
			t.Fatal("ambiguous mount selected")
		}
		return guard(now)
	})
	if e != nil {
		t.Fatal(e)
	}
	now = at.Add(4 * time.Minute)
	e = s.WithLinuxMountWatch(context.Background(), snap.Approval.DeviceID, &target, epoch, func() time.Time { return now }, func(in linuxmountwatch.Input, guard func(time.Time) error) error {
		if in.Available || in.Sample != nil || in.Reason != "stale" {
			t.Fatal("old evidence refreshed")
		}
		return guard(now)
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestLinuxMountWatchPendingGenerationAndLease(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := mountGeneration(t, snap.Approval.DeviceID, 1, at, []string{"/var"})
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	now := at.Add(time.Minute)
	b, m, chunks = mountGeneration(t, snap.Approval.DeviceID, 2, now, []string{"/var"})
	stageOverview(t, s, snap, cert, b, m, chunks, now)
	e := s.WithLinuxMountWatch(context.Background(), snap.Approval.DeviceID, nil, strings.Repeat("a", 64), func() time.Time { return now }, func(in linuxmountwatch.Input, guard func(time.Time) error) error {
		if in.Available || in.Reason != "newer_attempt" {
			t.Fatal("pending attempt hid uncertainty")
		}
		now = now.Add(6 * time.Second)
		return guard(now)
	})
	if e == nil {
		t.Fatal("expired source lease admitted")
	}
}
