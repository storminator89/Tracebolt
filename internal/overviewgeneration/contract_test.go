package overviewgeneration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/completeoverview"
	"strings"
	"testing"
	"time"
)

const captureID = "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const transferID = "sample_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func processSource(n int) completeoverview.Snapshot {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	s := completeoverview.Empty(captureID, at, completeoverview.ReasonReadFailed)
	s.CaptureFinishedAt = at.Add(time.Second)
	count := uint64(n)
	s.Processes = completeoverview.ProcessSection{Meta: completeoverview.SectionMeta{GenerationID: captureID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: count}}, Items: make([]completeoverview.Process, n)}
	for i := range s.Processes.Items {
		s.Processes.Items[i] = completeoverview.Process{PID: uint32(i + 1), Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}
	}
	return s
}
func volumeSource(n int) completeoverview.Snapshot {
	s := completeoverview.Empty(captureID, time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), completeoverview.ReasonReadFailed)
	count := uint64(n)
	s.Volumes = completeoverview.VolumeSection{Meta: completeoverview.SectionMeta{GenerationID: captureID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{NotApplicable: count}}, Items: make([]completeoverview.Volume, n)}
	// Source display paths are ascending while numeric mount IDs are descending.
	for i := range s.Volumes.Items {
		s.Volumes.Items[i] = completeoverview.Volume{ID: fmt.Sprintf("mount_%d", n-i), MountPoint: fmt.Sprintf("/fixture/%05d", i), Filesystem: "proc", Kind: "virtual", FilesystemGroup: "fs_0_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}}
	}
	return s
}
func buildFixture(t *testing.T, n int) (Manifest, []Chunk) {
	t.Helper()
	m, c, e := Build(context.Background(), processSource(n), "processes", transferID, nil)
	if e != nil {
		t.Fatal(e)
	}
	return m, c
}
func finishFixture(t *testing.T, m Manifest, c []Chunk) Complete {
	t.Helper()
	v, e := NewValidator(context.Background(), m)
	if e != nil {
		t.Fatal(e)
	}
	for _, chunk := range c {
		if e = v.Add(chunk); e != nil {
			t.Fatal(e)
		}
	}
	r, e := v.Finish()
	if e != nil || !r.Valid() {
		t.Fatal(e)
	}
	return r
}
func TestIndependentSectionCaptureIdentityAndEmpty(t *testing.T) {
	for _, n := range []int{0, 1, 97, 300, completeoverview.MaxProcessRows} {
		m, c := buildFixture(t, n)
		if m.GenerationID != transferID || m.CaptureGenerationID != captureID || m.Processes.GenerationID != captureID || m.Volumes.Coverage != completeoverview.Failed || m.ObservedCount != uint64(n) || !m.CollectedAt.Equal(m.CaptureStartedAt) {
			t.Fatal("capture metadata changed")
		}
		finishFixture(t, m, c)
	}
	s := processSource(1)
	if _, _, e := Build(context.Background(), s, "volumes", transferID, nil); e != ErrSource {
		t.Fatal("failed selected source accepted", e)
	}
	if m, c, e := Build(context.Background(), s, "processes", transferID, errors.New("source failed")); e != ErrSource || m != (Manifest{}) || c != nil {
		t.Fatal("source failure returned facts")
	}
	s.Processes.Items = nil
	if _, _, e := Build(context.Background(), s, "processes", transferID, nil); e == nil {
		t.Fatal("nil rows accepted")
	}
}
func TestVolumeNumericWireOrderAndDeepDetachment(t *testing.T) {
	s := volumeSource(300)
	m, c, e := Build(context.Background(), s, "volumes", transferID, nil)
	if e != nil {
		t.Fatal(e)
	}
	if c[0].Items[0].Volume.ID != "mount_1" || s.Volumes.Items[0].ID != "mount_300" {
		t.Fatal("source order mutated or wrong wire order")
	}
	s.Volumes.Items[0].MountPoint = "/changed"
	*s.Volumes.Meta.ObservedCount = 0
	finishFixture(t, m, c)
	r := finishFixture(t, m, c)
	copy := r.Manifest()
	*copy.Volumes.ObservedCount = 0
	if *r.Manifest().Volumes.ObservedCount != 300 {
		t.Fatal("receipt alias")
	}
	s = processSource(1)
	name, state := "fixture", "sleeping"
	parent, threads := uint32(0), uint32(1)
	rss, cpu := uint64(0), 0.0
	s.Processes.Items[0] = completeoverview.Process{PID: 1, ParentPID: &parent, Name: &name, State: &state, RSSBytes: &rss, CPUTimeSeconds: &cpu, Threads: &threads, Observation: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}}
	s.Processes.Meta.FieldCoverage = completeoverview.FieldCoverage{Observed: 1}
	m, c, e = Build(context.Background(), s, "processes", transferID, nil)
	if e != nil {
		t.Fatal(e)
	}
	name = "changed"
	rss = 42
	if *c[0].Items[0].Process.Name != "fixture" || *c[0].Items[0].Process.RSSBytes != 0 {
		t.Fatal("input pointer retained")
	}
	finishFixture(t, m, c)
}
func TestStrictDecodeBoundariesAndUnion(t *testing.T) {
	m, c := buildFixture(t, 1)
	mb, _ := EncodeManifest(m)
	cb, _ := EncodeChunk(c[0])
	if _, e := DecodeManifest(mb); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeChunk(cb); e != nil {
		t.Fatal(e)
	}
	mutations := [][]byte{bytes.Replace(cb, []byte(`"pid":1`), []byte(`"pid":1,"pid":1`), 1), bytes.Replace(cb, []byte(`"pid":1`), []byte(`"pid":1.0`), 1), bytes.Replace(cb, []byte(`"parentPid":null,`), nil, 1), bytes.Replace(cb, []byte(`"volume":null`), []byte(`"volume":{}`), 1), bytes.Replace(cb, []byte(`"process":`), []byte(`"extra":0,"process":`), 1), append(bytes.Clone(cb), 'x'), append(bytes.Repeat([]byte{' '}, MaxChunkBytes), cb...)}
	for _, raw := range mutations {
		if _, e := DecodeChunk(raw); e == nil {
			t.Fatal("invalid chunk accepted")
		}
	}
	for _, raw := range [][]byte{bytes.Replace(mb, []byte(`"fieldCoverage":`), []byte(`"fieldCoverage":null,"x":`), 1), bytes.Replace(mb, []byte(`"countExact":true`), []byte(`"countExact":null`), 1), bytes.Replace(mb, []byte(`"observedCount":1`), []byte(`"observedCount":"1"`), 1)} {
		if _, e := DecodeManifest(raw); e == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	if ValidateRow(Row{}) == nil || ValidateRow(Row{Process: c[0].Items[0].Process, Volume: &volumeSource(1).Volumes.Items[0]}) == nil {
		t.Fatal("invalid union")
	}
}
func TestLongMountPointFitsFixedRowAndRoundtrips(t *testing.T) {
	s := volumeSource(1)
	s.Volumes.Items[0].MountPoint = "/" + strings.Repeat("<", completeoverview.MaxMountPathBytes-1)
	m, c, e := Build(context.Background(), s, "volumes", transferID, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := EncodeChunk(c[0])
	if len(b) < 24<<10 || len(b) > MaxChunkBytes {
		t.Fatal("escaping byte budget")
	}
	decoded, e := DecodeChunk(b)
	if e != nil {
		t.Fatal(e)
	}
	finishFixture(t, m, []Chunk{decoded})
	s.Volumes.Items[0].MountPoint += "x"
	if _, _, e = Build(context.Background(), s, "volumes", transferID, nil); e == nil {
		t.Fatal("oversized path")
	}
}
func TestTerminalIntegrityAndCrossSectionMismatch(t *testing.T) {
	m, c := buildFixture(t, 300)
	v, _ := NewValidator(context.Background(), m)
	if e := v.Add(c[1]); e == nil {
		t.Fatal("out of order")
	}
	if e := v.Add(c[0]); e == nil {
		t.Fatal("failed resumed")
	}
	if r, e := v.Finish(); e == nil || r.Valid() {
		t.Fatal("failed completed")
	}
	v, _ = NewValidator(context.Background(), m)
	if r, e := v.Finish(); e != ErrIncomplete || r.Valid() {
		t.Fatal("premature completion")
	}
	for _, mutation := range []func(*Chunk){func(c *Chunk) { c.Section = "volumes" }, func(c *Chunk) { c.Items[1].Process.PID = c.Items[0].Process.PID }, func(c *Chunk) { c.RowOffset++ }, func(c *Chunk) { c.ManifestSHA256 = strings.Repeat("0", 64) }} {
		_, fresh := buildFixture(t, 300)
		bad := fresh[0]
		mutation(&bad)
		bad.SHA256 = chunkDigest(bad)
		v, _ = NewValidator(context.Background(), m)
		if e := v.Add(bad); e == nil {
			t.Fatal("invalid linkage/order/section")
		}
	}
	wrong := cloneManifest(m)
	wrong.Processes.FieldCoverage.Denied--
	wrong.Processes.FieldCoverage.Exited++
	hash, _ := ManifestDigest(wrong)
	v, _ = NewValidator(context.Background(), wrong)
	first := c[0]
	first.ManifestSHA256 = hash
	first.SHA256 = chunkDigest(first)
	if e := v.Add(first); e != nil {
		t.Fatal("premature coverage bound", e)
	}
	second := c[1]
	second.ManifestSHA256 = hash
	second.PreviousSHA256 = first.SHA256
	second.SHA256 = chunkDigest(second)
	if e := v.Add(second); e != nil {
		t.Fatal(e)
	}
	third := c[2]
	third.ManifestSHA256 = hash
	third.PreviousSHA256 = second.SHA256
	third.SHA256 = chunkDigest(third)
	if e := v.Add(third); e == nil {
		t.Fatal("dishonest coverage accepted")
	}
}
func TestLimitsCancellationAndCanonicalSizes(t *testing.T) {
	m, c := buildFixture(t, 1)
	if len(canonicalRow(c[0].Items[0])) != int(m.CanonicalRowBytes) {
		t.Fatal("row bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := Build(ctx, processSource(1), "processes", transferID, nil); e != ErrCanceled {
		t.Fatal(e)
	}
	for _, mutation := range []func(*Manifest){func(m *Manifest) { m.CanonicalSectionBytes++ }, func(m *Manifest) { m.CanonicalSnapshotBytes = MaxSnapshotBytes + 1 }, func(m *Manifest) { m.ChunkCount = MaxGenerationChunks + 1 }, func(m *Manifest) { m.Processes.GenerationID = transferID }, func(m *Manifest) { m.CollectedAt = m.CollectedAt.Add(time.Second) }} {
		bad := cloneManifest(m)
		mutation(&bad)
		if ValidateManifest(bad) == nil {
			t.Fatal("invalid manifest")
		}
	}
	var b bytes.Buffer
	for _, chunk := range c {
		for _, r := range chunk.Items {
			b.Write(canonicalRow(r))
		}
	}
	if uint64(b.Len()) != m.CanonicalRowBytes {
		t.Fatal("canonical count")
	}
	raw, _ := json.Marshal(m)
	if len(raw) > MaxManifestBytes {
		t.Fatal("manifest cap")
	}
}

func TestMaximumVolumeSectionConstantCheckpointAndDuplicateAcrossChunks(t *testing.T) {
	source := volumeSource(completeoverview.MaxVolumeRows)
	m, chunks, err := Build(context.Background(), source, "volumes", transferID, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewValidator(context.Background(), m)
	for _, c := range chunks {
		if err = v.Add(c); err != nil {
			t.Fatal(err)
		}
		raw, e := v.Checkpoint()
		if e != nil || len(raw) > 1024 {
			t.Fatalf("checkpoint grew with IDs: %d %v", len(raw), e)
		}
		v, e = RestoreValidatorFromTrustedCheckpoint(context.Background(), m, raw)
		if e != nil {
			t.Fatal(e)
		}
	}
	if r, e := v.Finish(); e != nil || !r.Valid() {
		t.Fatal(e)
	}
	// The numeric canonical order makes duplicates detectable with one key,
	// including duplicates across persisted checkpoint/chunk boundaries.
	small := volumeSource(300)
	m, chunks, err = Build(context.Background(), small, "volumes", transferID, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _ = NewValidator(context.Background(), m)
	if err = v.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	raw, _ := v.Checkpoint()
	v, err = RestoreValidatorFromTrustedCheckpoint(context.Background(), m, raw)
	if err != nil {
		t.Fatal(err)
	}
	bad := chunks[1]
	bad.Items[0].Volume.ID = chunks[0].Items[len(chunks[0].Items)-1].Volume.ID
	bad.SHA256 = chunkDigest(bad)
	if err = v.Add(bad); err == nil {
		t.Fatal("cross-boundary duplicate accepted")
	}
}

func TestFieldCoverageUncertaintyAndIndependentSectionFailures(t *testing.T) {
	s := processSource(7)
	observations := []completeoverview.Observation{{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}, {Status: completeoverview.Exited, Reason: completeoverview.ReasonProcessGone}, {Status: completeoverview.Invalid, Reason: completeoverview.ReasonInvalidSource}, {Status: completeoverview.Unsupported, Reason: completeoverview.ReasonNotSupported}, {Status: completeoverview.Unavailable, Reason: completeoverview.ReasonReadFailed}, {Status: completeoverview.Unavailable, Reason: completeoverview.ReasonSourceMissing}, {Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}
	s.Processes.Meta.FieldCoverage = completeoverview.FieldCoverage{Denied: 2, Exited: 1, Invalid: 1, Unsupported: 1, Unavailable: 2}
	for i, o := range observations {
		s.Processes.Items[i].Observation = o
	}
	m, c, e := Build(context.Background(), s, "processes", transferID, nil)
	if e != nil {
		t.Fatal(e)
	}
	r := finishFixture(t, m, c)
	if r.Manifest().Processes.FieldCoverage != s.Processes.Meta.FieldCoverage || r.Manifest().Processes.Coverage != completeoverview.Complete {
		t.Fatal("uncertain details conflated with enumeration")
	}
	for _, section := range []string{"processes", "volumes"} {
		failed := completeoverview.Empty(captureID, s.CaptureStartedAt, completeoverview.ReasonTimeout)
		if m, c, e := Build(context.Background(), failed, section, transferID, nil); e != ErrSource || m != (Manifest{}) || c != nil {
			t.Fatal("failed source became empty success")
		}
	}
}

func TestSectionByteLimitFailsWithoutPrefix(t *testing.T) {
	s := volumeSource(700)
	for i := range s.Volumes.Items {
		s.Volumes.Items[i].MountPoint = fmt.Sprintf("/%05d", i) + strings.Repeat("<", completeoverview.MaxMountPathBytes-6)
	}
	if m, c, e := Build(context.Background(), s, "volumes", transferID, nil); e != ErrLimit || m != (Manifest{}) || c != nil {
		t.Fatal("oversized selected section returned a prefix", e)
	}
}
