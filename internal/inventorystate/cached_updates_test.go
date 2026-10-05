package inventorystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func updatePayloads(t *testing.T, a Allocation, n int) ([]byte, [][]byte) {
	t.Helper()
	id := a.GenerationID
	at := a.AttemptedAt
	oldest, age := at.Add(-72*time.Hour), uint64(72*60*60)
	release, version, codename := "debian", "13", "trixie"
	count, checked, unknown, held := uint32(n), uint32(n), uint32(1), uint32(0)
	installed := checked + unknown
	rows := make([]cachedupdates.Candidate, n)
	for i := range rows {
		rows[i] = cachedupdates.Candidate{Name: fmt.Sprintf("fixture-update-%06d", i), Architecture: "amd64", InstalledVersion: "1.0", CandidateVersion: "2.0", State: "candidate_only", Installability: "not_evaluated"}
	}
	s := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: id, CollectedAt: at, Release: linuxpackages.ReleaseFields{ID: &release, VersionID: &version, VersionCodename: &codename}, Metadata: cachedupdates.Metadata{Freshness: "stale", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &installed, CheckedCount: &checked, CandidateCount: &count, HeldCount: &held, UnknownCount: &unknown, Coverage: "partial", Reason: cachedupdates.ReasonCandidateUnknown, Items: append([]cachedupdates.Candidate{}, rows[:min(n, cachedupdates.MaxRows)]...), Truncated: n > cachedupdates.MaxRows}
	if s.Truncated {
		s.Reason = cachedupdates.ReasonItemLimit
	}
	for cachedupdates.Validate(s) != nil {
		if len(s.Items) == 0 {
			t.Fatal("invalid synthetic update snapshot")
		}
		s.Items = s.Items[:len(s.Items)-1]
		s.Truncated = true
		s.Reason = cachedupdates.ReasonByteLimit
	}
	m, chunks, err := updategeneration.Build(context.Background(), updategeneration.SourceInventory{Snapshot: s, Rows: rows, Complete: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(chunks))
	for i, c := range chunks {
		out[i], err = json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
	}
	return raw, out
}
func newUpdateFixture(t *testing.T) (*State, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux private state tests")
	}
	dir := filepath.Join(t.TempDir(), "cached-updates")
	s, err := InitializeCachedUpdatesNew(dir, fixtureBinding, fixtureAgent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func reopenUpdates(t *testing.T, s *State, dir string) *State {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := OpenCachedUpdatesExisting(dir, fixtureBinding, fixtureAgent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	return out
}
func updateReceipt(t *testing.T, w Work) []byte {
	t.Helper()
	m, err := inventorywire.DecodeCachedUpdatesMessage(w.Operation, w.Body())
	if err != nil {
		t.Fatal(err)
	}
	var result any
	switch w.Operation {
	case "begin":
		result = map[string]any{"startedAt": fixtureAt.Add(time.Minute), "expiresAt": fixtureAt.Add(16 * time.Minute)}
	case "append":
		result = map[string]any{"ordinal": m.UpdateChunk.Ordinal, "rows": len(m.UpdateChunk.Items), "receivedAt": fixtureAt.Add(2 * time.Minute)}
	case "finalize":
		result = map[string]any{"collectedAt": fixtureAt, "completedAt": fixtureAt.Add(3 * time.Minute)}
	case "failure":
		result = map[string]any{"attemptedAt": m.FailureAt, "reason": m.FailureReason, "receivedAt": fixtureAt.Add(time.Minute)}
	case "abort":
		result = map[string]any{"aborted": true}
	}
	return updateReceiptResult(t, w, result)
}
func updateReceiptResult(t *testing.T, w Work, result any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"schemaVersion": inventorywire.CachedUpdatesReceiptVersion, "operation": w.Operation, "sequence": fmt.Sprint(w.Sequence), "generationId": w.GenerationID, "manifestHash": w.ManifestHash, "requestSha256": w.Digest, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestCachedUpdatesRestartExactBytesAllRowsAndOriginalAge(t *testing.T) {
	for _, n := range []int{0, 1, 129, 1201} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, dir := newUpdateFixture(t)
			a := reserve(t, s)
			wantID, _ := inventorywire.CachedUpdatesGenerationID(fixtureAgent, 1)
			if a.GenerationID != wantID {
				t.Fatal("wrong generation domain")
			}
			m, c := updatePayloads(t, a, n)
			m = append([]byte(" \n"), m...)
			if len(c) > 0 {
				c[0] = append(c[0], []byte(" \n")...)
			}
			if err := s.Stage(context.Background(), a, m, c); err != nil {
				t.Fatal(err)
			}
			expected := append([][]byte{m}, c...)
			seen := 0
			for i := 0; ; i++ {
				w := next(t, s)
				before := w.Body()
				msg, err := inventorywire.DecodeCachedUpdatesMessage(w.Operation, before)
				if err != nil {
					t.Fatal(err)
				}
				if msg.Manifest != nil || msg.Chunk != nil {
					t.Fatal("update rows relabeled")
				}
				if msg.UpdateManifest != nil && (!msg.UpdateManifest.CollectedAt.Equal(a.AttemptedAt) || msg.UpdateManifest.CandidateCount != uint32(n) || msg.UpdateManifest.UnknownCount != 1 || *msg.UpdateManifest.Metadata.AgeSeconds != 72*60*60) {
					t.Fatal("original capture facts lost")
				}
				if msg.UpdateChunk != nil {
					seen += len(msg.UpdateChunk.Items)
				}
				if i < len(expected) && !bytes.Contains(before, expected[i]) {
					t.Fatal("exact payload changed")
				}
				s = reopenUpdates(t, s, dir)
				if retry := next(t, s); !sameWork(w, retry) || !bytes.Equal(before, retry.Body()) {
					t.Fatal("restart bytes changed")
				}
				ack := updateReceipt(t, w)
				wrong := bytes.Replace(ack, []byte(inventorywire.CachedUpdatesReceiptVersion), []byte(inventorywire.ReceiptVersion), 1)
				if err = s.Acknowledge(w, wrong); !errors.Is(err, ErrAcknowledgment) {
					t.Fatal("package receipt accepted", err)
				}
				if err = s.Acknowledge(w, ack); err != nil {
					t.Fatal(err)
				}
				s = reopenUpdates(t, s, dir)
				if err = s.Acknowledge(w, ack); err != nil {
					t.Fatal("exact receipt replay refused", err)
				}
				if err = s.Acknowledge(w, append(bytes.Clone(ack), ' ')); !errors.Is(err, ErrAcknowledgment) {
					t.Fatal("changed receipt replay accepted", err)
				}
				if w.Operation == "finalize" {
					break
				}
			}
			if seen != n {
				t.Fatal("lost rows", seen, n)
			}
			if _, ok, err := s.NextWork(); err != nil || ok {
				t.Fatal("completed bytes retained", err)
			}
			at, err := s.LastAttemptedAt()
			if err != nil || !at.Equal(a.AttemptedAt) {
				t.Fatal("attempt cooldown lost", err)
			}
			if reserve(t, s).Sequence != 2 {
				t.Fatal("consumed floor lost")
			}
		})
	}
}
func TestCachedUpdatesCrossDomainSpoolsRefusedWithoutChanges(t *testing.T) {
	for _, phase := range []string{"idle", "allocated", "ready", "retired"} {
		for _, updates := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", phase, updates), func(t *testing.T) {
				create, payload, ack, wrongOpen := newFixture, payloads, receipt, OpenCachedUpdatesExisting
				if updates {
					create, payload, ack, wrongOpen = newUpdateFixture, updatePayloads, updateReceipt, OpenExisting
				}
				s, dir := create(t)
				if phase != "idle" {
					a := reserve(t, s)
					if phase == "ready" || phase == "retired" {
						m, c := payload(t, a, 129)
						if err := s.Stage(context.Background(), a, m, c); err != nil {
							t.Fatal(err)
						}
					}
				}
				if phase == "retired" {
					for {
						w := next(t, s)
						if err := s.Acknowledge(w, ack(t, w)); err != nil {
							t.Fatal(err)
						}
						if w.Operation == "finalize" {
							break
						}
					}
				}
				s.Close()
				before := directoryBytes(t, dir)
				other, err := wrongOpen(dir, fixtureBinding, fixtureAgent)
				if other != nil {
					other.Close()
				}
				if !errors.Is(err, ErrCorrupt) {
					t.Fatal("wrong-domain spool adopted", err)
				}
				unchanged(t, dir, before)
			})
		}
	}
}
func TestCachedUpdatesInterruptedCaptureAndInvalidGeneration(t *testing.T) {
	s, dir := newUpdateFixture(t)
	a := reserve(t, s)
	pm, pc := payloads(t, a, 1)
	if err := s.Stage(context.Background(), a, pm, pc); !errors.Is(err, ErrBody) {
		t.Fatal("package data staged as updates", err)
	}
	changed := a
	changed.AttemptedAt = changed.AttemptedAt.Add(time.Second)
	m, c := updatePayloads(t, changed, 129)
	if err := s.Stage(context.Background(), a, m, c); !errors.Is(err, ErrBody) {
		t.Fatal("capture age refreshed", err)
	}
	m, c = updatePayloads(t, a, 129)
	c[1] = c[0]
	if err := s.Stage(context.Background(), a, m, c); !errors.Is(err, ErrBody) {
		t.Fatal("incomplete duplicate chunks staged", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Stage(ctx, a, m, c); !errors.Is(err, ErrCanceled) {
		t.Fatal("cancellation ignored", err)
	}
	s = reopenUpdates(t, s, dir)
	w := next(t, s)
	msg, err := inventorywire.DecodeCachedUpdatesMessage("failure", w.Body())
	if err != nil || msg.FailureReason != "collection_failed" || !msg.FailureAt.Equal(a.AttemptedAt) {
		t.Fatal("restart recaptured or refreshed", err)
	}
	m, c = updatePayloads(t, a, 1)
	if err = s.Stage(context.Background(), a, m, c); !errors.Is(err, ErrPending) {
		t.Fatal("stale live permit accepted", err)
	}
	if err = s.Acknowledge(w, updateReceipt(t, w)); err != nil {
		t.Fatal(err)
	}
	s = reopenUpdates(t, s, dir)
	if reserve(t, s).Sequence != 2 {
		t.Fatal("failed floor rewound")
	}
}
func TestCachedUpdatesStatusConflictAndAbortRemainExact(t *testing.T) {
	s, dir := newUpdateFixture(t)
	a := reserve(t, s)
	m, c := updatePayloads(t, a, 129)
	if err := s.Stage(context.Background(), a, m, c); err != nil {
		t.Fatal(err)
	}
	w, err := s.StatusWork()
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"state": "pending", "acceptedChunks": 1, "expectedChunks": 2, "acceptedRows": 128, "startedAt": fixtureAt.Add(time.Minute), "expiresAt": fixtureAt.Add(16 * time.Minute), "completedAt": ""}
	if _, err = s.ValidateStatus(w, updateReceiptResult(t, w, result)); err != nil {
		t.Fatal(err)
	}
	result["acceptedRows"] = 127
	if _, err = s.ValidateStatus(w, updateReceiptResult(t, w, result)); !errors.Is(err, ErrAcknowledgment) {
		t.Fatal("wrong row prefix accepted", err)
	}
	result["acceptedRows"] = 128
	if err = s.RequestAbortAfterStatus(w, updateReceiptResult(t, w, result)); !errors.Is(err, ErrAcknowledgment) {
		t.Fatal("live transfer aborted", err)
	}
	result["state"], result["acceptedChunks"], result["acceptedRows"] = "expired", 2, 129
	result["completedAt"], result["expiresAt"] = fixtureAt.Add(3*time.Minute), fixtureAt.Add(24*time.Hour)
	if _, err = s.ValidateStatus(w, updateReceiptResult(t, w, result)); err != nil {
		t.Fatal("completed expired state rejected", err)
	}
	if err = s.RequestAbortAfterStatus(w, updateReceiptResult(t, w, result)); !errors.Is(err, ErrAcknowledgment) {
		t.Fatal("complete result discarded", err)
	}
	result["acceptedChunks"], result["acceptedRows"], result["completedAt"], result["expiresAt"] = 0, 0, "", fixtureAt.Add(16*time.Minute)
	if err = s.RequestAbortAfterStatus(w, updateReceiptResult(t, w, result)); err != nil {
		t.Fatal(err)
	}
	abort := next(t, s)
	if abort.Operation != "abort" {
		t.Fatal("missing purpose-bound abort")
	}
	if _, err = os.Stat(filepath.Join(dir, "generation.pack")); err != nil {
		t.Fatal("bytes removed before acknowledgment", err)
	}
	s = reopenUpdates(t, s, dir)
	if !sameWork(abort, next(t, s)) {
		t.Fatal("abort retry changed")
	}
	if err = s.Acknowledge(abort, updateReceipt(t, abort)); err != nil {
		t.Fatal(err)
	}
	s = reopenUpdates(t, s, dir)
	if reserve(t, s).Sequence != 2 {
		t.Fatal("abort lost floor")
	}
}

func TestCachedUpdatesFullChunkCountAndByteBoundaries(t *testing.T) {
	s, dir := newUpdateFixture(t)
	a := reserve(t, s)
	raw, original := updatePayloads(t, a, updategeneration.MaxGenerationChunks)
	m, err := updategeneration.DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	m.ChunkCount = updategeneration.MaxGenerationChunks
	hash, err := updategeneration.ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(m)
	raw = append(raw, bytes.Repeat([]byte(" "), updategeneration.MaxManifestBytes-len(raw))...)
	var rows []cachedupdates.Candidate
	for _, b := range original {
		c, err := updategeneration.DecodeChunk(b)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, c.Items...)
	}
	chunks := make([][]byte, len(rows))
	previous := ""
	for i, row := range rows {
		c := updategeneration.Chunk{SchemaVersion: updategeneration.SchemaVersion, GenerationID: a.GenerationID, ManifestSHA256: hash, Ordinal: uint32(i), ChunkCount: uint32(len(rows)), RowOffset: uint64(i), PreviousSHA256: previous, Items: []cachedupdates.Candidate{row}}
		b, _ := json.Marshal(c)
		cut := bytes.LastIndex(b, []byte(`,"sha256":`))
		payload := append(bytes.Clone(b[:cut]), '}')
		c.SHA256 = digest(append([]byte("tracebolt.complete-cached-apt-updates.chunk.v1\x00"), payload...))
		previous = c.SHA256
		chunks[i], _ = json.Marshal(c)
	}
	chunks[0] = append(chunks[0], bytes.Repeat([]byte(" "), updategeneration.MaxChunkBytes-len(chunks[0]))...)
	if err = s.Stage(context.Background(), a, append(bytes.Clone(raw), ' '), chunks); !errors.Is(err, ErrBody) {
		t.Fatal("oversize manifest accepted", err)
	}
	over := append([][]byte(nil), chunks...)
	over[0] = append(bytes.Clone(chunks[0]), ' ')
	if err = s.Stage(context.Background(), a, raw, over); !errors.Is(err, ErrBody) {
		t.Fatal("oversize chunk accepted", err)
	}
	if err = s.Stage(context.Background(), a, raw, chunks); err != nil {
		t.Fatal("full advertised bounds rejected", err)
	}
	before := next(t, s)
	s = reopenUpdates(t, s, dir)
	if !sameWork(before, next(t, s)) {
		t.Fatal("boundary restart bytes changed")
	}
	if err = s.Acknowledge(before, updateReceipt(t, before)); err != nil {
		t.Fatal(err)
	}
	w := next(t, s)
	msg, err := inventorywire.DecodeCachedUpdatesMessage("append", w.Body())
	if err != nil || msg.UpdateChunk == nil || len(msg.UpdateChunk.Items) != 1 || !bytes.Contains(w.Body(), chunks[0]) {
		t.Fatal("raw full-size chunk not preserved", err)
	}
	// Storage limits intentionally remain the original package-transfer ceilings.
	if MaxRawBytes != updategeneration.MaxGenerationRawBytes || MaxPackBytes != MaxRawBytes+(updategeneration.MaxGenerationChunks+2)*1024 {
		t.Fatal("transfer limits diverged")
	}
}
