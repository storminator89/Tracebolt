package api

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateCompleteUpdatesFixture = flag.Bool("update-complete-updates-fixture", false, "Regenerate the explicitly synthetic complete-update Go/UI golden fixture")

func TestCompleteUpdatesGoDTOFixture(t *testing.T) {
	at := time.Date(2026, 10, 5, 4, 0, 0, 123456789, time.UTC)
	now := at.Add(10 * time.Second)
	oldest := at.Add(-72 * time.Hour)
	age := uint64(259200)
	device := "agent_" + strings.Repeat("a", 32)
	generation, e := inventorywire.CachedUpdatesGenerationID(device, 7)
	if e != nil {
		t.Fatal(e)
	}
	rows := []cachedupdates.Candidate{{Name: "fixture-curl", Architecture: "amd64", InstalledVersion: "1:8.14.1-2", CandidateVersion: "1:8.14.1-2+deb13u1", State: "candidate_only", Installability: "not_evaluated"}, {Name: "fixture-held", Architecture: "amd64", InstalledVersion: "2.0~rc1-1", CandidateVersion: "2.0-1", State: "held", Installability: "not_evaluated"}}
	id, version, codename := "debian", "13", "trixie"
	installed, checked, candidates, held, unknown := uint32(4), uint32(3), uint32(2), uint32(1), uint32(1)
	snapshot := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: generation, CollectedAt: at, DurationMS: 8, Release: linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}, Coverage: "partial", Reason: cachedupdates.ReasonCandidateUnknown, Metadata: cachedupdates.Metadata{Freshness: "stale", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &installed, CheckedCount: &checked, CandidateCount: &candidates, HeldCount: &held, UnknownCount: &unknown, Items: rows}
	m, chunks, e := updategeneration.Build(context.Background(), updategeneration.SourceInventory{Snapshot: snapshot, Rows: rows, Complete: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	v, e := updategeneration.NewValidator(context.Background(), m)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range chunks {
		if e = v.Add(c); e != nil {
			t.Fatal(e)
		}
	}
	if done, e := v.Finish(); e != nil || !done.Valid() {
		t.Fatal("fixture incomplete", e)
	}
	hash, _ := updategeneration.ManifestDigest(m)
	binding := enrollmentstore.InventoryBinding{Sequence: 7, GenerationID: generation, ManifestHash: hash}
	completed := at.Add(5 * time.Second)
	view, e := completeUpdatesView(enrollmentstore.CompleteUpdatesStatus{DeviceID: device, ServerNow: now, Status: "available", Sequence: 7, CompleteBinding: binding, Complete: &enrollmentstore.CompleteUpdatesGenerationStatus{Manifest: m, State: "complete", StartedAt: at.Add(time.Second), CompletedAt: completed, ExpiresAt: at.Add(inventoryledger.ObservationTTL), AcceptedChunks: m.ChunkCount, AcceptedRows: uint64(candidates)}})
	if e != nil {
		t.Fatal(e)
	}
	expired, e := completeUpdatesView(enrollmentstore.CompleteUpdatesStatus{DeviceID: device, ServerNow: at.Add(25 * time.Hour), Status: "unavailable", Sequence: 7, CompleteBinding: binding, Complete: &enrollmentstore.CompleteUpdatesGenerationStatus{Manifest: m, State: "expired", StartedAt: at.Add(time.Second), CompletedAt: completed, ExpiresAt: at.Add(inventoryledger.ObservationTTL)}})
	if e != nil || expired.Status != "unavailable" || expired.Complete == nil || expired.Complete.State != "expired" {
		t.Fatal("expired metadata became API error or current data", e)
	}
	page := completeUpdatesPage(device, now, enrollmentstore.CompleteUpdatesPageResult{Binding: binding, Manifest: m, CompletedAt: completed, ServerNow: now, Items: rows, TotalRows: uint64(candidates), ScannedRows: len(rows), Exhausted: true, CursorExpiresAt: now.Add(inventoryledger.CursorTTL)})
	fixture := struct {
		View completeUpdateView `json:"view"`
		Page completeUpdatePage `json:"page"`
	}{view, page}
	raw, e := json.MarshalIndent(fixture, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "web", "src", "complete-updates-go-fixture.json")
	if *updateCompleteUpdatesFixture {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	expected, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatal("Go/UI fixture differs; review and explicitly regenerate synthetic bytes")
	}
}
