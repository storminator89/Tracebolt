package updategeneration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/linuxpackages"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sourceFixture(t testing.TB, n int) SourceInventory {
	t.Helper()
	at := time.Date(2026, 10, 5, 4, 0, 0, 123456789, time.UTC)
	oldest := at.Add(-72 * time.Hour)
	age := uint64(72 * 60 * 60)
	id, version, codename := "debian", "13", "trixie"
	rows := make([]cachedupdates.Candidate, 0, n)
	held := uint32(0)
	for i := 0; i < n; i++ {
		state := "candidate_only"
		if i%7 == 0 {
			state = "held"
			held++
		}
		rows = append(rows, cachedupdates.Candidate{Name: fmt.Sprintf("fixture-update-%06d", i), Architecture: "amd64", InstalledVersion: "1:1.0~rc1-1", CandidateVersion: "2:1.0-1", State: state, Installability: "not_evaluated"})
	}
	candidates, installed, unknown := uint32(n), uint32(min(n+2, MaxGenerationRows)), uint32(0)
	checked := installed
	s := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: "sample_00112233445566778899aabbccddeeff", CollectedAt: at, DurationMS: 31, Release: linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}, Metadata: cachedupdates.Metadata{Freshness: "stale", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &installed, CheckedCount: &checked, CandidateCount: &candidates, HeldCount: &held, UnknownCount: &unknown, Coverage: "complete", Reason: cachedupdates.ReasonNone, Items: append([]cachedupdates.Candidate{}, rows[:min(n, cachedupdates.MaxRows)]...)}
	if n > len(s.Items) {
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = cachedupdates.ReasonItemLimit
	}
	for cachedupdates.Validate(s) != nil {
		if len(s.Items) == 0 {
			t.Fatal("invalid fixture metadata")
		}
		s.Items = s.Items[:len(s.Items)-1]
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = cachedupdates.ReasonByteLimit
	}
	return SourceInventory{Snapshot: s, Rows: rows, Complete: true}
}
func built(t testing.TB, n int) (Manifest, []Chunk) {
	t.Helper()
	m, chunks, err := Build(context.Background(), sourceFixture(t, n), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, chunks
}
func complete(t testing.TB, m Manifest, chunks []Chunk) Complete {
	t.Helper()
	v, err := NewValidator(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chunks {
		if err = v.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	result, err := v.Finish()
	if err != nil || !result.Valid() {
		t.Fatal("not complete", err)
	}
	return result
}
func TestCompleteKnownCandidatesExceedPreviewAndOneThousandRows(t *testing.T) {
	s := sourceFixture(t, 1201)
	m, chunks, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.CandidateCount != 1201 || m.ChunkCount < 10 || m.InstalledCount != *s.Snapshot.InstalledCount || m.CheckedCount != *s.Snapshot.CheckedCount || m.HeldCount != *s.Snapshot.HeldCount || m.UnknownCount != 0 || m.ComparisonCoverage != "complete" || m.ComparisonReason != cachedupdates.ReasonNone || !m.CollectedAt.Equal(s.Snapshot.CollectedAt) || !reflect.DeepEqual(m.Metadata, s.Snapshot.Metadata) || !reflect.DeepEqual(m.Release, s.Snapshot.Release) {
		t.Fatal("original full metadata lost")
	}
	count := 0
	canonical := []byte(rowDomain)
	wire := 0
	mb, _ := json.Marshal(m)
	wire += len(mb)
	for _, c := range chunks {
		raw, _ := json.Marshal(c)
		if len(c.Items) > MaxChunkRows || len(raw) > MaxChunkBytes {
			t.Fatal("unbounded chunk")
		}
		if _, err := DecodeChunk(raw); err != nil {
			t.Fatal(err)
		}
		count += len(c.Items)
		wire += len(raw)
		for _, r := range c.Items {
			canonical = append(canonical, canonicalRow(r)...)
		}
	}
	sum := sha256.Sum256(canonical)
	if count != 1201 || m.RowsSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("full canonical row digest mismatch")
	}
	proof := complete(t, m, chunks)
	if proof.CanonicalWireBytes() != uint64(wire) || !reflect.DeepEqual(proof.Manifest(), m) || proof.LastChunkSHA256() != chunks[len(chunks)-1].SHA256 {
		t.Fatal("bad consistency receipt")
	}
	if _, err := DecodeManifest(mb); err != nil {
		t.Fatal(err)
	}
	// Input order does not change canonical rows or exact manifest/chunk bytes.
	for i, j := 0, len(s.Rows)-1; i < j; i, j = i+1, j-1 {
		s.Rows[i], s.Rows[j] = s.Rows[j], s.Rows[i]
	}
	m2, c2, err := Build(context.Background(), s, nil)
	if err != nil || !reflect.DeepEqual(m, m2) || !reflect.DeepEqual(chunks, c2) {
		t.Fatal("canonical order unstable", err)
	}
}
func TestFullRowsDoNotTurnUnknownComparisonsIntoCurrent(t *testing.T) {
	s := sourceFixture(t, 400)
	*s.Snapshot.UnknownCount = 1
	*s.Snapshot.CheckedCount--
	// Existing preview truncation can hide the comparison reason, never its count.
	m, chunks, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	proof := complete(t, m, chunks)
	if proof.Manifest().ComparisonCoverage != "partial" || proof.Manifest().ComparisonReason != cachedupdates.ReasonCandidateUnknown || proof.Manifest().UnknownCount != 1 {
		t.Fatal("unknown comparison became complete")
	}
	s = sourceFixture(t, 0)
	*s.Snapshot.UnknownCount = 1
	*s.Snapshot.CheckedCount--
	s.Snapshot.Coverage = "partial"
	s.Snapshot.Reason = cachedupdates.ReasonCandidateUnknown
	m, chunks, err = Build(context.Background(), s, nil)
	if err != nil || len(chunks) != 0 {
		t.Fatal(err)
	}
	proof = complete(t, m, chunks)
	if proof.Manifest().ComparisonCoverage != "partial" || proof.Manifest().UnknownCount != 1 || proof.Manifest().CandidateCount != 0 {
		t.Fatal("empty known set misreported")
	}
}
func TestBuildRejectsMissingSourcePrefixAndPreviewMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*SourceInventory){
		"incomplete": func(s *SourceInventory) { s.Complete = false },
		"nil-rows":   func(s *SourceInventory) { s.Rows = nil },
		"prefix":     func(s *SourceInventory) { s.Rows = s.Rows[:3] },
		"unavailable": func(s *SourceInventory) {
			s.Snapshot = cachedupdates.Empty(s.Snapshot.GenerationID, s.Snapshot.CollectedAt, cachedupdates.ReasonTimeout)
		},
		"preview-mismatch":      func(s *SourceInventory) { s.Snapshot.Items[0].CandidateVersion = "3:1.0-1" },
		"held-mismatch":         func(s *SourceInventory) { s.Rows[len(s.Rows)-1].State = "held" },
		"missing-count":         func(s *SourceInventory) { s.Snapshot.CheckedCount = nil },
		"false-cache-freshness": func(s *SourceInventory) { s.Snapshot.Metadata.Freshness = "fresh" },
		"replaced-cache-age":    func(s *SourceInventory) { *s.Snapshot.Metadata.AgeSeconds = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			s := sourceFixture(t, 1000)
			mutate(&s)
			m, chunks, err := Build(context.Background(), s, nil)
			if err == nil || !reflect.DeepEqual(m, Manifest{}) || chunks != nil {
				t.Fatal("usable prefix on failure", err)
			}
		})
	}
	s := sourceFixture(t, 1000)
	if m, c, e := Build(context.Background(), s, errors.New("source changed")); !errors.Is(e, ErrSource) || !reflect.DeepEqual(m, Manifest{}) || c != nil {
		t.Fatal("source error discarded")
	}
	s = sourceFixture(t, 0)
	s.Rows = nil
	if _, _, e := Build(context.Background(), s, nil); !errors.Is(e, ErrSource) {
		t.Fatal("nil rows became successful zero")
	}
}
func TestBuildRejectsDuplicateIdentityAndBounds(t *testing.T) {
	s := sourceFixture(t, 1000)
	s.Rows[999] = s.Rows[998]
	if _, _, e := Build(context.Background(), s, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("duplicate identity", e)
	}
	s = sourceFixture(t, 1000)
	s.Rows[999].Name = strings.Repeat("a", 257)
	if _, _, e := Build(context.Background(), s, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal("oversized row", e)
	}
	s = sourceFixture(t, 0)
	s.Rows = make([]cachedupdates.Candidate, MaxGenerationRows+1)
	if _, _, e := Build(context.Background(), s, nil); !errors.Is(e, ErrLimit) {
		t.Fatal("row cap", e)
	}
}
func TestBuildDetachesRowsAndOriginalMetadata(t *testing.T) {
	s := sourceFixture(t, 129)
	m, chunks, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := json.Marshal(struct {
		M Manifest
		C []Chunk
	}{m, chunks})
	s.Rows[0].Name = "changed-input"
	*s.Snapshot.Release.ID = "ubuntu"
	*s.Snapshot.Metadata.AgeSeconds = 0
	*s.Snapshot.Metadata.OldestIndexModifiedAt = s.Snapshot.CollectedAt
	now, _ := json.Marshal(struct {
		M Manifest
		C []Chunk
	}{m, chunks})
	if !bytes.Equal(initial, now) {
		t.Fatal("caller mutation changed frozen output")
	}
	first := chunks[1].Items[0]
	appended := append(chunks[0].Items, cachedupdates.Candidate{Name: "append"})
	appended[len(appended)-1].Name = "another"
	if chunks[1].Items[0] != first {
		t.Fatal("chunk append overwrote sibling")
	}
	v, _ := NewValidator(context.Background(), m)
	*m.Release.ID = "mutated-after-validator"
	for _, c := range chunks {
		if err := v.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := v.Finish()
	if err != nil {
		t.Fatal(err)
	}
	detached := proof.Manifest()
	*detached.Release.ID = "mutated-receipt"
	*detached.Metadata.AgeSeconds = 0
	if *proof.Manifest().Release.ID != "debian" || *proof.Manifest().Metadata.AgeSeconds == 0 {
		t.Fatal("receipt exposed mutable state")
	}
}
func TestChunkByteBoundSplitsBeforeRowBound(t *testing.T) {
	s := sourceFixture(t, 300)
	for i := range s.Rows {
		s.Rows[i].InstalledVersion = "1" + strings.Repeat("a", 500)
		s.Rows[i].CandidateVersion = "2" + strings.Repeat("a", 500)
	}
	s.Snapshot.Items = []cachedupdates.Candidate{}
	s.Snapshot.Coverage = "partial"
	s.Snapshot.Reason = cachedupdates.ReasonByteLimit
	s.Snapshot.Truncated = true
	m, chunks, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 6 || len(chunks[0].Items) >= MaxChunkRows {
		t.Fatal("byte splitting not applied")
	}
	complete(t, m, chunks)
}
func TestDistinctDomainsAndEmptySuccess(t *testing.T) {
	m, chunks := built(t, 0)
	if chunks == nil || len(chunks) != 0 || m.CandidateCount != 0 || m.ChunkCount != 0 || m.RowsSHA256 != hashHex(newRowsHash()) {
		t.Fatal("empty scope")
	}
	complete(t, m, chunks)
	old := sha256.Sum256([]byte("tracebolt.complete-linux-packages.rows.v1\x00"))
	if m.RowsSHA256 == hex.EncodeToString(old[:]) {
		t.Fatal("package domain reused")
	}
	md, err := ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	plain := sha256.Sum256(b)
	if md == hex.EncodeToString(plain[:]) || md == m.RowsSHA256 {
		t.Fatal("undomained digest")
	}
}

func TestFullSupportedCandidateCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("separate full 16,384-candidate boundary")
	}
	m, chunks := built(t, MaxGenerationRows)
	if m.CandidateCount != MaxGenerationRows || chunks[len(chunks)-1].Items[len(chunks[len(chunks)-1].Items)-1].Name != "fixture-update-016383" {
		t.Fatal("supported tail lost")
	}
	result := complete(t, m, chunks)
	if result.Manifest().CandidateCount != MaxGenerationRows {
		t.Fatal("incomplete maximum receipt")
	}
}
