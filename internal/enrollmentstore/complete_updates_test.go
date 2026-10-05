package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
)

func completeUpdatesFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f, s, path, snap, cert := completeFixture(t)
	if e := s.InitializeCompleteUpdates(context.Background()); e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, cert
}
func completeUpdatesSource(t testing.TB, device string, seq uint64, n int, at time.Time) updategeneration.SourceInventory {
	t.Helper()
	generation, e := inventorywire.CachedUpdatesGenerationID(device, seq)
	if e != nil {
		t.Fatal(e)
	}
	rows := make([]cachedupdates.Candidate, n)
	held := uint32(0)
	for i := range rows {
		state := "candidate_only"
		if i%7 == 0 {
			state = "held"
			held++
		}
		rows[i] = cachedupdates.Candidate{Name: fmt.Sprintf("fixture-update-%06d", i), Architecture: "amd64", InstalledVersion: "1:1.0~rc1-1", CandidateVersion: "2:1.0-1", State: state, Installability: "not_evaluated"}
	}
	candidates, installed, unknown := uint32(n), uint32(min(n+2, updategeneration.MaxGenerationRows)), uint32(0)
	checked := installed
	oldest, age := at.Add(-72*time.Hour), uint64(72*60*60)
	release, version, codename := "debian", "13", "trixie"
	snapshot := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: generation, CollectedAt: at, DurationMS: 31, Release: linuxpackages.ReleaseFields{ID: &release, VersionID: &version, VersionCodename: &codename}, Metadata: cachedupdates.Metadata{Freshness: "stale", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &installed, CheckedCount: &checked, CandidateCount: &candidates, HeldCount: &held, UnknownCount: &unknown, Coverage: "complete", Reason: cachedupdates.ReasonNone, Items: append([]cachedupdates.Candidate{}, rows[:min(n, cachedupdates.MaxRows)]...)}
	if n > len(snapshot.Items) {
		snapshot.Truncated = true
		snapshot.Coverage = "partial"
		snapshot.Reason = cachedupdates.ReasonItemLimit
	}
	for cachedupdates.Validate(snapshot) != nil {
		if len(snapshot.Items) == 0 {
			t.Fatal("invalid complete updates source fixture")
		}
		snapshot.Items = snapshot.Items[:len(snapshot.Items)-1]
		snapshot.Truncated = true
		snapshot.Coverage = "partial"
		snapshot.Reason = cachedupdates.ReasonByteLimit
	}
	return updategeneration.SourceInventory{Snapshot: snapshot, Rows: rows, Complete: true}
}
func buildCompleteUpdates(t testing.TB, seq uint64, source updategeneration.SourceInventory) (InventoryBinding, updategeneration.Manifest, []updategeneration.Chunk) {
	t.Helper()
	m, chunks, e := updategeneration.Build(context.Background(), source, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := updategeneration.ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	return InventoryBinding{Sequence: seq, GenerationID: m.GenerationID, ManifestHash: hash}, m, chunks
}
func updatesGenerationFixture(t testing.TB, device string, seq uint64, n int, at time.Time) (InventoryBinding, updategeneration.Manifest, []updategeneration.Chunk) {
	t.Helper()
	return buildCompleteUpdates(t, seq, completeUpdatesSource(t, device, seq, n, at))
}
func stageCompleteUpdates(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b InventoryBinding, m updategeneration.Manifest, chunks []updategeneration.Chunk, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal(e)
	}
	for _, c := range chunks {
		if _, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at); e != nil {
			t.Fatal(e)
		}
	}
}
func promoteCompleteUpdates(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b InventoryBinding, m updategeneration.Manifest, chunks []updategeneration.Chunk, at time.Time) {
	t.Helper()
	stageCompleteUpdates(t, s, snap, cert, b, m, chunks, at)
	if _, e := s.CompleteUpdatesFinalize(context.Background(), snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal(e)
	}
}

func TestCompleteUpdatesRealAuthorityPaginationReplayAndRestart(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 123456789).UTC()
	b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 7, 1301, at)
	begin, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at.Add(time.Second))
	if e != nil || retry != begin {
		t.Fatalf("begin retry refreshed receipt: %+v %v", retry, e)
	}
	first, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunks[0], at.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrIncomplete) || !reflect.DeepEqual(got, CompleteUpdatesCompletion{}) {
		t.Fatal("partial promotion", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	status, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(3*time.Second))
	if e != nil || status.Transfer == nil || status.Transfer.AcceptedChunks != 1 || status.Transfer.AcceptedRows != uint64(len(chunks[0].Items)) {
		t.Fatalf("restart lost transfer: %+v %v", status, e)
	}
	again, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunks[0], at.Add(3*time.Second))
	if e != nil || again != first {
		t.Fatal("restart replay refreshed chunk", e)
	}
	for _, c := range chunks[1:] {
		got, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(4*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		again, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(4*time.Second))
		if e != nil || again != got {
			t.Fatal("chunk retry changed", e)
		}
	}
	completed, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(5*time.Second))
	if e != nil || completed.Manifest.CandidateCount != 1301 || !reflect.DeepEqual(completed.Manifest, m) {
		t.Fatal("full manifest lost", e)
	}
	finalRetry, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(6*time.Second))
	if e != nil || !reflect.DeepEqual(finalRetry, completed) {
		t.Fatal("completion replay changed", e)
	}
	if e = s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(6*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("aborted completed generation", e)
	}
	s.Close()
	s = f.open(t, path)
	now := at.Add(7 * time.Second)
	view, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now)
	if e != nil || view.Complete == nil || view.Complete.Manifest.CandidateCount != 1301 || view.CompleteBinding != b {
		t.Fatalf("reopen current: %+v %v", view, e)
	}
	var got []cachedupdates.Candidate
	req := inventoryledger.PageRequest{Limit: 37}
	for n := 0; n < 40; n++ {
		page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, req, now)
		if e != nil || page.Binding != b || page.TotalRows != 1301 || !reflect.DeepEqual(page.Manifest, m) {
			t.Fatalf("page: %+v %v", page, e)
		}
		got = append(got, page.Items...)
		if page.Exhausted {
			break
		}
		if page.NextCursor == "" {
			t.Fatal("missing continuation")
		}
		req.Cursor = page.NextCursor
	}
	if len(got) != 1301 {
		t.Fatal("preview prefix or duplicate", len(got))
	}
	for i, p := range got {
		if p.Name != fmt.Sprintf("fixture-update-%06d", i) || p.Installability != "not_evaluated" {
			t.Fatal("lost canonical candidate", i, p)
		}
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snap.InvitationID].Replay.Sequence != 0 || len(tx.inventory) != 0 || len(tx.system) != 0 {
			t.Fatal("complete updates advanced another sequence domain")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// The exact same numeric sequence remains independently usable for packages.
	pb, pm, pc := completeGeneration(t, snap.Approval.DeviceID, 7, 1, now)
	if pb.GenerationID == b.GenerationID {
		t.Fatal("generation identity domain reused")
	}
	promoteComplete(t, s, snap, cert, pb, pm, pc, now)
	view, e = s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now)
	if e != nil || view.CompleteBinding != b {
		t.Fatal("package report replaced updates", e)
	}
}

func TestCompleteUpdatesPendingAbortAndFailurePreservePrevious(t *testing.T) {
	f, s, path, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 513, at)
	promoteCompleteUpdates(t, s, snap, cert, old, m, chunks, at)
	next, m2, chunks2 := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 700, at.Add(time.Second))
	stageCompleteUpdates(t, s, snap, cert, next, m2, chunks2[:1], at.Add(time.Second))
	check := func(now time.Time) CompleteUpdatesStatus {
		t.Helper()
		v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now)
		if e != nil || v.Complete == nil || v.CompleteBinding != old || !reflect.DeepEqual(v.Complete.Manifest, m) {
			t.Fatalf("old current erased: %+v %v", v, e)
		}
		p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, now)
		if e != nil || p.Binding != old || p.TotalRows != 513 {
			t.Fatal("old page hidden", e)
		}
		return v
	}
	check(at.Add(2 * time.Second))
	if _, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrIncomplete) {
		t.Fatal(e)
	}
	if e := s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(4*time.Second)); e != nil {
		t.Fatal("abort retry", e)
	}
	check(at.Add(4 * time.Second))
	s.Close()
	s = f.open(t, path)
	for _, x := range []struct {
		b InventoryBinding
		m updategeneration.Manifest
	}{{old, m}, {next, m2}} {
		if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), x.b, x.m, at.Add(5*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
			t.Fatal("aborted floor reused", e)
		}
	}
	generation, _ := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, 3)
	failure := InventoryFailureReport{Sequence: 3, GenerationID: generation, AttemptedAt: at.Add(5 * time.Second), Reason: "source_missing"}
	receipt, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(6*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(7*time.Second))
	if e != nil || receipt != retry {
		t.Fatal("failure replay refreshed age", e)
	}
	v := check(at.Add(7 * time.Second))
	if v.Failure == nil || *v.Failure != receipt || v.Sequence != 3 {
		t.Fatal("failure receipt lost")
	}
	failure.Reason = "source_invalid"
	if _, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(8*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("failure mutated", e)
	}
}

func TestCompleteUpdatesUnknownComparisonsAndEmptyKnownSet(t *testing.T) {
	for _, n := range []int{0, 400} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			_, s, _, snap, cert := completeUpdatesFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			source := completeUpdatesSource(t, snap.Approval.DeviceID, 1, n, at)
			*source.Snapshot.UnknownCount = 1
			*source.Snapshot.CheckedCount--
			if n == 0 {
				source.Snapshot.Coverage = "partial"
				source.Snapshot.Reason = cachedupdates.ReasonCandidateUnknown
			}
			b, m, c := buildCompleteUpdates(t, 1, source)
			promoteCompleteUpdates(t, s, snap, cert, b, m, c, at)
			p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 100}, at)
			if e != nil || p.Manifest.ComparisonCoverage != "partial" || p.Manifest.ComparisonReason != cachedupdates.ReasonCandidateUnknown || p.Manifest.UnknownCount != 1 || p.TotalRows != uint64(n) || !reflect.DeepEqual(p.Manifest.Metadata, source.Snapshot.Metadata) || !reflect.DeepEqual(p.Manifest.Release, source.Snapshot.Release) {
				t.Fatalf("unknowns or original metadata lost: %+v %v", p, e)
			}
			if n == 0 && (p.Items == nil || !p.Exhausted || p.NextCursor != "") {
				t.Fatal("empty known set not explicit")
			}
		})
	}
}

func TestCompleteUpdatesExpiryAndAuthorityRevocation(t *testing.T) {
	t.Run("capture-and-cursor-age", func(t *testing.T) {
		_, s, _, snap, cert := completeUpdatesFixture(t)
		ctx := context.Background()
		at := time.Unix(testNow+10, 0).UTC()
		b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 300, at.Add(-time.Hour))
		promoteCompleteUpdates(t, s, snap, cert, b, m, c, at)
		p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at)
		if e != nil {
			t.Fatal(e)
		}
		if page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, Cursor: p.NextCursor}, at.Add(inventoryledger.CursorTTL)); !errors.Is(e, inventoryledger.ErrCursorExpired) || !reflect.DeepEqual(page, CompleteUpdatesPageResult{}) {
			t.Fatal("expired cursor succeeded", e)
		}
		expired := m.CollectedAt.Add(inventoryledger.ObservationTTL)
		v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, expired)
		if e != nil || v.Complete == nil || v.Complete.State != "expired" || !v.Complete.ExpiresAt.Equal(expired) || !reflect.DeepEqual(v.Complete.Manifest, m) {
			t.Fatalf("original expiry metadata lost: %+v %v", v, e)
		}
		if page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, expired); !errors.Is(e, inventoryledger.ErrExpired) || !reflect.DeepEqual(page, CompleteUpdatesPageResult{}) {
			t.Fatal("expired rows leaked", e)
		}
		next, m2, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 10, expired)
		if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), next, m2, expired); e != nil {
			t.Fatal(e)
		}
		v, e = s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, expired.Add(inventoryledger.StagingTTL))
		if e != nil || v.Transfer == nil || v.Transfer.State != "expired" || v.Complete.State != "expired" {
			t.Fatal("staging expiry lost", e)
		}
	})
	t.Run("fresh-authority-on-every-operation", func(t *testing.T) {
		f, s, path, snap, cert := completeUpdatesFixture(t)
		ctx := context.Background()
		at := time.Unix(testNow+10, 0).UTC()
		b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 300, at)
		if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, strings.Repeat("1", 64), b, m, at); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal("wrong issued leaf", e)
		}
		foreign, fm, _ := updatesGenerationFixture(t, id("agent", 9), 1, 1, at)
		if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), foreign, fm, at); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal("foreign device binding", e)
		}
		stageCompleteUpdates(t, s, snap, cert, b, m, c, at)
		if _, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
			t.Fatal("clock regression", e)
		}
		other := f.open(t, path)
		revoke := control(snap, 77)
		revoke.Now = at.Add(time.Second).Unix()
		if _, e := other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
			t.Fatal(e)
		}
		now := at.Add(2 * time.Second)
		if got, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, now); !errors.Is(e, enrollmentstate.ErrState) || !reflect.DeepEqual(got, CompleteUpdatesCompletion{}) {
			t.Fatal("revoked finalize", e)
		}
		if _, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c[0], now); !errors.Is(e, enrollmentstate.ErrState) {
			t.Fatal("revoked exact replay", e)
		}
		if _, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, now); !errors.Is(e, enrollmentstate.ErrState) {
			t.Fatal("revoked operator view", e)
		}
		if _, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, now); !errors.Is(e, enrollmentstate.ErrState) {
			t.Fatal("revoked operator page", e)
		}
	})
}

func TestCompleteUpdatesPinnedSignedBoundedSearchCursors(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 2300, at)
	promoteCompleteUpdates(t, s, snap, cert, b, m, c, at)
	first, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at)
	if e != nil {
		t.Fatal(e)
	}
	search := inventoryledger.PageRequest{Limit: 10, Search: "fixture-update-002299"}
	p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, search, at)
	if e != nil || len(p.Items) != 0 || p.ScannedRows != inventoryledger.MaxScanRows || p.Exhausted || !p.SearchIncomplete || p.NextCursor == "" {
		t.Fatalf("unbounded or falsely exhaustive search: %+v %v", p, e)
	}
	search.Cursor = p.NextCursor
	q, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, search, at)
	if e != nil || len(q.Items) != 1 || q.Items[0].Name != "fixture-update-002299" || !q.Exhausted || q.SearchIncomplete || q.ScannedRows != 2300-inventoryledger.MaxScanRows {
		t.Fatalf("tail search lost: %+v %v", q, e)
	}
	empty, em, ec := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 0, at.Add(time.Second))
	promoteCompleteUpdates(t, s, snap, cert, empty, em, ec, at.Add(time.Second))
	now := at.Add(2 * time.Second)
	old, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, Cursor: first.NextCursor, GenerationID: b.GenerationID}, now)
	if e != nil || old.Binding != b || len(old.Items) != 10 || old.Items[0].Name != "fixture-update-000010" || !old.CursorExpiresAt.Equal(first.CursorExpiresAt) {
		t.Fatal("cursor mixed generation or refreshed expiry", e)
	}
	zero, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, now)
	if e != nil || zero.Binding != empty || zero.Items == nil || len(zero.Items) != 0 || zero.TotalRows != 0 || !zero.Exhausted {
		t.Fatalf("explicit zero mishandled: %+v %v", zero, e)
	}
	for name, req := range map[string]inventoryledger.PageRequest{"limit": {Limit: 11, Cursor: first.NextCursor}, "query": {Limit: 10, Search: "changed", Cursor: first.NextCursor}, "generation": {Limit: 10, GenerationID: empty.GenerationID, Cursor: first.NextCursor}, "signature": {Limit: 10, Cursor: first.NextCursor + "x"}} {
		t.Run(name, func(t *testing.T) {
			page, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, req, now)
			if !errors.Is(e, inventoryledger.ErrCursor) || !reflect.DeepEqual(page, CompleteUpdatesPageResult{}) {
				t.Fatal("cursor rebind accepted", e)
			}
		})
	}
	for _, req := range []inventoryledger.PageRequest{{Limit: 0}, {Limit: 101}, {Limit: 1, Search: strings.Repeat("x", 129)}, {Limit: 1, Search: "\x00"}} {
		if p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, req, now); e == nil || !reflect.DeepEqual(p, CompleteUpdatesPageResult{}) {
			t.Fatal("unbounded request accepted", e)
		}
	}
	if p, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, GenerationID: b.GenerationID}, now); !errors.Is(e, inventoryledger.ErrCursorExpired) || !reflect.DeepEqual(p, CompleteUpdatesPageResult{}) {
		t.Fatal("unpinned retired read allowed", e)
	}
}

func TestCompleteUpdatesTamperedPayloadsFailClosed(t *testing.T) {
	for _, phase := range []string{"finalize", "page"} {
		for _, part := range []string{"row-body", "row-hash", "chunk-body", "missing-row", "missing-chunk"} {
			// Completed pages use normalized rows, not retained transport chunks.
			if phase == "page" && (part == "chunk-body" || part == "missing-chunk") {
				continue
			}
			t.Run(phase+"/"+part, func(t *testing.T) {
				_, s, _, snap, cert := completeUpdatesFixture(t)
				ctx := context.Background()
				at := time.Unix(testNow+10, 0).UTC()
				b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 300, at)
				stageCompleteUpdates(t, s, snap, cert, b, m, c, at)
				if phase == "page" {
					if _, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
						t.Fatal(e)
					}
				}
				var e error
				switch part {
				case "row-body":
					row := c[0].Items[0]
					row.CandidateVersion = "3:1.0-1"
					raw, _ := json.Marshal(row)
					_, e = s.db.Exec(`UPDATE enrollment_complete_updates_rows SET body=? WHERE device=? AND generation=? AND ordinal=0`, raw, snap.Approval.DeviceID, b.GenerationID)
				case "row-hash":
					_, e = s.db.Exec(`UPDATE enrollment_complete_updates_rows SET body_hash=? WHERE device=? AND generation=? AND ordinal=0`, strings.Repeat("0", 64), snap.Approval.DeviceID, b.GenerationID)
				case "chunk-body":
					raw, _ := json.Marshal(c[0])
					raw = bytes.Replace(raw, []byte("2:1.0-1"), []byte("3:1.0-1"), 1)
					_, e = s.db.Exec(`UPDATE enrollment_complete_updates_chunks SET body=? WHERE device=? AND generation=? AND ordinal=0`, raw, snap.Approval.DeviceID, b.GenerationID)
				case "missing-row":
					_, e = s.db.Exec(`DELETE FROM enrollment_complete_updates_rows WHERE device=? AND generation=? AND ordinal=0`, snap.Approval.DeviceID, b.GenerationID)
				case "missing-chunk":
					_, e = s.db.Exec(`DELETE FROM enrollment_complete_updates_chunks WHERE device=? AND generation=? AND ordinal=0`, snap.Approval.DeviceID, b.GenerationID)
				}
				if e != nil {
					t.Fatal(e)
				}
				if phase == "finalize" {
					got, e := s.CompleteUpdatesFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second))
					if !errors.Is(e, ErrStorage) || !reflect.DeepEqual(got, CompleteUpdatesCompletion{}) {
						t.Fatal("tampered promotion succeeded", e)
					}
				} else {
					got, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at.Add(time.Second))
					if !errors.Is(e, ErrStorage) || !reflect.DeepEqual(got, CompleteUpdatesPageResult{}) {
						t.Fatal("tampered page succeeded", e)
					}
				}
			})
		}
	}
}

func TestCompleteUpdatesDeclaredQuotaRollbackPreservesCurrent(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 1, at)
	promoteCompleteUpdates(t, s, snap, cert, old, m, c, at)
	// Reserve a large valid declared chunk set without allocating source payload.
	makeReservation := func(seq uint64) (InventoryBinding, updategeneration.Manifest) {
		b, m, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, seq, 1024, at)
		m.ChunkCount = 1024
		var e error
		b.ManifestHash, e = updategeneration.ManifestDigest(m)
		if e != nil {
			t.Fatal(e)
		}
		return b, m
	}
	b2, m2 := makeReservation(2)
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b2, m2, at); e != nil {
		t.Fatal(e)
	}
	if e := s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b2, at); e != nil {
		t.Fatal(e)
	}
	b3, m3 := makeReservation(3)
	got, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b3, m3, at)
	if !errors.Is(e, inventoryledger.ErrQuota) || got != (inventoryledger.BeginReceipt{}) {
		t.Fatal("declared chunk budget not enforced", e)
	}
	v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at)
	if e != nil || v.CompleteBinding != old || v.Sequence != 2 {
		t.Fatal("quota rejection replaced current or spent floor", e)
	}
	var generations, chunks int
	if e = s.db.QueryRow(`SELECT count(*),sum(declared_chunks) FROM enrollment_complete_updates_generations`).Scan(&generations, &chunks); e != nil || generations != 2 || chunks != 1025 {
		t.Fatal("quota rejection leaked reservation", generations, chunks, e)
	}
	small, sm, sc := updatesGenerationFixture(t, snap.Approval.DeviceID, 3, 1, at)
	promoteCompleteUpdates(t, s, snap, cert, small, sm, sc, at)
	b4, m4, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 4, 0, at)
	if _, e = s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b4, m4, at); !errors.Is(e, inventoryledger.ErrQuota) {
		t.Fatal("generation allowance not enforced", e)
	}
}

func TestCompleteUpdatesOptionalStrictSchemaAndLegacyBytes(t *testing.T) {
	t.Run("absent-until-explicit-init", func(t *testing.T) {
		f, s, path, snap, cert := completeFixture(t)
		ctx := context.Background()
		at := time.Unix(testNow+10, 0).UTC()
		var count int
		if e := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_complete_updates_%'`).Scan(&count); e != nil || count != 0 {
			t.Fatal("fresh profile implicitly enabled extension", e)
		}
		var ledger, credential []byte
		if e := s.db.QueryRow(`SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&ledger); e != nil {
			t.Fatal(e)
		}
		if e := s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, snap.InvitationID).Scan(&credential); e != nil {
			t.Fatal(e)
		}
		b, m, _ := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 1, at)
		if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); !errors.Is(e, ErrCompleteUpdatesNotConfigured) {
			t.Fatal("unconfigured write succeeded", e)
		}
		s.Close()
		s = f.open(t, path)
		if e := s.InitializeCompleteUpdates(ctx); e != nil {
			t.Fatal(e)
		}
		var key []byte
		if e := s.db.QueryRow(`SELECT cursor_key FROM enrollment_complete_updates_meta WHERE id=1`).Scan(&key); e != nil {
			t.Fatal(e)
		}
		if e := s.InitializeCompleteUpdates(ctx); e != nil {
			t.Fatal("idempotent initialization", e)
		}
		var secondKey, afterLedger, afterCredential []byte
		s.db.QueryRow(`SELECT cursor_key FROM enrollment_complete_updates_meta WHERE id=1`).Scan(&secondKey)
		s.db.QueryRow(`SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&afterLedger)
		s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, snap.InvitationID).Scan(&afterCredential)
		if !bytes.Equal(key, secondKey) || !bytes.Equal(ledger, afterLedger) || !bytes.Equal(credential, afterCredential) {
			t.Fatal("initialization rewrote old authority or cursor key")
		}
		v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at)
		if e != nil || v.Status != "awaiting" || v.Complete != nil || v.Transfer != nil || v.Sequence != 0 {
			t.Fatalf("initialization fabricated collection: %+v %v", v, e)
		}
	})
	t.Run("legacy-profile-denied", func(t *testing.T) {
		_, s, _ := fixtureStore(t)
		if e := s.InitializeCompleteUpdates(context.Background()); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal("legacy profile upgraded", e)
		}
	})
	for name, sql := range map[string]string{"extra-index": `CREATE INDEX unexpected_updates_index ON enrollment_complete_updates_rows(generation)`, "partial-schema": `DROP TABLE enrollment_complete_updates_rows`} {
		t.Run(name, func(t *testing.T) {
			f, s, path, _, _ := completeUpdatesFixture(t)
			if _, e := s.db.Exec(sql); e != nil {
				t.Fatal(e)
			}
			s.Close()
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if reopened, e := Open(path, f.config, f.issuerDER); e == nil {
				reopened.Close()
				t.Fatal("non-exact schema accepted")
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("failed reopen mutated schema", e)
			}
		})
	}
}

func TestCompleteUpdatesTrustedClockSuppressesExpiredReadResults(t *testing.T) {
	for _, kind := range []string{"view", "status", "page"} {
		t.Run(kind, func(t *testing.T) {
			_, s, _, snap, cert := completeUpdatesFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 3, at.Add(-time.Hour))
			promoteCompleteUpdates(t, s, snap, cert, b, m, c, at)
			expiry := m.CollectedAt.Add(inventoryledger.ObservationTTL)
			calls := 0
			ctx := WithCompleteUpdatesClock(context.Background(), func() time.Time {
				calls++
				if calls == 1 {
					return expiry.Add(-time.Nanosecond)
				}
				return expiry
			})
			switch kind {
			case "view":
				out, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at)
				if !errors.Is(e, inventoryledger.ErrExpired) || !reflect.DeepEqual(out, CompleteUpdatesStatus{}) {
					t.Fatal("post-commit expired view returned data", e)
				}
			case "status":
				out, e := s.CompleteUpdatesStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, at)
				if !errors.Is(e, inventoryledger.ErrExpired) || !reflect.DeepEqual(out, CompleteUpdatesStatus{}) {
					t.Fatal("post-commit expired status returned data", e)
				}
			case "page":
				out, e := s.CompleteUpdatesPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 1}, at)
				if e == nil || !reflect.DeepEqual(out, CompleteUpdatesPageResult{}) {
					t.Fatal("post-commit expired page returned data", e)
				}
			}
			if calls < 2 {
				t.Fatal("missing post-commit trusted-clock read")
			}
		})
	}
}

func TestCompleteUpdatesTransferConflictsDoNotSpendNextFloor(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := updatesGenerationFixture(t, snap.Approval.DeviceID, 1, 300, at)
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal(e)
	}
	if got, e := s.CompleteUpdatesAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c[1], at); !errors.Is(e, inventoryledger.ErrConflict) || got != (inventoryledger.ChunkReceipt{}) {
		t.Fatal("out-of-order chunk accepted", e)
	}
	next, nm, nc := updatesGenerationFixture(t, snap.Approval.DeviceID, 2, 1, at)
	if _, e := s.CompleteUpdatesBegin(ctx, snap.InvitationID, cert.CertificateHash(), next, nm, at); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("active transfer superseded", e)
	}
	generation, _ := inventorywire.CachedUpdatesGenerationID(snap.Approval.DeviceID, 2)
	failure := InventoryFailureReport{Sequence: 2, GenerationID: generation, AttemptedAt: at, Reason: "source_missing"}
	if _, e := s.CompleteUpdatesFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("failure superseded live transfer", e)
	}
	if e := s.CompleteUpdatesAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal(e)
	}
	promoteCompleteUpdates(t, s, snap, cert, next, nm, nc, at)
	v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at)
	if e != nil || v.Sequence != 2 || v.CompleteBinding != next {
		t.Fatal("rejected transfer spent next floor", e)
	}
}
