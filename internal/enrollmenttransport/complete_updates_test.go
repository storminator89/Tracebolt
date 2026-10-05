package enrollmenttransport

import (
	"bytes"
	"context"
	"fmt"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
	"net/http"
	"testing"
	"time"
)

func (f *fixture) completeUpdatesRequest(t *testing.T, origin, op string, sequence uint64, raw []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := inventorywire.NewCachedUpdatesSignedRequest(context.Background(), origin, f.pair, op, sequence, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest(http.MethodPost, origin+inventorywire.CachedUpdatesPathPrefix+op, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func TestCompleteUpdatesRealIngressAllChunksAtomicRetryRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			if e := f.store.InitializeCompleteUpdates(context.Background()); e != nil {
				t.Fatal(e)
			}
			_, server, client := f.listen(t, nil)
			generation, e := inventorywire.CachedUpdatesGenerationID(f.snapshot.Approval.DeviceID, 1)
			if e != nil {
				t.Fatal(e)
			}
			at := time.Now().UTC().Add(-time.Second)
			m, chunks, e := fullUpdateIngressFixture(generation, at, 1201)

			if e != nil {
				t.Fatal(e)
			}
			hash, _ := updategeneration.ManifestDigest(m)
			request := func(op string, payload any) []byte {
				t.Helper()
				raw, e := inventorywire.EncodeCachedUpdatesMessage(op, 1, generation, hash, payload)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			send := func(op string, raw []byte, want int) []byte {
				t.Helper()
				return response(t, client, f.completeUpdatesRequest(t, server.URL, op, 1, raw), want)
			}
			begin := request("begin", m)
			first := send("begin", begin, 200)
			receipt, e := inventorywire.DecodeCachedUpdatesReceipt(first, "begin", begin)
			if e != nil || receipt.StartedAt.Before(at) {
				t.Fatal("bad begin receipt", e)
			}
			if again := send("begin", begin, 200); !bytes.Equal(first, again) {
				t.Fatal("begin retry refreshed committed receipt")
			}
			final := request("finalize", struct{}{})
			send("finalize", final, 409)
			for i, c := range chunks {
				raw := request("append", c)
				got := send("append", raw, 200)
				if _, e = inventorywire.DecodeCachedUpdatesReceipt(got, "append", raw); e != nil {
					t.Fatal(e)
				}
				if again := send("append", raw, 200); !bytes.Equal(got, again) {
					t.Fatal("chunk retry changed receipt")
				}
				view, e := f.store.CompleteUpdatesView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
				if e != nil || view.Complete != nil {
					t.Fatal("partial chunks exposed as complete", i, e)
				}
			}
			status := request("status", struct{}{})
			state, e := inventorywire.DecodeCachedUpdatesReceipt(send("status", status, 200), "status", status)
			if e != nil || state.State != "pending" || state.AcceptedRows != 1201 {
				t.Fatal("status mismatch", e)
			}
			completed := send("finalize", final, 200)
			finish, e := inventorywire.DecodeCachedUpdatesReceipt(completed, "finalize", final)
			if e != nil || !finish.CollectedAt.Equal(at) {
				t.Fatal("completion refreshed source time", e)
			}
			if again := send("finalize", final, 200); !bytes.Equal(completed, again) {
				t.Fatal("finalize retry changed receipt")
			}
			state, e = inventorywire.DecodeCachedUpdatesReceipt(send("status", status, 200), "status", status)
			if e != nil || state.State != "complete" || !state.CompletedAt.Equal(finish.CompletedAt) || state.AcceptedRows != 1201 {
				t.Fatal("completion status inconsistent", e)
			}
			seen := 0
			cursor := ""
			for {
				page, e := f.store.CompleteUpdatesPage(context.Background(), f.snapshot.Approval.DeviceID, inventoryledger.PageRequest{GenerationID: generation, Limit: 100, Cursor: cursor}, time.Now().UTC())
				if e != nil || page.TotalRows != 1201 || len(page.Items) > 100 || !page.Manifest.CollectedAt.Equal(at) {
					t.Fatal("complete page unavailable or changed", e)
				}
				for _, row := range page.Items {
					if row.Name != fmt.Sprintf("invented-update-%06d", seen) {
						t.Fatal("candidate omitted or duplicated", seen, row.Name)
					}
					seen++
				}
				if page.Exhausted {
					break
				}
				if page.NextCursor == "" || page.NextCursor == cursor {
					t.Fatal("paging made no progress")
				}
				cursor = page.NextCursor
			}
			if seen != 1201 {
				t.Fatal("complete tail omitted", seen)
			}

			f.revoke(t)
			send("finalize", final, 403)
		})
	}
}

func TestCompleteUpdatesIngressFailureNeverBecomesEmptyComplete(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			if e := f.store.InitializeCompleteUpdates(context.Background()); e != nil {
				t.Fatal(e)
			}
			_, server, client := f.listen(t, nil)
			generation, _ := inventorywire.CachedUpdatesGenerationID(f.snapshot.Approval.DeviceID, 1)
			at := time.Now().UTC().Add(-time.Second)
			raw, e := inventorywire.EncodeCachedUpdatesMessage("failure", 1, generation, "", map[string]any{"attemptedAt": at, "reason": "source_missing"})
			if e != nil {
				t.Fatal(e)
			}
			first := response(t, client, f.completeUpdatesRequest(t, server.URL, "failure", 1, raw), 200)
			if _, e = inventorywire.DecodeCachedUpdatesReceipt(first, "failure", raw); e != nil {
				t.Fatal(e)
			}
			if next := response(t, client, f.completeUpdatesRequest(t, server.URL, "failure", 1, raw), 200); !bytes.Equal(first, next) {
				t.Fatal("failure retry refreshed timestamp")
			}
			view, e := f.store.CompleteUpdatesView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Complete != nil || view.Transfer != nil || view.Failure == nil || !view.Failure.Failure.AttemptedAt.Equal(at) {
				t.Fatal("source failure fabricated inventory", e)
			}
			// A valid residual-only source is independently explicit and may complete
			// zero retained rows at a new floor; failure above cannot stand for it.
			generation, _ = inventorywire.CachedUpdatesGenerationID(f.snapshot.Approval.DeviceID, 2)
			m, _, e := fullUpdateIngressFixture(generation, at.Add(time.Millisecond), 0)
			if e != nil {
				t.Fatal(e)
			}
			hash, _ := updategeneration.ManifestDigest(m)
			for _, op := range []string{"begin", "finalize"} {
				var payload any = struct{}{}
				if op == "begin" {
					payload = m
				}
				body, e := inventorywire.EncodeCachedUpdatesMessage(op, 2, generation, hash, payload)
				if e != nil {
					t.Fatal(e)
				}
				receipt := response(t, client, f.completeUpdatesRequest(t, server.URL, op, 2, body), 200)
				if _, e = inventorywire.DecodeCachedUpdatesReceipt(receipt, op, body); e != nil {
					t.Fatal(e)
				}
			}
			view, e = f.store.CompleteUpdatesView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Complete == nil || view.Complete.Manifest.CandidateCount != 0 || view.Failure != nil {
				t.Fatal("valid empty complete inventory lost", e)
			}
			response(t, client, f.completeUpdatesRequest(t, server.URL, "failure", 1, raw), 409)
		})
	}
}

func TestCompleteUpdatesRequiresFreshMatchingCollectionProfile(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			_, server, client := f.listen(t, nil)
			response(t, client, f.completeUpdatesRequest(t, server.URL, "status", 1, []byte(`{}`)), 404)
		})
	}
}

// Synthetic cache-only capture; no endpoint source is read by this fixture.
func fullUpdateIngressFixture(generation string, at time.Time, n int) (updategeneration.Manifest, []updategeneration.Chunk, error) {
	rows := make([]cachedupdates.Candidate, n)
	held := uint32(0)
	for i := range rows {
		state := "candidate_only"
		if i%7 == 0 {
			state = "held"
			held++
		}
		rows[i] = cachedupdates.Candidate{Name: fmt.Sprintf("invented-update-%06d", i), Architecture: "amd64", InstalledVersion: "1.0-1", CandidateVersion: "2.0-1", State: state, Installability: "not_evaluated"}
	}
	distro, version, codename := "debian", "13", "trixie"
	oldest := at.Add(-time.Hour)
	age := uint64(3600)
	count := uint32(n)
	unknown := uint32(0)
	snapshot := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseFields{ID: &distro, VersionID: &version, VersionCodename: &codename}, Coverage: "complete", Reason: cachedupdates.ReasonNone, Metadata: cachedupdates.Metadata{Freshness: "unknown", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &count, CheckedCount: &count, CandidateCount: &count, HeldCount: &held, UnknownCount: &unknown, Items: append([]cachedupdates.Candidate{}, rows[:min(n, 3)]...)}
	if n > len(snapshot.Items) {
		snapshot.Truncated = true
		snapshot.Coverage = "partial"
		snapshot.Reason = cachedupdates.ReasonItemLimit
	}
	return updategeneration.Build(context.Background(), updategeneration.SourceInventory{Snapshot: snapshot, Rows: rows, Complete: true}, nil)
}
