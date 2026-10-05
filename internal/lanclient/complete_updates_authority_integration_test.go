//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The source is entirely invented. The production sender and protected spool
// deliver through genuine enrolled mTLS/signed-HTTP ingress into the real SQLite
// promotion path; paging uses the store's real current-authority/cursor checks.
// Operator HTTP session/CSRF behavior is covered by the separate API tests.
func TestCompleteUpdatesSenderActualAuthorityRestartAndAll1100Rows(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f := newOverviewAuthorityFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			if e := f.store.InitializeCompleteUpdates(ctx); e != nil {
				t.Fatal("complete update schema fixture", e)
			}
			var lost atomic.Bool
			var mu sync.Mutex
			var appendBodies [][]byte
			var committedReceipts [][]byte
			_, server, _ := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != inventorywire.CachedUpdatesPathPrefix+"append" {
						next.ServeHTTP(w, r)
						return
					}
					raw, e := io.ReadAll(io.LimitReader(r.Body, inventorywire.MaxBodyBytes+1))
					if e != nil {
						t.Error("synthetic update request read")
						w.WriteHeader(500)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(raw))
					message, e := inventorywire.DecodeCachedUpdatesMessage("append", raw)
					if e != nil || message.UpdateChunk == nil {
						t.Error("synthetic update frame rejected")
						w.WriteHeader(500)
						return
					}
					if message.UpdateChunk.Ordinal != 2 {
						next.ServeHTTP(w, r)
						return
					}
					recorder := httptest.NewRecorder()
					next.ServeHTTP(recorder, r) // Actual ingress authenticates and commits first.
					if recorder.Code != http.StatusOK {
						t.Error("actual ingress did not commit synthetic append")
						w.WriteHeader(500)
						return
					}
					if _, e := inventorywire.DecodeCachedUpdatesReceipt(recorder.Body.Bytes(), "append", raw); e != nil {
						t.Error("actual committed append receipt invalid")
						w.WriteHeader(500)
						return
					}
					mu.Lock()
					appendBodies = append(appendBodies, bytes.Clone(raw))
					committedReceipts = append(committedReceipts, bytes.Clone(recorder.Body.Bytes()))
					mu.Unlock()
					if lost.CompareAndSwap(false, true) {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					for key, values := range recorder.Header() {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(recorder.Body.Bytes())
				})
			})
			material, path := f.material(t, server.URL)
			unchanged := overviewFileBytes(t, overviewExistingPaths(material))
			completeUpdatesConsentFixture(t, material, path)
			var calls atomic.Int32
			var source cachedupdates.CompleteSource
			collect := func(_ context.Context, id string, at time.Time, _ cachedupdates.CompleteLocalConsent, _ string) (cachedupdates.CompleteSource, error) {
				calls.Add(1)
				source = syntheticCompleteUpdates(id, at, 1100)
				held := uint32(0)
				for i := range source.Rows {
					if i%11 == 0 {
						source.Rows[i].State = "held"
						held++
					}
				}
				source.Snapshot.Items = append([]cachedupdates.Candidate{}, source.Rows[:1]...)
				installed, unknown := uint32(1102), uint32(2)
				source.Snapshot.InstalledCount, source.Snapshot.UnknownCount, source.Snapshot.HeldCount = &installed, &unknown, &held
				if cachedupdates.Validate(source.Snapshot) != nil {
					return cachedupdates.CompleteSource{}, cachedupdates.ErrInvalidSnapshot
				}
				return source, nil
			}
			now := func() time.Time { return time.Now().UTC() }
			sender, e := openCompleteUpdatesSenderWithSource(material, now, collect)
			if e != nil || sender == nil {
				t.Fatal("actual-authority sender fixture", e)
			}
			defer func() { sender.Close() }()
			report, e := sender.Burst(ctx)
			if !errors.Is(e, ErrInventoryTransport) || report.Status != "pending_retained" || report.Sequence != 1 || report.Operations != 4 || calls.Load() != 1 {
				t.Fatal("lost real receipt not retained", e)
			}
			work, pending, e := sender.state.NextWork()
			if e != nil || !pending || work.Operation != "append" || work.Ordinal != 2 || work.Sequence != 1 {
				t.Fatal("wrong exact pending operation", e)
			}
			pendingBytes := work.Body()
			before, e := f.store.CompleteUpdatesView(ctx, material.config.AgentID, now())
			if e != nil || before.Complete != nil || before.Transfer == nil || before.Transfer.State != "pending" || before.Transfer.AcceptedChunks != 3 || before.Transfer.AcceptedRows != 384 {
				t.Fatal("partial real generation promoted or lost", e)
			}
			if _, e := f.store.CompleteUpdatesPage(ctx, material.config.AgentID, inventoryledger.PageRequest{Limit: 73}, now()); !errors.Is(e, inventoryledger.ErrNotFound) {
				t.Fatal("partial real rows became pageable", e)
			}
			if sender.Close() != nil {
				t.Fatal("sender ownership close")
			}
			sender, e = openCompleteUpdatesSenderWithSource(material, now, collect)
			if e != nil || sender == nil {
				t.Fatal("sender ownership reopen", e)
			}
			report, e = sender.Burst(ctx)
			if e != nil || report.Status != "acknowledged" || report.Sequence != 1 || !report.RetriedPending || report.Captured || calls.Load() != 1 {
				t.Fatal("actual-authority restart recaptured or failed", e)
			}
			mu.Lock()
			exact := len(appendBodies) == 2 && bytes.Equal(appendBodies[0], pendingBytes) && bytes.Equal(appendBodies[1], pendingBytes)
			sameReceipt := len(committedReceipts) == 2 && bytes.Equal(committedReceipts[0], committedReceipts[1])
			mu.Unlock()
			if !exact || !sameReceipt {
				t.Fatal("real committed retry changed request or receipt bytes")
			}
			complete, e := f.store.CompleteUpdatesView(ctx, material.config.AgentID, now())
			if e != nil || complete.Complete == nil || complete.Complete.State != "complete" || complete.CompleteBinding.Sequence != 1 || complete.Complete.Manifest.CandidateCount != 1100 || complete.Complete.AcceptedRows != 1100 || complete.Complete.Manifest.HeldCount != 100 || complete.Complete.Manifest.UnknownCount != 2 || complete.Complete.Manifest.ComparisonCoverage != "partial" || complete.Complete.Manifest.ComparisonReason != cachedupdates.ReasonCandidateUnknown {
				t.Fatal("real full generation facts changed", e)
			}
			original := source.Snapshot.CollectedAt
			if !complete.Complete.Manifest.CollectedAt.Equal(original) || !complete.Complete.Manifest.Metadata.OldestIndexModifiedAt.Equal(*source.Snapshot.Metadata.OldestIndexModifiedAt) || *complete.Complete.Manifest.Metadata.AgeSeconds != 3600 {
				t.Fatal("delivery refreshed source or metadata age")
			}
			floor, e := sender.state.SequenceFloor()
			if e != nil || floor != 1 {
				t.Fatal("update sender floor mismatch", e)
			}
			report, e = sender.Burst(ctx)
			if e != nil || report.Status != "not_due" || calls.Load() != 1 {
				t.Fatal("completion immediately recaptured", e)
			}
			if sender.Close() != nil {
				t.Fatal("completed sender close")
			}
			// Reopen the actual manager database after stopping its local fixture server.
			// The next pages therefore cannot be satisfied by retained in-memory state.
			server.Close()
			if f.store.Close() != nil {
				t.Fatal("manager fixture close")
			}
			f.store, e = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
			if e != nil {
				t.Fatal("manager fixture reopen", e)
			}
			retained, e := f.store.CompleteUpdatesView(ctx, material.config.AgentID, now())
			if e != nil || retained.Complete == nil || retained.CompleteBinding != complete.CompleteBinding || !retained.Complete.CompletedAt.Equal(complete.Complete.CompletedAt) {
				t.Fatal("manager restart changed completion", e)
			}
			request := inventoryledger.PageRequest{GenerationID: complete.CompleteBinding.GenerationID, Limit: 73}
			seen, pages := 0, 0
			for {
				page, e := f.store.CompleteUpdatesPage(ctx, material.config.AgentID, request, now())
				if e != nil || page.ValidateAt(now()) != nil || page.TotalRows != 1100 || len(page.Items) > 73 || page.Binding != complete.CompleteBinding || !page.Manifest.CollectedAt.Equal(original) || !page.CompletedAt.Equal(complete.Complete.CompletedAt) || !page.Manifest.Metadata.OldestIndexModifiedAt.Equal(*source.Snapshot.Metadata.OldestIndexModifiedAt) || *page.Manifest.Metadata.AgeSeconds != 3600 {
					t.Fatal("restarted manager page changed generation or original ages", e)
				}
				pages++
				for _, row := range page.Items {
					if seen >= len(source.Rows) || row != source.Rows[seen] {
						t.Fatal("candidate omitted, changed or duplicated at full tail", seen)
					}
					seen++
				}
				if page.Exhausted {
					break
				}
				if page.NextCursor == "" || page.NextCursor == request.Cursor || pages > 1100 {
					t.Fatal("generation-pinned page made no progress")
				}
				request.Cursor = page.NextCursor
			}
			if seen != 1100 || pages != 16 || calls.Load() != 1 {
				t.Fatal("full tail lost or paging triggered source access")
			}
			overviewFilesUnchanged(t, unchanged)
			t.Log("synthetic proof: production sender; real enrolled ingress and SQLite promotion; exact lost-receipt retry across sender reopen; manager database reopen; all 1100 rows over16 bounded pages; original capture/index ages and unknown comparisons retained")
		})
	}
}
