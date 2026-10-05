//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type completeUpdatesHarness struct {
	t        *testing.T
	mu       sync.Mutex
	profile  string
	verifier *inventorywire.Verifier
	clock    *inventoryClock
	manifest updategeneration.Manifest
	rows     uint64
	receipts map[string][]byte
	requests []inventoryTestRequest
	override func(http.ResponseWriter, inventorywire.Message, []byte) bool
}

func (h *completeUpdatesHarness) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := strings.TrimPrefix(r.URL.Path, inventorywire.CachedUpdatesPathPrefix)
	var raw []byte
	var signedAt time.Time
	if h.profile == "http-test" {
		v, e := h.verifier.Verify(r)
		if e != nil {
			h.t.Error("full update signature rejected")
			w.WriteHeader(403)
			return
		}
		raw, signedAt = v.Body, v.SignedAt
	} else {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			h.t.Error("missing update mTLS")
			w.WriteHeader(403)
			return
		}
		raw, _ = io.ReadAll(io.LimitReader(r.Body, inventorywire.MaxBodyBytes+1))
	}
	m, e := inventorywire.DecodeCachedUpdatesMessage(op, raw)
	if e != nil || m.Manifest != nil || m.Chunk != nil {
		h.t.Error("wrong fixed update domain")
		w.WriteHeader(400)
		return
	}
	h.requests = append(h.requests, inventoryTestRequest{op, bytes.Clone(raw), signedAt})
	key := fmt.Sprintf("%d/%s", m.Sequence, op)
	if m.UpdateChunk != nil {
		key += fmt.Sprintf("/%d", m.UpdateChunk.Ordinal)
	}
	response, exists := h.receipts[key]
	if !exists {
		var result any
		switch op {
		case "begin":
			h.manifest = *m.UpdateManifest
			h.rows = 0
			result = map[string]any{"startedAt": h.clock.now(), "expiresAt": h.clock.now().Add(15 * time.Minute)}
		case "append":
			h.rows += uint64(len(m.UpdateChunk.Items))
			result = map[string]any{"ordinal": m.UpdateChunk.Ordinal, "rows": len(m.UpdateChunk.Items), "receivedAt": h.clock.now()}
		case "finalize":
			result = map[string]any{"collectedAt": h.manifest.CollectedAt, "completedAt": h.clock.now()}
		case "failure":
			result = map[string]any{"attemptedAt": m.FailureAt, "receivedAt": h.clock.now(), "reason": m.FailureReason}
		default:
			h.t.Error("unexpected update operation")
			w.WriteHeader(400)
			return
		}
		sum := sha256.Sum256(raw)
		response, _ = json.Marshal(map[string]any{"schemaVersion": inventorywire.CachedUpdatesReceiptVersion, "operation": op, "sequence": strconv.FormatUint(m.Sequence, 10), "generationId": m.GenerationID, "manifestHash": m.ManifestHash, "requestSha256": hex.EncodeToString(sum[:]), "result": result})
		h.receipts[key] = response
	}
	w.Header().Set("Content-Type", "application/json")
	if h.override != nil && h.override(w, m, raw) {
		return
	}
	w.Write(response)
}
func syntheticCompleteUpdates(id string, at time.Time, count int) cachedupdates.CompleteSource {
	rows := make([]cachedupdates.Candidate, count)
	for i := range rows {
		rows[i] = cachedupdates.Candidate{Name: fmt.Sprintf("invented-package-%05d", i), Architecture: "amd64", InstalledVersion: "1.0-1", CandidateVersion: "2.0-1", State: "candidate_only", Installability: "not_evaluated"}
	}
	idField, version, codename := "debian", "13", "trixie"
	total, held, unknown := uint32(count), uint32(0), uint32(0)
	oldest, age := at.Add(-time.Hour), uint64(3600)
	s := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: id, CollectedAt: at, DurationMS: 1, Release: linuxpackages.ReleaseFields{ID: &idField, VersionID: &version, VersionCodename: &codename}, Coverage: "complete", Reason: cachedupdates.ReasonNone, Metadata: cachedupdates.Metadata{Freshness: "unknown", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &total, CheckedCount: &total, CandidateCount: &total, HeldCount: &held, UnknownCount: &unknown, Items: append([]cachedupdates.Candidate{}, rows...)}
	if count > 1 {
		s.Items = s.Items[:1]
		s.Truncated = true
		s.Coverage = "partial"
		s.Reason = cachedupdates.ReasonItemLimit
	}
	return cachedupdates.CompleteSource{Snapshot: s, Rows: rows, Complete: true}
}
func completeUpdatesFixture(t *testing.T, profile string, count int) (*inventorySender, *completeUpdatesHarness, *atomic.Int32, string) {
	t.Helper()
	clock := &inventoryClock{}
	clock.set(time.Now().UTC())
	h := &completeUpdatesHarness{t: t, profile: profile, clock: clock, receipts: map[string][]byte{}}
	f := integrationFixture(t, profile, func(http.Handler) http.Handler { return http.HandlerFunc(h.serve) })
	m, path := prepareEndpointHandoff(t, f.material)
	if profile == "http-test" {
		var e error
		h.verifier, e = inventorywire.NewCachedUpdatesVerifier(inventorywire.Config{Origin: m.config.ManagerOrigin, Registry: f.registry})
		if e != nil {
			t.Fatal(e)
		}
	}
	completeUpdatesConsentFixture(t, m, path)
	calls := &atomic.Int32{}
	s, e := openCompleteUpdatesSenderWithSource(m, clock.now, func(_ context.Context, id string, at time.Time, _ cachedupdates.CompleteLocalConsent, _ string) (cachedupdates.CompleteSource, error) {
		calls.Add(1)
		return syntheticCompleteUpdates(id, at, count), nil
	})
	if e != nil || s == nil {
		t.Fatal("full sender fixture", e)
	}
	t.Cleanup(func() { s.Close() })
	return s, h, calls, path
}
func TestCompleteUpdatesTLSAndHTTPRestartKeepAll1100RowsAndAge(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			s, h, calls, _ := completeUpdatesFixture(t, profile, 1100)
			original := h.clock.now()
			lost := false
			h.override = func(w http.ResponseWriter, m inventorywire.Message, _ []byte) bool {
				if m.Operation == "append" && m.UpdateChunk.Ordinal == 2 && !lost {
					lost = true
					w.WriteHeader(503)
					return true
				}
				return false
			}
			r, e := burstInventory(s)
			if !errors.Is(e, ErrInventoryTransport) || r.Operations != 4 || calls.Load() != 1 {
				t.Fatal("uncertain append not retained", e)
			}
			pending, ok, e := s.state.NextWork()
			if e != nil || !ok || pending.Ordinal != 2 {
				t.Fatal("wrong pending update operation", e)
			}
			before := pending.Body()
			s.Close()
			h.clock.set(original.Add(time.Second))
			next, e := openCompleteUpdatesSenderWithSource(s.material, h.clock.now, s.collectUpdates)
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close()
			r, e = burstInventory(next)
			if e != nil || r.Status != "acknowledged" || !r.RetriedPending || calls.Load() != 1 {
				t.Fatal("full update restart failed", e, r.Status)
			}
			h.mu.Lock()
			retries := [][]byte{}
			proofs := []time.Time{}
			for _, request := range h.requests {
				if request.operation == "append" {
					m, _ := inventorywire.DecodeCachedUpdatesMessage("append", request.body)
					if m.UpdateChunk.Ordinal == 2 {
						retries = append(retries, request.body)
						proofs = append(proofs, request.signedAt)
					}
				}
			}
			if h.rows != 1100 || h.manifest.CandidateCount != 1100 || h.manifest.ChunkCount <= 1 || !h.manifest.CollectedAt.Equal(original) || !h.manifest.Metadata.OldestIndexModifiedAt.Equal(original.Add(-time.Hour)) {
				t.Fatal("full update count or age changed")
			}
			h.mu.Unlock()
			if len(retries) != 2 || !bytes.Equal(before, retries[0]) || !bytes.Equal(before, retries[1]) {
				t.Fatal("pending update bytes changed")
			}
			if profile == "http-test" && !proofs[1].After(proofs[0]) {
				t.Fatal("HTTP proof did not refresh independently of capture")
			}
			r, e = burstInventory(next)
			if e != nil || r.Status != "not_due" || calls.Load() != 1 {
				t.Fatal("six-hour capture cadence changed", e)
			}
		})
	}
}
func TestCompleteUpdatesWithdrawalDuringCaptureAndTransferSendsNoMoreRows(t *testing.T) {
	for _, phase := range []string{"capture", "transfer"} {
		t.Run(phase, func(t *testing.T) {
			s, h, calls, path := completeUpdatesFixture(t, "tls", 129)
			if phase == "capture" {
				original := s.collectUpdates
				s.collectUpdates = func(ctx context.Context, id string, at time.Time, c cachedupdates.CompleteLocalConsent, b string) (cachedupdates.CompleteSource, error) {
					out, e := original(ctx, id, at, c, b)
					if removeCompleteUpdatesConsent(s.material) != nil {
						t.Fatal("withdrawal fixture")
					}
					return out, e
				}
			} else {
				h.override = func(_ http.ResponseWriter, m inventorywire.Message, _ []byte) bool {
					if m.Operation == "begin" && removeCompleteUpdatesConsent(s.material) != nil {
						t.Error("withdrawal fixture")
					}
					return false
				}
			}
			r, e := burstInventory(s)
			if e != nil || r.Status != "disabled" || calls.Load() != 1 {
				t.Fatal("withdrawal not stopped", e, r.Status)
			}
			h.mu.Lock()
			network := len(h.requests)
			h.mu.Unlock()
			want := 0
			if phase == "transfer" {
				want = 1
			}
			if network != want {
				t.Fatal("rows sent after withdrawal")
			}
			pending, ok, e := s.state.NextWork()
			if e != nil || !ok || pending.Sequence != 1 {
				t.Fatal("consumed floor lost", e)
			}
			before := pending.Body()
			r, e = burstInventory(s)
			if e != nil || r.Status != "disabled" || calls.Load() != 1 {
				t.Fatal("disabled source resumed")
			}
			s.Close()
			disabled, e := openCompleteUpdatesSenderWithSource(s.material, h.clock.now, s.collectUpdates)
			if e != nil || disabled != nil {
				t.Fatal("disabled restart reopened spool")
			}
			completeUpdatesConsentFixture(t, s.material, path)
			next, e := openCompleteUpdatesSenderWithSource(s.material, h.clock.now, s.collectUpdates)
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close()
			retained, ok, e := next.state.NextWork()
			if e != nil || !ok || !bytes.Equal(before, retained.Body()) || retained.Sequence != 1 {
				t.Fatal("fresh re-enable reset pending bytes/floor", e)
			}
		})
	}
}
func TestCompleteUpdatesFailureAndOptionalDeliveryStayIsolated(t *testing.T) {
	s, h, _, _ := completeUpdatesFixture(t, "tls", 0)
	s.collectUpdates = func(_ context.Context, id string, at time.Time, _ cachedupdates.CompleteLocalConsent, _ string) (cachedupdates.CompleteSource, error) {
		return cachedupdates.CompleteSource{Snapshot: cachedupdates.Empty(id, at, cachedupdates.ReasonCacheMissing)}, errors.New("private source diagnostic")
	}
	r, e := burstInventory(s)
	if e != nil || r.Status != "failure_acknowledged" {
		t.Fatal("failed capture became completed zero", e)
	}
	h.mu.Lock()
	if len(h.requests) != 1 || h.requests[0].operation != "failure" || bytes.Contains(h.requests[0].body, []byte("private source diagnostic")) {
		t.Fatal("source failure leaked or completed")
	}
	h.mu.Unlock()
	s.Close()
	other, h2, _, _ := completeUpdatesFixture(t, "tls", 129)
	h2.override = func(w http.ResponseWriter, _ inventorywire.Message, _ []byte) bool { w.WriteHeader(503); return true }
	report := Report{}
	if e := runCompleteUpdatesAttempt(context.Background(), other, &report); e != nil || report.CachedUpdatesStatus != "pending_retained" {
		t.Fatal("optional transport blocked metrics cadence", e)
	}
	journal := false
	if e := runOverviewAndJournal(context.Background(), nil, &report, func(context.Context) string { journal = true; return "disabled" }); e != nil || !journal {
		t.Fatal("optional failure blocked journal")
	}
}

func TestCompleteUpdatesSharedBurstLimitAndCompletedRetryEndCapture(t *testing.T) {
	s, h, calls, _ := completeUpdatesFixture(t, "tls", cachedupdates.MaxInstalledRows)
	original := h.clock.now()
	operations, bursts := 0, 0
	for {
		r, e := burstInventory(s)
		bursts++
		operations += r.Operations
		if r.Operations > inventoryMaxOperations || calls.Load() != 1 || bursts > 1 && !r.RetriedPending {
			t.Fatal("bounded retry recaptured or exceeded operation limit", e, r.Operations)
		}
		if e == nil {
			if r.Status != "acknowledged" {
				t.Fatal("full generation did not complete", r.Status)
			}
			break
		}
		// Either cooperative time exhaustion or the operation cap can win under
		// instrumentation/load. Both must retain exact work and bound this burst.
		if !errors.Is(e, ErrInventoryPending) && !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal("unexpected bounded update failure", e)
		}
		if errors.Is(e, ErrInventoryPending) && r.Operations != inventoryMaxOperations {
			t.Fatal("operation cap ended early")
		}
		if bursts > updategeneration.MaxGenerationChunks+2 {
			t.Fatal("bounded transfer made no progress")
		}
		h.clock.set(h.clock.now().Add(time.Second))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if bursts < 3 || operations < 130 || h.rows != cachedupdates.MaxInstalledRows || !h.manifest.CollectedAt.Equal(original) {
		t.Fatal("large full generation incomplete or age refreshed")
	}
}

func TestCompleteUpdatesRejectsPackageReceiptsAndConflicts(t *testing.T) {
	oldConflict := []byte(`{"error":{"code":"inventory_state_conflict","message":"Agent telemetry could not be accepted."}}`)
	newConflict := []byte(`{"error":{"code":"cached_updates_state_conflict","message":"Agent telemetry could not be accepted."}}`)
	if inventoryDomainConflictResponse(oldConflict, true) || inventoryDomainConflictResponse(newConflict, false) || !inventoryDomainConflictResponse(newConflict, true) {
		t.Fatal("conflict domains mixed")
	}
	s, h, calls, _ := completeUpdatesFixture(t, "tls", 1)
	h.override = func(w http.ResponseWriter, m inventorywire.Message, raw []byte) bool {
		response := inventoryTestReceipt(m, raw, map[string]any{"startedAt": h.clock.now(), "expiresAt": h.clock.now().Add(15 * time.Minute)})
		w.Write(response)
		return true
	}
	r, e := burstInventory(s)
	if !errors.Is(e, ErrInventoryReceipt) || r.Status != "pending_retained" || calls.Load() != 1 {
		t.Fatal("package receipt accepted for full updates", e)
	}
	before, ok, e := s.state.NextWork()
	if e != nil || !ok || before.Operation != "begin" {
		t.Fatal("invalid receipt advanced update state")
	}
	h.override = nil
	r, e = burstInventory(s)
	if e != nil || r.Status != "acknowledged" || !r.RetriedPending || calls.Load() != 1 {
		t.Fatal("exact work did not survive wrong receipt", e)
	}
}
