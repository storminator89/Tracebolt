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
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorystate"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/linuxpackages"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type inventoryClock struct{ nanos atomic.Int64 }

func (c *inventoryClock) now() time.Time  { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *inventoryClock) set(t time.Time) { c.nanos.Store(t.UnixNano()) }

type inventoryTestRequest struct {
	operation string
	body      []byte
	signedAt  time.Time
}
type inventoryHarness struct {
	t         *testing.T
	mu        sync.Mutex
	profile   string
	verifier  *inventorywire.Verifier
	clock     *inventoryClock
	manifest  fullinventory.Manifest
	started   time.Time
	accepted  uint32
	rows      uint64
	completed time.Time
	receipts  map[string][]byte
	requests  []inventoryTestRequest
	override  func(http.ResponseWriter, inventorywire.Message, []byte, []byte) bool
}

func inventoryTestReceipt(m inventorywire.Message, raw []byte, result any) []byte {
	digest := sha256.Sum256(raw)
	out, _ := json.Marshal(map[string]any{"schemaVersion": inventorywire.ReceiptVersion, "operation": m.Operation, "sequence": strconv.FormatUint(m.Sequence, 10), "generationId": m.GenerationID, "manifestHash": m.ManifestHash, "requestSha256": hex.EncodeToString(digest[:]), "result": result})
	return out
}
func (h *inventoryHarness) status(m inventorywire.Message, raw []byte, state string, complete bool) []byte {
	expires := h.started.Add(15 * time.Minute)
	completed := ""
	if complete {
		expires = h.manifest.CollectedAt.Add(24 * time.Hour)
		completed = h.completed.Format(time.RFC3339Nano)
	}
	return inventoryTestReceipt(m, raw, map[string]any{"state": state, "acceptedChunks": h.accepted, "expectedChunks": h.manifest.ChunkCount, "acceptedRows": h.rows, "startedAt": h.started, "expiresAt": expires, "completedAt": completed})
}
func (h *inventoryHarness) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := strings.TrimPrefix(r.URL.Path, inventorywire.PathPrefix)
	var raw []byte
	var signedAt time.Time
	if h.profile == "http-test" {
		v, err := h.verifier.Verify(r)
		if err != nil {
			h.t.Error("inventory signature rejected")
			w.WriteHeader(403)
			return
		}
		raw = v.Body
		signedAt = v.SignedAt
	} else {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			h.t.Error("missing mutual TLS certificate")
			w.WriteHeader(403)
			return
		}
		raw, _ = io.ReadAll(io.LimitReader(r.Body, inventorywire.MaxBodyBytes+1))
		if r.Header.Get(inventorywire.SignatureHeader) != "" {
			h.t.Error("HTTP signature leaked onto TLS")
		}
	}
	m, err := inventorywire.DecodeMessage(op, raw)
	if err != nil {
		h.t.Error("invalid inventory request")
		w.WriteHeader(400)
		return
	}
	h.requests = append(h.requests, inventoryTestRequest{op, bytes.Clone(raw), signedAt})
	key := fmt.Sprintf("%d/%s", m.Sequence, op)
	if m.Chunk != nil {
		key += fmt.Sprintf("/%d", m.Chunk.Ordinal)
	}
	response, exists := h.receipts[key]
	if !exists {
		var result any
		switch op {
		case "begin":
			h.manifest = *m.Manifest
			h.started = h.clock.now()
			h.accepted = 0
			h.rows = 0
			h.completed = time.Time{}
			result = map[string]any{"startedAt": h.started, "expiresAt": h.started.Add(15 * time.Minute)}
		case "append":
			h.accepted++
			h.rows += uint64(len(m.Chunk.Items))
			result = map[string]any{"ordinal": m.Chunk.Ordinal, "rows": len(m.Chunk.Items), "receivedAt": h.started}
		case "finalize":
			h.completed = h.started
			result = map[string]any{"collectedAt": h.manifest.CollectedAt, "completedAt": h.completed}
		case "failure":
			result = map[string]any{"attemptedAt": m.FailureAt, "receivedAt": h.clock.now(), "reason": m.FailureReason}
		case "abort":
			result = map[string]any{"aborted": true}
		case "status":
			response = h.status(m, raw, "pending", false)
		default:
			h.t.Error("wrong inventory operation")
			w.WriteHeader(400)
			return
		}
		if result != nil {
			response = inventoryTestReceipt(m, raw, result)
			h.receipts[key] = response
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if h.override != nil && h.override(w, m, raw, response) {
		return
	}
	_, _ = w.Write(response)
}

func syntheticInventory(_ context.Context, generation string, at time.Time, count int) (fullinventory.SourceInventory, error) {
	s := fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: make([]linuxpackages.PackageRow, count)}
	for i := range s.Rows {
		name := fmt.Sprintf("invented-package-%06d", i)
		s.Rows[i] = linuxpackages.PackageRow{Name: name, Version: "1.0-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.0-1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	return s, nil
}
func inventoryFixture(t *testing.T, profile string, count int) (*inventorySender, *inventoryHarness, *atomic.Int32) {
	t.Helper()
	clock := &inventoryClock{}
	clock.set(time.Now().UTC())
	h := &inventoryHarness{t: t, profile: profile, clock: clock, receipts: map[string][]byte{}}
	f := integrationFixture(t, profile, func(http.Handler) http.Handler { return http.HandlerFunc(h.serve) })
	if profile == "http-test" {
		var err error
		h.verifier, err = inventorywire.New(inventorywire.Config{Origin: f.material.config.ManagerOrigin, Registry: f.registry})
		if err != nil {
			t.Fatal(err)
		}
	}
	c := f.material.config
	c.SchemaVersion = CompleteConfigVersion
	c.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	if err := InitializeGuidedState(c); err != nil {
		t.Fatal(err)
	}
	m, err := loadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	s, err := openInventorySenderWithSource(m, clock.now, func(ctx context.Context, generation string, at time.Time) (fullinventory.SourceInventory, error) {
		calls.Add(1)
		return syntheticInventory(ctx, generation, at, count)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, h, calls
}
func burstInventory(s *inventorySender) (inventoryReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return s.Burst(ctx)
}
func reopenInventory(t *testing.T, s *inventorySender) *inventorySender {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := openInventorySenderWithSource(s.material, s.now, s.collect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	return next
}
func inventoryConflict(w http.ResponseWriter) {
	w.WriteHeader(409)
	_, _ = w.Write([]byte(`{"error":{"code":"inventory_state_conflict","message":"Agent telemetry could not be accepted."}}`))
}

func TestInventoryNativeTLSAndHTTPExactRestartAll513Rows(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			s, h, calls := inventoryFixture(t, profile, 513)
			lost := false
			h.override = func(w http.ResponseWriter, m inventorywire.Message, _, _ []byte) bool {
				if m.Operation == "append" && m.Chunk.Ordinal == 2 && !lost {
					lost = true
					w.WriteHeader(503)
					return true
				}
				return false
			}
			r, err := burstInventory(s)
			if !errors.Is(err, ErrInventoryTransport) || r.Operations != 4 || calls.Load() != 1 {
				t.Fatal("uncertain append not retained")
			}
			pending, ok, err := s.state.NextWork()
			if err != nil || !ok || pending.Ordinal != 2 {
				t.Fatal("wrong retained operation")
			}
			before := pending.Body()
			s = reopenInventory(t, s)
			h.clock.set(h.clock.now().Add(time.Second))
			r, err = burstInventory(s)
			if err != nil || r.Status != "acknowledged" || !r.RetriedPending || r.Operations != 4 || calls.Load() != 1 {
				t.Fatalf("exact resume failed: %v %v", r, err)
			}
			h.mu.Lock()
			var retries [][]byte
			var proofTimes []time.Time
			for _, request := range h.requests {
				if request.operation == "append" {
					m, _ := inventorywire.DecodeMessage("append", request.body)
					if m.Chunk.Ordinal == 2 {
						retries = append(retries, request.body)
						proofTimes = append(proofTimes, request.signedAt)
					}
				}
			}
			rows := h.rows
			h.mu.Unlock()
			if rows != 513 || len(retries) != 2 || !bytes.Equal(retries[0], retries[1]) || !bytes.Equal(before, retries[1]) {
				t.Fatal("rows or exact retry changed")
			}
			if profile == "http-test" && (len(proofTimes) != 2 || proofTimes[1].Sub(proofTimes[0]) != time.Second) {
				t.Fatal("retry did not refresh only the HTTP proof time")
			}
			r, err = burstInventory(s)
			if err != nil || r.Status != "not_due" || r.Operations != 0 || calls.Load() != 1 {
				t.Fatal("immediate recapture")
			}
		})
	}
}

func TestInventoryNativeCooldownSurvivesRestartAndClockRollback(t *testing.T) {
	s, h, calls := inventoryFixture(t, "tls", 0)
	at := h.clock.now()
	r, err := burstInventory(s)
	if err != nil || r.Status != "acknowledged" || r.Operations != 2 {
		t.Fatal("valid zero-row generation rejected", err)
	}
	s = reopenInventory(t, s)
	for _, offset := range []time.Duration{-time.Hour, 6*time.Hour - time.Nanosecond} {
		h.clock.set(at.Add(offset))
		r, err = burstInventory(s)
		if err != nil || r.Status != "not_due" || calls.Load() != 1 {
			t.Fatal("cooldown or rollback recaptured")
		}
	}
	h.clock.set(at.Add(6 * time.Hour))
	r, err = burstInventory(s)
	if err != nil || r.Sequence != 2 || calls.Load() != 2 {
		t.Fatal("due generation not captured", err)
	}
}

func TestInventoryNativeBudgetResumesBeforeCapture(t *testing.T) {
	s, _, calls := inventoryFixture(t, "tls", 8065)
	metrics, err := openSenderState(s.material)
	if err != nil {
		t.Fatal(err)
	}
	defer metrics.Close()
	metricCalls := 0
	report, err := runPreparedAttempt(context.Background(), s.material, metrics, s, func(ctx context.Context, _ Material, state *lanclientstate.State) (Report, error) {
		metricCalls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Second || calls.Load() != 0 || state != metrics {
			t.Fatal("metric attempt did not precede bounded collection")
		}
		return Report{Status: "acknowledged"}, nil
	})
	if err != nil || report.InventoryStatus != "pending_retained" || report.InventoryOperations != 64 || calls.Load() != 1 || metricCalls != 1 {
		t.Fatal("healthy burst cap was converted into scheduler failure", report, err)
	}
	s = reopenInventory(t, s)
	r, err := burstInventory(s)
	if err != nil || r.Status != "acknowledged" || r.Operations != 2 || !r.RetriedPending || calls.Load() != 1 {
		t.Fatal("bounded remainder failed", r, err)
	}
}

func TestInventoryNativePreparedAttemptStopsBeforeInventoryOnMetricFailure(t *testing.T) {
	s, h, calls := inventoryFixture(t, "tls", 0)
	metrics, err := openSenderState(s.material)
	if err != nil {
		t.Fatal(err)
	}
	defer metrics.Close()
	r, err := runPreparedAttempt(context.Background(), s.material, metrics, s, func(context.Context, Material, *lanclientstate.State) (Report, error) {
		return Report{Status: "pending_retained"}, ErrTransport
	})
	if !errors.Is(err, ErrTransport) || r.InventoryStatus != "" || calls.Load() != 0 {
		t.Fatal("metric failure triggered another observation")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.requests) != 0 {
		t.Fatal("metric failure triggered inventory traffic")
	}
}

func TestInventoryNativeCaptureFailureAndCancellationRetainAllocation(t *testing.T) {
	for _, scenario := range []string{"source-prefix-error", "nil-rows", "bad-generation", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			s, h, _ := inventoryFixture(t, "tls", 0)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			calls := 0
			s.collect = func(ctx context.Context, g string, at time.Time) (fullinventory.SourceInventory, error) {
				calls++
				source, _ := syntheticInventory(ctx, g, at, 1)
				switch scenario {
				case "source-prefix-error":
					return source, errors.New("sensitive-source-marker")
				case "nil-rows":
					source.Rows = nil
				case "bad-generation":
					source.GenerationID = "sample_ffffffffffffffffffffffffffffffff"
				case "cancel":
					cancel()
				}
				return source, nil
			}
			r, err := s.Burst(ctx)
			if scenario == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation ignored")
				}
				s = reopenInventory(t, s)
				s.collect = func(context.Context, string, time.Time) (fullinventory.SourceInventory, error) {
					t.Fatal("recollected allocated attempt")
					return fullinventory.SourceInventory{}, nil
				}
				r, err = burstInventory(s)
			}
			if err != nil || r.Status != "failure_acknowledged" || calls != 1 {
				t.Fatal("fixed failure report missing", r, err)
			}
			h.mu.Lock()
			requests := append([]inventoryTestRequest(nil), h.requests...)
			h.mu.Unlock()
			if len(requests) != 1 || requests[0].operation != "failure" || bytes.Contains(requests[0].body, []byte("sensitive-source-marker")) {
				t.Fatal("partial/source error transmitted")
			}
			if r, err = burstInventory(s); err != nil || r.Status != "not_due" {
				t.Fatal("failure cooldown lost")
			}
		})
	}
}

func TestInventoryNativeConflictRequiresFreshStrictStatus(t *testing.T) {
	for _, state := range []string{"expired", "failed", "pending", "bad-counts", "expired-complete"} {
		t.Run(state, func(t *testing.T) {
			s, h, calls := inventoryFixture(t, "tls", 1)
			phase := 0
			h.override = func(w http.ResponseWriter, m inventorywire.Message, raw, response []byte) bool {
				if m.Operation == "append" {
					if phase == 0 {
						w.WriteHeader(503)
					} else {
						inventoryConflict(w)
					}
					return true
				}
				if m.Operation == "status" {
					status := state
					if state == "bad-counts" || state == "expired-complete" {
						status = "expired"
					}
					if state == "expired-complete" {
						h.completed = h.started
					}
					out := h.status(m, raw, status, state == "expired-complete")
					if state == "bad-counts" {
						var envelope map[string]any
						_ = json.Unmarshal(out, &envelope)
						envelope["result"].(map[string]any)["acceptedRows"] = float64(0)
						out, _ = json.Marshal(envelope)
					}
					_, _ = w.Write(out)
					return true
				}
				return false
			}
			if _, err := burstInventory(s); !errors.Is(err, ErrInventoryTransport) {
				t.Fatal("fixture pause failed")
			}
			h.clock.set(h.clock.now().Add(16 * time.Minute))
			phase = 1
			r, err := burstInventory(s)
			if state == "expired" || state == "failed" {
				if err != nil || r.Status != "aborted" || r.Operations != 3 {
					t.Fatal("strict abort failed", r, err)
				}
			} else {
				if err == nil || r.Operations != 2 {
					t.Fatal("untrusted status changed state", r, err)
				}
				w, ok, _ := s.state.NextWork()
				if !ok || w.Operation != "append" {
					t.Fatal("retained transfer replaced")
				}
			}
			if calls.Load() != 1 {
				t.Fatal("conflict recaptured")
			}
		})
	}
}

func TestInventoryNativeLostFinalizeStatusRetriesExactFinalize(t *testing.T) {
	for _, state := range []string{"complete", "expired"} {
		t.Run(state, func(t *testing.T) {
			s, h, calls := inventoryFixture(t, "tls", 1)
			attempts := 0
			h.override = func(w http.ResponseWriter, m inventorywire.Message, raw, _ []byte) bool {
				if m.Operation == "finalize" {
					attempts++
					if attempts == 1 {
						w.WriteHeader(503)
						return true
					}
					if attempts == 2 {
						inventoryConflict(w)
						return true
					}
				}
				if m.Operation == "status" {
					_, _ = w.Write(h.status(m, raw, state, true))
					return true
				}
				return false
			}
			if _, err := burstInventory(s); !errors.Is(err, ErrInventoryTransport) {
				t.Fatal("lost finalize fixture failed")
			}
			work, _, _ := s.state.NextWork()
			before := work.Body()
			s = reopenInventory(t, s)
			r, err := burstInventory(s)
			if err != nil || r.Status != "acknowledged" || r.Operations != 3 || calls.Load() != 1 {
				t.Fatal("lost finalize recovery failed", r, err)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			for _, request := range h.requests {
				if request.operation == "finalize" && !bytes.Equal(before, request.body) {
					t.Fatal("finalize bytes refreshed")
				}
			}
		})
	}
}

func TestInventoryNativeNoDeadlineMissingStateLockAndBinding(t *testing.T) {
	s, _, calls := inventoryFixture(t, "tls", 0)
	if _, err := s.Burst(context.Background()); !errors.Is(err, ErrConfiguration) || calls.Load() != 0 {
		t.Fatal("unbounded caller accepted")
	}
	if _, err := openInventorySender(s.material); !errors.Is(err, ErrState) {
		t.Fatal("lifetime lock not held")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	dir := inventoryStateDirectory(s.material.config)
	if _, err := inventorystate.OpenExisting(dir, strings.Repeat("f", 64), s.material.config.AgentID); !errors.Is(err, inventorystate.ErrBinding) {
		t.Fatal("changed binding accepted")
	}
	c := s.material.config
	c.StateDirectory = filepath.Join(t.TempDir(), "absent")
	m, err := loadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openInventorySender(m); !errors.Is(err, ErrState) {
		t.Fatal("missing state accepted")
	}
	if _, err := os.Stat(c.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("sender created state")
	}
}

func TestInventoryNativeAllocationIsDurableBeforeSource(t *testing.T) {
	s, _, _ := inventoryFixture(t, "tls", 0)
	s.collect = func(ctx context.Context, generation string, at time.Time) (fullinventory.SourceInventory, error) {
		floor, err := s.state.SequenceFloor()
		attempt, attemptErr := s.state.LastAttemptedAt()
		raw, readErr := os.ReadFile(filepath.Join(inventoryStateDirectory(s.material.config), "ledger.json"))
		var disk struct {
			Phase       string `json:"phase"`
			AttemptedAt string `json:"attemptedAt"`
			Floor       uint64 `json:"floor"`
		}
		if err != nil || attemptErr != nil || readErr != nil || json.Unmarshal(raw, &disk) != nil || floor != 1 || disk.Floor != 1 || disk.Phase != "allocated" || !attempt.Equal(at) || disk.AttemptedAt != at.Format(time.RFC3339Nano) {
			t.Fatal("source ran before durable allocation")
		}
		return syntheticInventory(ctx, generation, at, 0)
	}
	if _, err := burstInventory(s); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryNativeRejectsUnsafeResponsesWithoutStatusOrPayloadLeak(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, scenario := range []string{"resource-conflict", "generic-conflict", "duplicate-conflict", "redirect", "forbidden", "server-error", "oversize", "encoding", "wrong-type", "wrong-digest", "future-time", "duplicate-receipt"} {
			t.Run(profile+"/"+scenario, func(t *testing.T) {
				s, h, calls := inventoryFixture(t, profile, 0)
				h.override = func(w http.ResponseWriter, m inventorywire.Message, raw, response []byte) bool {
					switch scenario {
					case "resource-conflict":
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`{"error":{"code":"inventory_resource_limit","message":"Agent telemetry could not be accepted."}}`))
					case "generic-conflict":
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`{"error":"sensitive-response-marker"}`))
					case "duplicate-conflict":
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`{"error":{"code":"inventory_state_conflict","message":"Agent telemetry could not be accepted."},"error":{"code":"inventory_state_conflict","message":"Agent telemetry could not be accepted."}}`))
					case "redirect":
						w.Header().Set("Location", s.material.config.ManagerOrigin+inventorywire.PathPrefix+"status")
						w.WriteHeader(307)
					case "forbidden":
						w.WriteHeader(403)
					case "server-error":
						w.WriteHeader(500)
					case "oversize":
						_, _ = w.Write(bytes.Repeat([]byte("x"), inventorywire.MaxReceiptBytes+1))
					case "encoding":
						w.Header().Set("Content-Encoding", "gzip")
						_, _ = w.Write(response)
					case "wrong-type":
						w.Header().Set("Content-Type", "text/plain")
						_, _ = w.Write(response)
					case "wrong-digest":
						var envelope map[string]any
						_ = json.Unmarshal(response, &envelope)
						envelope["requestSha256"] = strings.Repeat("0", 64)
						out, _ := json.Marshal(envelope)
						_, _ = w.Write(out)
					case "future-time":
						_, _ = w.Write(inventoryTestReceipt(m, raw, map[string]any{"startedAt": h.clock.now().Add(time.Hour), "expiresAt": h.clock.now().Add(75 * time.Minute)}))
					case "duplicate-receipt":
						out := append([]byte(`{"operation":"begin",`), response[1:]...)
						_, _ = w.Write(out)
					}
					return true
				}
				r, err := burstInventory(s)
				if err == nil || strings.Contains(err.Error(), "sensitive-response-marker") || r.Status != "pending_retained" || r.Operations != 1 || calls.Load() != 1 {
					t.Fatal("unsafe response accepted or leaked")
				}
				work, ok, stateErr := s.state.NextWork()
				if stateErr != nil || !ok || work.Operation != "begin" {
					t.Fatal("unsafe response changed retained work")
				}
				h.mu.Lock()
				defer h.mu.Unlock()
				if len(h.requests) != 1 {
					t.Fatal("generic failure or redirect triggered more operations")
				}
			})
		}
	}
}

func TestInventoryNativeDeadlineDuringTransportKeepsExactBytes(t *testing.T) {
	s, h, _ := inventoryFixture(t, "tls", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h.override = func(w http.ResponseWriter, m inventorywire.Message, _, _ []byte) bool {
		cancel()
		w.WriteHeader(503)
		return true
	}
	_, err := s.Burst(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("transport deadline not surfaced")
	}
	work, ok, stateErr := s.state.NextWork()
	if stateErr != nil || !ok || work.Operation != "begin" {
		t.Fatal("cancelled delivery discarded generation")
	}
	before := work.Body()
	s = reopenInventory(t, s)
	after, ok, stateErr := s.state.NextWork()
	if stateErr != nil || !ok || !bytes.Equal(before, after.Body()) {
		t.Fatal("cancelled delivery changed bytes on restart")
	}
}
