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
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewstate"
	"localrmm/internal/overviewwire"
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

type overviewHarness struct {
	t         *testing.T
	mu        sync.Mutex
	profile   string
	verifier  *overviewwire.Verifier
	clock     *inventoryClock
	manifests map[string]overviewgeneration.Manifest
	started   map[string]time.Time
	rows      map[string]uint64
	accepted  map[string]uint32
	completed map[string]time.Time
	receipts  map[string][]byte
	requests  []overviewTestRequest
	override  func(http.ResponseWriter, overviewwire.Message, []byte, []byte) bool
}
type overviewTestRequest struct {
	message  overviewwire.Message
	body     []byte
	signedAt time.Time
}

func overviewTestReceipt(m overviewwire.Message, raw []byte, result any) []byte {
	d := sha256.Sum256(raw)
	out, _ := json.Marshal(map[string]any{"schemaVersion": overviewwire.ReceiptVersion, "section": m.Section, "operation": m.Operation, "sequence": strconv.FormatUint(m.Sequence, 10), "generationId": m.GenerationID, "manifestHash": m.ManifestHash, "requestSha256": hex.EncodeToString(d[:]), "result": result})
	return out
}
func (h *overviewHarness) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	op := strings.TrimPrefix(r.URL.Path, overviewwire.PathPrefix)
	var raw []byte
	var signedAt time.Time
	if h.profile == "http-test" {
		v, e := h.verifier.Verify(r)
		if e != nil {
			h.t.Error("overview signature rejected")
			w.WriteHeader(403)
			return
		}
		raw, signedAt = v.Body, v.SignedAt
	} else {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			h.t.Error("overview mTLS identity missing")
			w.WriteHeader(403)
			return
		}
		raw, _ = io.ReadAll(io.LimitReader(r.Body, overviewwire.MaxBodyBytes+1))
		if r.Header.Get(overviewwire.SignatureHeader) != "" {
			h.t.Error("HTTP signature on TLS")
		}
	}
	m, e := overviewwire.DecodeMessage(op, raw)
	if e != nil {
		h.t.Error("invalid overview request")
		w.WriteHeader(400)
		return
	}
	h.requests = append(h.requests, overviewTestRequest{m, bytes.Clone(raw), signedAt})
	key := fmt.Sprintf("%s/%d/%s", m.Section, m.Sequence, op)
	if m.Chunk != nil {
		key += fmt.Sprintf("/%d", m.Chunk.Ordinal)
	}
	response, exists := h.receipts[key]
	if !exists {
		var result any
		switch op {
		case "begin":
			h.manifests[m.Section] = *m.Manifest
			h.started[m.Section] = h.clock.now()
			h.rows[m.Section] = 0
			h.accepted[m.Section] = 0
			h.completed[m.Section] = time.Time{}
			result = map[string]any{"startedAt": h.started[m.Section], "expiresAt": h.started[m.Section].Add(15 * time.Minute)}
		case "append":
			h.rows[m.Section] += uint64(len(m.Chunk.Items))
			h.accepted[m.Section]++
			result = map[string]any{"ordinal": m.Chunk.Ordinal, "rows": len(m.Chunk.Items), "receivedAt": h.started[m.Section]}
		case "finalize":
			h.completed[m.Section] = h.started[m.Section]
			result = map[string]any{"collectedAt": h.manifests[m.Section].CollectedAt, "completedAt": h.started[m.Section]}
		case "failure":
			result = map[string]any{"attemptedAt": m.FailureAt, "receivedAt": h.clock.now(), "reason": m.FailureReason}
		case "status":
			response = h.status(m, raw, "pending", false)
		case "abort":
			result = map[string]any{"aborted": true}
		default:
			h.t.Error("unexpected overview operation")
			w.WriteHeader(400)
			return
		}
		if result != nil {
			response = overviewTestReceipt(m, raw, result)
			h.receipts[key] = response
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if h.override != nil && h.override(w, m, raw, response) {
		return
	}
	w.Write(response)
}
func syntheticOverview(_ context.Context, id string, at time.Time, processes, volumes int) (completeoverview.Snapshot, error) {
	s := completeoverview.Empty(id, at, completeoverview.ReasonReadFailed)
	pc, vc := uint64(processes), uint64(volumes)
	s.Processes = completeoverview.ProcessSection{Meta: completeoverview.SectionMeta{GenerationID: id, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &pc, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: pc}}, Items: make([]completeoverview.Process, processes)}
	for i := range s.Processes.Items {
		s.Processes.Items[i] = completeoverview.Process{PID: uint32(i + 1), Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}
	}
	s.Volumes = completeoverview.VolumeSection{Meta: completeoverview.SectionMeta{GenerationID: id, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &vc, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{NotApplicable: vc}}, Items: make([]completeoverview.Volume, volumes)}
	for i := range s.Volumes.Items {
		s.Volumes.Items[i] = completeoverview.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: fmt.Sprintf("/fixture/%05d", i), Filesystem: "proc", Kind: "virtual", FilesystemGroup: "fs_0_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}}
	}
	return s, completeoverview.Validate(s)
}
func overviewConsentFixture(t *testing.T, m Material) {
	t.Helper()
	for _, section := range []string{"processes", "volumes"} {
		s, e := overviewstate.InitializeNew(overviewStateDirectory(m.config, section), m.binding, m.config.AgentID, section)
		if e != nil {
			t.Fatal(e)
		}
		if s.Close() != nil {
			t.Fatal("fixture close")
		}
	}
	raw, _ := json.Marshal(overviewConsentFor(m))
	if writeOverviewConsent(m, raw) != nil {
		t.Fatal("fixture consent")
	}
}
func overviewFixture(t *testing.T, profile string, processes, volumes int) (*overviewSender, *overviewHarness, *atomic.Int32) {
	t.Helper()
	clock := &inventoryClock{}
	clock.set(time.Now().UTC())
	h := &overviewHarness{t: t, profile: profile, clock: clock, manifests: map[string]overviewgeneration.Manifest{}, started: map[string]time.Time{}, rows: map[string]uint64{}, accepted: map[string]uint32{}, completed: map[string]time.Time{}, receipts: map[string][]byte{}}
	f := integrationFixture(t, profile, func(http.Handler) http.Handler { return http.HandlerFunc(h.serve) })
	if profile == "http-test" {
		var e error
		h.verifier, e = overviewwire.New(overviewwire.Config{Origin: f.material.config.ManagerOrigin, Registry: f.registry})
		if e != nil {
			t.Fatal(e)
		}
	}
	m, _ := prepareEndpointHandoff(t, f.material)
	overviewConsentFixture(t, m)
	calls := &atomic.Int32{}
	s, e := openOverviewSenderWithSource(m, clock.now, func(ctx context.Context, id string, at time.Time) (completeoverview.Snapshot, error) {
		calls.Add(1)
		return syntheticOverview(ctx, id, at, processes, volumes)
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, h, calls
}
func burstOverview(s *overviewSender) (overviewBurstReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return s.Burst(ctx)
}
func reopenOverview(t *testing.T, s *overviewSender) *overviewSender {
	t.Helper()
	s.Close()
	next, e := openOverviewSenderWithSource(s.material, s.now, s.collect)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { next.Close() })
	return next
}

func TestOverviewNativeTLSAndHTTPSharedCaptureExactRestart(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			s, h, calls := overviewFixture(t, profile, 513, 300)
			h.clock.set(h.clock.now().Add(-time.Minute))
			lost := false
			h.override = func(w http.ResponseWriter, m overviewwire.Message, _, _ []byte) bool {
				if m.Section == "processes" && m.Operation == "append" && m.Chunk.Ordinal == 2 && !lost {
					lost = true
					w.WriteHeader(503)
					return true
				}
				return false
			}
			status, e := burstOverview(s)
			if !errors.Is(e, ErrOverviewTransport) || status.Processes.Status != "pending_retained" || status.Volumes.Status != "acknowledged" || calls.Load() != 1 {
				t.Fatalf("first burst: %v %+v calls=%d", e, status, calls.Load())
			}
			original := h.manifests["processes"]
			if original.CaptureGenerationID != h.manifests["volumes"].CaptureGenerationID || original.GenerationID == h.manifests["volumes"].GenerationID || !original.CollectedAt.Equal(h.manifests["volumes"].CollectedAt) {
				t.Fatal("shared capture/independent transfer identity lost")
			}
			pending, ok, e := s.processes.state.NextWork()
			if e != nil || !ok {
				t.Fatal("pending missing")
			}
			s = reopenOverview(t, s)
			h.clock.set(h.clock.now().Add(20 * time.Second))
			status, e = burstOverview(s)
			if e != nil || status.Processes.Status != "acknowledged" || status.Volumes.Status != "not_due" || calls.Load() != 1 || h.rows["processes"] != 513 || h.rows["volumes"] != 300 {
				t.Fatalf("restart: %v %+v", e, status)
			}
			found := 0
			for _, r := range h.requests {
				if r.message.Section == "processes" && r.message.Operation == "append" && r.message.Chunk.Ordinal == 2 {
					found++
					if !bytes.Equal(pending.Body(), r.body) {
						t.Fatal("retry changed exact bytes")
					}
				}
			}
			if found != 2 || !h.manifests["processes"].CollectedAt.Equal(original.CollectedAt) {
				t.Fatal("retry count/age")
			}
			h.clock.set(original.CollectedAt.Add(time.Minute))
			status, e = burstOverview(s)
			if e != nil || status.Processes.Sequence != 2 || status.Volumes.Sequence != 2 || calls.Load() != 2 {
				t.Fatal("fixed minute cadence", e, status)
			}
		})
	}
}

// Stage the real large generations before testing the shared transfer-operation
// budget. Capture/staging time is not a guarantee of 64 deliveries within a
// burst: the independent cooperative deadline may legitimately end it earlier.
// Fresh shared capture is covered by TestOverviewNativeTLSAndHTTPSharedCaptureExactRestart.
func stageOverviewFairnessFixture(t *testing.T, s *overviewSender, at time.Time) {
	t.Helper()
	var source completeoverview.Snapshot
	for i, section := range []*overviewSectionSender{s.processes, s.volumes} {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), overviewBurstTimeout)
			defer cancel()
			a, err := section.state.Allocate(ctx, at)
			if err != nil {
				t.Fatal("fairness fixture allocation", err)
			}
			if i == 0 {
				source, err = s.collect(ctx, a.GenerationID, at)
				if err != nil {
					t.Fatal("fairness fixture capture", err)
				}
			}
			manifest, chunks, err := overviewgeneration.Build(ctx, source, section.section, a.GenerationID, nil)
			if err != nil {
				t.Fatal("fairness fixture generation", err)
			}
			rawManifest, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal("fairness fixture manifest", err)
			}
			rawChunks := make([][]byte, len(chunks))
			for j := range chunks {
				rawChunks[j], err = json.Marshal(chunks[j])
				if err != nil {
					t.Fatal("fairness fixture chunk", err)
				}
			}
			if err = section.state.Stage(ctx, a, rawManifest, rawChunks); err != nil {
				t.Fatal("fairness fixture staging", err)
			}
		}()
	}
}

func TestOverviewSharedBurstBudgetAndFairness(t *testing.T) {
	s, h, calls := overviewFixture(t, "tls", 9000, 9000)
	stageOverviewFairnessFixture(t, s, h.clock.now())
	if calls.Load() != 1 || len(h.requests) != 0 {
		t.Fatal("fixture must stage one capture without transport")
	}
	first, e := burstOverview(s)
	if !errors.Is(e, ErrOverviewPending) || first.Processes.Operations+first.Volumes.Operations != 64 || first.Volumes.Operations != 0 || first.Processes.Captured || first.Volumes.Captured || calls.Load() != 1 {
		t.Fatal("shared budget", e, first)
	}
	second, e := burstOverview(s)
	if !errors.Is(e, ErrOverviewPending) || second.Processes.Operations+second.Volumes.Operations != 64 || second.Volumes.Operations != 64 || second.Processes.Captured || second.Volumes.Captured || calls.Load() != 1 {
		t.Fatal("section fairness", e, second)
	}
	third, e := burstOverview(s)
	if e != nil || third.Processes.Operations != 9 || third.Volumes.Operations != 9 || third.Processes.Captured || third.Volumes.Captured || third.Processes.Status != "acknowledged" || third.Volumes.Status != "acknowledged" || h.rows["processes"] != 9000 || h.rows["volumes"] != 9000 || calls.Load() != 1 {
		t.Fatal("full rows beyond cap", e, third)
	}
}
func TestOverviewDisableSuppressesEveryPendingOperationWithoutFloorReset(t *testing.T) {
	s, h, calls := overviewFixture(t, "tls", 300, 300)
	revoked := false
	h.override = func(w http.ResponseWriter, m overviewwire.Message, _, _ []byte) bool {
		if !revoked {
			revoked = true
			if removeOverviewConsent(s.material) != nil {
				t.Error("disable fixture")
			}
		}
		return false
	}
	out, e := burstOverview(s)
	if e != nil || out.Processes.Status != "disabled" || out.Volumes.Status != "disabled" || len(h.requests) != 1 {
		t.Fatal("sent after consent removal", e, out, len(h.requests))
	}
	for _, section := range []*overviewSectionSender{s.processes, s.volumes} {
		floor, e := section.state.SequenceFloor()
		if e != nil || floor != 1 {
			t.Fatal("consumed floor lost")
		}
		if _, pending, e := section.state.NextWork(); e != nil || !pending {
			t.Fatal("pending unexpectedly reset")
		}
	}
	s = reopenOverview(t, s)
	if s != nil {
		t.Fatal("disabled runtime reopened domains")
	}
	if calls.Load() != 1 {
		t.Fatal("disabled recapture")
	}
}
func TestOverviewFailedSectionCannotReplaceCompleteSibling(t *testing.T) {
	s, h, calls := overviewFixture(t, "tls", 1, 1)
	original := s.collect
	s.collect = func(ctx context.Context, id string, at time.Time) (completeoverview.Snapshot, error) {
		source, e := original(ctx, id, at)
		source.Volumes = completeoverview.Empty(id, at, completeoverview.ReasonPermissionDenied).Volumes
		return source, e
	}
	out, e := burstOverview(s)
	if e != nil || out.Processes.Status != "acknowledged" || out.Volumes.Status != "failure_acknowledged" || calls.Load() != 1 || h.rows["processes"] != 1 {
		t.Fatal("independent section failure", e, out)
	}
	if _, exists := h.manifests["volumes"]; exists {
		t.Fatal("failed section promoted as complete")
	}
}
func TestOverviewReceiptSectionMismatchKeepsExactPending(t *testing.T) {
	s, h, _ := overviewFixture(t, "tls", 1, 1)
	h.override = func(w http.ResponseWriter, m overviewwire.Message, _, response []byte) bool {
		var v map[string]any
		json.Unmarshal(response, &v)
		if m.Section == "processes" {
			v["section"] = "volumes"
		} else {
			v["section"] = "processes"
		}
		json.NewEncoder(w).Encode(v)
		return true
	}
	out, e := burstOverview(s)
	if !errors.Is(e, ErrOverviewReceipt) || out.Processes.Status != "pending_retained" || out.Volumes.Status != "pending_retained" {
		t.Fatal("cross section receipt accepted", e, out)
	}
	for _, section := range []*overviewSectionSender{s.processes, s.volumes} {
		w, pending, e := section.state.NextWork()
		if e != nil || !pending || w.Operation != "begin" {
			t.Fatal("wrong receipt advanced cursor")
		}
	}
}
func TestOverviewDefaultOffNeverCreatesStateOrCollects(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, _ := prepareEndpointHandoff(t, f.material)
	calls := 0
	collect := func(context.Context, string, time.Time) (completeoverview.Snapshot, error) {
		calls++
		t.Fatal("default-off collection")
		return completeoverview.Snapshot{}, nil
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"acknowledged":true}`)} {
		if raw != nil {
			if os.WriteFile(filepath.Join(m.config.StateDirectory, overviewConsentName), raw, 0600) != nil {
				t.Fatal("fixture")
			}
		}
		s, e := openOverviewSenderWithSource(m, time.Now, collect)
		if e != nil || s != nil {
			t.Fatal("default off", e)
		}
		for _, section := range []string{"processes", "volumes"} {
			if _, e := os.Stat(overviewStateDirectory(m.config, section)); !os.IsNotExist(e) {
				t.Fatal("default-off state creation")
			}
		}
	}
	if calls != 0 {
		t.Fatal("source called")
	}
}

func (h *overviewHarness) status(m overviewwire.Message, raw []byte, state string, complete bool) []byte {
	expires := h.started[m.Section].Add(15 * time.Minute)
	completed := ""
	if complete {
		expires = h.manifests[m.Section].CollectedAt.Add(24 * time.Hour)
		completed = h.completed[m.Section].Format(time.RFC3339Nano)
	}
	return overviewTestReceipt(m, raw, map[string]any{"state": state, "acceptedChunks": h.accepted[m.Section], "expectedChunks": h.manifests[m.Section].ChunkCount, "acceptedRows": h.rows[m.Section], "startedAt": h.started[m.Section], "expiresAt": expires, "completedAt": completed})
}
func overviewConflict(w http.ResponseWriter) {
	w.WriteHeader(409)
	w.Write([]byte(`{"error":{"code":"overview_state_conflict","message":"Agent telemetry could not be accepted."}}`))
}
func TestOverviewConflictsRequireSectionBoundStrictStatus(t *testing.T) {
	for _, state := range []string{"expired", "failed", "pending", "bad-counts"} {
		t.Run(state, func(t *testing.T) {
			s, h, calls := overviewFixture(t, "tls", 1, 1)
			phase := 0
			h.override = func(w http.ResponseWriter, m overviewwire.Message, raw, _ []byte) bool {
				if m.Section != "processes" {
					return false
				}
				if m.Operation == "append" {
					if phase == 0 {
						w.WriteHeader(503)
					} else {
						overviewConflict(w)
					}
					return true
				}
				if m.Operation == "status" {
					status := state
					if state == "bad-counts" {
						status = "expired"
					}
					response := h.status(m, raw, status, false)
					if state == "bad-counts" {
						var envelope map[string]any
						json.Unmarshal(response, &envelope)
						envelope["result"].(map[string]any)["acceptedRows"] = 0
						response, _ = json.Marshal(envelope)
					}
					w.Write(response)
					return true
				}
				return false
			}
			if _, e := burstOverview(s); !errors.Is(e, ErrOverviewTransport) {
				t.Fatal("fixture pause", e)
			}
			h.clock.set(h.clock.now().Add(16 * time.Minute))
			phase = 1
			out, e := burstOverview(s)
			if state == "expired" || state == "failed" {
				if e != nil || out.Processes.Status != "aborted" || out.Processes.Operations != 3 {
					t.Fatal("status abort", e, out)
				}
			} else {
				if e == nil || out.Processes.Operations != 2 {
					t.Fatal("untrusted status advanced", e, out)
				}
				w, pending, _ := s.processes.state.NextWork()
				if !pending || w.Operation != "append" {
					t.Fatal("pending lost")
				}
			}
			if calls.Load() != 1 || out.Volumes.Status != "not_due" {
				t.Fatal("pending work triggered recapture", calls.Load(), out)
			}
		})
	}
}
func TestOverviewLostFinalizeRetriesExactOriginalAfterStatus(t *testing.T) {
	s, h, calls := overviewFixture(t, "tls", 1, 1)
	attempts := 0
	h.override = func(w http.ResponseWriter, m overviewwire.Message, raw, _ []byte) bool {
		if m.Section != "processes" {
			return false
		}
		if m.Operation == "finalize" {
			attempts++
			if attempts == 1 {
				w.WriteHeader(503)
				return true
			}
			if attempts == 2 {
				overviewConflict(w)
				return true
			}
		}
		if m.Operation == "status" {
			w.Write(h.status(m, raw, "complete", true))
			return true
		}
		return false
	}
	if _, e := burstOverview(s); !errors.Is(e, ErrOverviewTransport) {
		t.Fatal("fixture", e)
	}
	work, _, _ := s.processes.state.NextWork()
	original := work.Body()
	s = reopenOverview(t, s)
	out, e := burstOverview(s)
	if e != nil || out.Processes.Status != "acknowledged" || out.Processes.Operations != 3 || calls.Load() != 1 {
		t.Fatal("exact finalize retry", e, out)
	}
	for _, request := range h.requests {
		if request.message.Section == "processes" && request.message.Operation == "finalize" && !bytes.Equal(request.body, original) {
			t.Fatal("finalize retry changed bytes")
		}
	}
}

func TestOverviewSourceErrorCancellationAndAllocationAreDurable(t *testing.T) {
	for _, scenario := range []string{"error", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			s, h, _ := overviewFixture(t, "tls", 1, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			calls := 0
			s.collect = func(ctx context.Context, id string, at time.Time) (completeoverview.Snapshot, error) {
				calls++
				floor, e := s.processes.state.SequenceFloor()
				original, e2 := s.processes.state.LastAttemptedAt()
				if e != nil || e2 != nil || floor != 1 || !original.Equal(at) {
					t.Fatal("source ran before durable reservation")
				}
				source, _ := syntheticOverview(ctx, id, at, 1, 1)
				if scenario == "cancel" {
					cancel()
					return source, nil
				}
				return source, errors.New("sensitive-source-marker")
			}
			out, e := s.Burst(ctx)
			if scenario == "cancel" {
				if !errors.Is(e, context.Canceled) {
					t.Fatal("cancellation ignored", e)
				}
				s = reopenOverview(t, s)
				s.collect = func(context.Context, string, time.Time) (completeoverview.Snapshot, error) {
					t.Fatal("recollected allocated transfer")
					return completeoverview.Snapshot{}, nil
				}
				out, e = burstOverview(s)
				if out.Volumes.Status != "not_due" {
					t.Fatal("fresh sibling admitted before retained failure")
				}
			} else if out.Volumes.Status != "failure_acknowledged" {
				t.Fatal("source error promoted sibling")
			}
			if e != nil || out.Processes.Status != "failure_acknowledged" || calls != 1 {
				t.Fatal("fixed failure not retained", e, out)
			}
			for _, request := range h.requests {
				if request.message.Operation != "failure" || bytes.Contains(request.body, []byte("sensitive-source-marker")) {
					t.Fatal("partial/error content transmitted")
				}
			}
		})
	}
}
func TestOverviewRejectsUnsafeResponsesWithoutStatusOrPayloadLeaks(t *testing.T) {
	for _, scenario := range []string{"resource-conflict", "generic-conflict", "duplicate-conflict", "redirect", "forbidden", "server-error", "oversize", "encoding", "wrong-type", "wrong-digest", "future-time", "duplicate-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			s, h, calls := overviewFixture(t, "tls", 0, 0)
			h.override = func(w http.ResponseWriter, m overviewwire.Message, raw, response []byte) bool {
				switch scenario {
				case "resource-conflict":
					w.WriteHeader(409)
					w.Write([]byte(`{"error":{"code":"overview_resource_limit","message":"Agent telemetry could not be accepted."}}`))
				case "generic-conflict":
					w.WriteHeader(409)
					w.Write([]byte(`{"error":"sensitive-response-marker"}`))
				case "duplicate-conflict":
					w.WriteHeader(409)
					w.Write([]byte(`{"error":{"code":"overview_state_conflict","message":"Agent telemetry could not be accepted."},"error":{"code":"overview_state_conflict","message":"Agent telemetry could not be accepted."}}`))
				case "redirect":
					w.Header().Set("Location", s.material.config.ManagerOrigin+overviewwire.PathPrefix+"status")
					w.WriteHeader(307)
				case "forbidden":
					w.WriteHeader(403)
				case "server-error":
					w.WriteHeader(500)
				case "oversize":
					w.Write(bytes.Repeat([]byte("x"), overviewwire.MaxReceiptBytes+1))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write(response)
				case "wrong-type":
					w.Header().Set("Content-Type", "text/plain")
					w.Write(response)
				case "wrong-digest":
					var envelope map[string]any
					json.Unmarshal(response, &envelope)
					envelope["requestSha256"] = strings.Repeat("0", 64)
					json.NewEncoder(w).Encode(envelope)
				case "future-time":
					w.Write(overviewTestReceipt(m, raw, map[string]any{"startedAt": h.clock.now().Add(time.Hour), "expiresAt": h.clock.now().Add(75 * time.Minute)}))
				case "duplicate-receipt":
					w.Write(append([]byte(`{"operation":"begin",`), response[1:]...))
				}
				return true
			}
			out, e := burstOverview(s)
			if e == nil || strings.Contains(e.Error(), "sensitive-response-marker") || out.Processes.Status != "pending_retained" || out.Volumes.Status != "pending_retained" || out.Processes.Operations+out.Volumes.Operations != 2 || calls.Load() != 1 {
				t.Fatal("unsafe response accepted/leaked", e, out)
			}
			for _, section := range []*overviewSectionSender{s.processes, s.volumes} {
				w, pending, e := section.state.NextWork()
				if e != nil || !pending || w.Operation != "begin" {
					t.Fatal("unsafe receipt advanced section")
				}
			}
			for _, request := range h.requests {
				if request.message.Operation != "begin" {
					t.Fatal("untrusted conflict caused recovery")
				}
			}
		})
	}
}
func TestOverviewCanceledOrUnboundedBurstDoesNotCollect(t *testing.T) {
	s, _, calls := overviewFixture(t, "tls", 0, 0)
	if _, e := s.Burst(context.Background()); !errors.Is(e, ErrConfiguration) {
		t.Fatal("unbounded caller accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if _, e := s.Burst(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled caller accepted", e)
	}
	if calls.Load() != 0 {
		t.Fatal("source admitted without live deadline")
	}
	if other, e := openOverviewSenderWithSource(s.material, s.now, s.collect); e == nil || other != nil {
		t.Fatal("exclusive section lock ignored")
	}
}
