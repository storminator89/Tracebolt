package store

import (
	"context"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/health"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/proactivejournal"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func journalStoreCapture(t *testing.T, s *Store, device, revision, unit string, now time.Time) JournalAIAttempt {
	t.Helper()
	x := health.Incident{ID: "health_0000000000000010", Kind: "service", Key: "service:" + unit, Target: unit, OpenedAt: now, LastObservedAt: now}
	ok, err := s.ClaimJournalAI(context.Background(), device, x, revision, now)
	if err != nil || !ok {
		t.Fatal("fixture claim", err)
	}
	g := journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}
	r, err := journalrequest.NewWithGeneration(device, strings.Repeat("c", 64), 1, journalview.Query{Unit: unit, Start: now.Add(-5 * time.Minute), End: now, MaxPriority: 4}, g, now)
	if err != nil {
		t.Fatal(err)
	}
	a := JournalAIAttempt{DeviceID: device, IncidentID: x.ID, Revision: revision, Unit: unit, State: "preparing", CreatedAt: now}
	if err = s.SetJournalAICapture(context.Background(), a, proactivejournal.Capture{Description: r.Description}); err != nil {
		t.Fatal(err)
	}
	return a
}
func TestJournalAIStoreSharesHealthRateBudget(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	device := "agent_" + strings.Repeat("1", 32)
	revision := "cfg-" + strings.Repeat("2", 32)
	healthIncident := analysisIncident(t, s, device, 1, now)
	if claim := claimAnalysis(t, s, device, healthIncident.ID, "health-scope", now, now); claim == nil {
		t.Fatal("health fixture claim")
	}
	a := journalStoreCapture(t, s, device, revision, "fixture.service", now.Add(10*time.Second))
	if ok, err := s.StartJournalAIModel(ctx, a, now.Add(10*time.Second)); err != nil || ok {
		t.Fatal("journal bypassed shared interval", err)
	}
	if ok, err := s.StartJournalAIModel(ctx, a, now.Add(time.Minute)); err != nil || !ok {
		t.Fatal("journal not admitted after interval", err)
	}
	healthIncident = analysisIncident(t, s, device, 2, now.Add(70*time.Second))
	if claim := claimAnalysis(t, s, device, healthIncident.ID, "health-scope", now, now.Add(70*time.Second)); claim != nil {
		t.Fatal("health bypassed journal interval")
	}
	// Distinct devices avoid rule cooldown while proving the global hourly cap.
	for i := 0; i < 4; i++ {
		id := "agent_" + strings.Repeat(string(rune('3'+i)), 32)
		at := now.Add(time.Duration(i+2) * time.Minute)
		x := analysisIncident(t, s, id, 1, at)
		if claim := claimAnalysis(t, s, id, x.ID, "health-scope", now, at); claim == nil {
			t.Fatal("hourly fixture claim", i)
		}
	}
	a = journalStoreCapture(t, s, "agent_"+strings.Repeat("8", 32), revision, "fixture.service", now.Add(6*time.Minute))
	if ok, err := s.StartJournalAIModel(ctx, a, now.Add(6*time.Minute)); err != nil || ok {
		t.Fatal("journal bypassed shared hourly budget", err)
	}
}
func TestJournalAIStoreRestartQueuesKnownCapturesAndNeverReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	device, revision := "agent_"+strings.Repeat("1", 32), "cfg-"+strings.Repeat("2", 32)
	a := journalStoreCapture(t, s, device, revision, "fixture.service", now)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	attempts, err := s.JournalAIAttempts(context.Background())
	if err != nil || len(attempts) != 1 || attempts[0].State != "cancel_pending" || attempts[0].Capture == nil {
		t.Fatal("restart lost cancellation", err, attempts)
	}
	x := health.Incident{ID: a.IncidentID, Kind: "service", Target: a.Unit, OpenedAt: now, LastObservedAt: now}
	if ok, err := s.ClaimJournalAI(context.Background(), device, x, "cfg-"+strings.Repeat("3", 32), now.Add(time.Hour)); err != nil || ok {
		t.Fatal("restart/provider revision replayed incident", err)
	}
	if err = s.ConfirmJournalAICancel(context.Background(), attempts[0]); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.JournalAICancellationPending(context.Background()); err != nil || pending {
		t.Fatal("confirmed cancellation retained", err)
	}
}
func TestJournalAIStoreRejectsRawScopeInDurableHealthResults(t *testing.T) {
	s := newHealthAnalysisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	x := analysisIncident(t, s, "device", 1, now)
	claim := claimAnalysis(t, s, "device", x.ID, "scope", now, now)
	result := analysisResult(t, claim, nil)
	result.Packet.DataScope = proactivejournal.DataScope
	result.Packet.Evidence[0].Detail = "synthetic-sensitive-journal-marker"
	if err := s.CompleteHealthAnalysis(ctx, "device", x.ID, "scope", result, now); !errors.Is(err, ErrInvalidHealthAnalysis) {
		t.Fatal("raw scope entered durable health store", err)
	}
	var raw []byte
	if err := s.db.QueryRow(`SELECT result FROM health_analyses`).Scan(&raw); err != nil || len(raw) != 0 {
		t.Fatal("sensitive result persisted", err)
	}
	if result.Packet.DataScope == analysis.HealthDataScope {
		t.Fatal("fixture mislabeled")
	}
}

func enabledJournalReceipt(t *testing.T, s *Store, now time.Time) JournalAIReceipt {
	t.Helper()
	old, err := s.JournalAIReceipt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rev, err := JournalAIRevision()
	if err != nil {
		t.Fatal(err)
	}
	r := JournalAIReceipt{Revision: rev, Enabled: true, ManagerID: "fixture-manager", Transport: "tls", ProviderRevision: "cfg-" + strings.Repeat("1", 32), CredentialGeneration: "cfg-" + strings.Repeat("2", 32), BaseURL: "http://127.0.0.1:11434/v1", Model: "fixture-model", Targets: []proactivejournal.Target{{DeviceID: "agent_" + strings.Repeat("3", 32), Unit: "fixture.service", Generation: journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}}}, LookbackMinutes: 5, DataScope: proactivejournal.DataScope, CaptureAcknowledged: true, ExportAcknowledged: true, ApprovedBy: "shared-administrator", ApprovedAt: now}
	if err = s.SaveJournalAIReceipt(context.Background(), old.Revision, r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestJournalAIMutationFenceSurvivesFailedDisableAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fenced.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	approved := enabledJournalReceipt(t, s, now)
	if _, err = s.db.Exec(`CREATE TRIGGER fixture_scope_failure BEFORE UPDATE ON journal_ai_settings BEGIN SELECT RAISE(FAIL,'synthetic scope-write failure'); END`); err != nil {
		t.Fatal(err)
	}
	rev, _ := JournalAIRevision()
	disabled := JournalAIReceipt{Revision: rev, Targets: []proactivejournal.Target{}, DataScope: proactivejournal.DataScope}
	if err = s.SaveJournalAIReceipt(context.Background(), approved.Revision, disabled); !errors.Is(err, ErrJournalAIFenced) {
		t.Fatal("failed disable was not durably fenced", err)
	}
	if _, err = s.JournalAIReceipt(context.Background()); !errors.Is(err, ErrJournalAIFenced) {
		t.Fatal("fenced enabled receipt remained readable", err)
	}
	var n int
	if err = s.db.QueryRow(`SELECT count(*) FROM journal_ai_mutations`).Scan(&n); err != nil || n != 1 {
		t.Fatal("missing durable blocker", err, n)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal("journal-only fence blocked ordinary manager startup", err)
	}
	defer reopened.Close()
	if _, err = reopened.JournalAIReceipt(context.Background()); !errors.Is(err, ErrJournalAIFenced) {
		t.Fatal("restart adopted old enabled receipt", err)
	}
	if _, err = reopened.HealthStates(context.Background()); err != nil {
		t.Fatal("journal fence blocked health state", err)
	}
}
func TestJournalAIFenceCreationFailureDoesNotClaimDurableStop(t *testing.T) {
	s := newHealthAnalysisStore(t)
	approved := enabledJournalReceipt(t, s, time.Now().UTC())
	if _, err := s.db.Exec(`CREATE TRIGGER fixture_fence_failure BEFORE INSERT ON journal_ai_mutations BEGIN SELECT RAISE(FAIL,'synthetic fence-write failure'); END`); err != nil {
		t.Fatal(err)
	}
	rev, _ := JournalAIRevision()
	disabled := JournalAIReceipt{Revision: rev, Targets: []proactivejournal.Target{}, DataScope: proactivejournal.DataScope}
	if err := s.SaveJournalAIReceipt(context.Background(), approved.Revision, disabled); !errors.Is(err, ErrJournalAIFenceUnconfirmed) {
		t.Fatal("failure falsely claimed durable stop", err)
	}
	current, err := s.JournalAIReceipt(context.Background())
	if err != nil || !current.Enabled || current.Revision != approved.Revision {
		t.Fatal("fixture did not retain old receipt", err)
	}
	var n int
	if err = s.db.QueryRow(`SELECT count(*) FROM journal_ai_mutations`).Scan(&n); err != nil || n != 0 {
		t.Fatal("fixture unexpectedly persisted a blocker", err)
	}
}
