package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/analysis"
	"runtime"
	"strings"
	"testing"
)

const proactivePanicCanary = "PRIVATE-LOG-AND-PANIC-CANARY"

// These integration fixtures exercise the manager's real protected local store,
// which is only supported on Linux. They use no real provider or journal source.
func TestProactiveHealthProviderPanicTerminalizesWithoutRetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected manager store is Linux-only")
	}
	o, source := investigationsFixture(t)
	_, session := o.login(t)
	id := source.inputs[0].DeviceID
	calls := 0
	setProactiveFixtureProvider(o, func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls++
		panic(proactivePanicCanary)
	})
	proactiveEnable(t, o, session["csrfToken"].(string), id)
	seedProactiveIncident(t, o, source)
	if err := o.app.runProactiveAI(context.Background(), o.app.health); err != nil {
		t.Fatal(err)
	}
	records, err := o.app.store.HealthAnalyses(context.Background(), id)
	if err != nil || len(records) != 1 || calls != 1 {
		t.Fatalf("unexpected record count or state: %d calls=%d err=%v", len(records), calls, err)
	}
	for _, record := range records {
		if record.Status != "unavailable" || record.Result == nil || record.Result.AI.Findings != nil {
			t.Fatal("provider panic did not finish as unavailable")
		}
	}
	raw, err := json.Marshal(records)
	if err != nil || strings.Contains(string(raw), proactivePanicCanary) {
		t.Fatal("panic leaked into health record")
	}
	if err = o.app.runProactiveAI(context.Background(), o.app.health); err != nil || calls != 1 {
		t.Fatal("failed attempt was retried", err, calls)
	}
	o.app.ai.mu.Lock()
	busy := o.app.ai.busy
	o.app.ai.mu.Unlock()
	if busy {
		t.Fatal("manager AI slot remained busy")
	}
}

func TestProactiveJournalProviderPanicDoesNotPersistContentOrRetry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected manager store is Linux-only")
	}
	o, clock, fixture, csrf := journalAIFixture(t)
	res, _ := o.call(t, "POST", "/api/ai/journal", journalApproval(t, o, fixture), csrf, nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	openJournalIncident(t, o, clock)
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || fixture.creates != 1 {
		t.Fatal("capture not created", err)
	}
	fixture.accept(t, 20)
	calls := 0
	o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls++
		panic(proactivePanicCanary)
	}})
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil {
		t.Fatal(err)
	}
	attempts, err := o.app.store.JournalAIAttempts(context.Background())
	if err != nil || len(attempts) != 1 || attempts[0].State != "unavailable" || calls != 1 || len(o.app.journalAI.results) != 0 {
		t.Fatalf("unexpected journal outcome: records=%d calls=%d err=%v", len(attempts), calls, err)
	}
	raw, err := json.Marshal(attempts)
	if err != nil || strings.Contains(string(raw), proactivePanicCanary) || strings.Contains(string(raw), "IGNORE INSTRUCTIONS") || strings.Contains(string(raw), "synthetic-log-secret") {
		t.Fatal("panic or log content persisted")
	}
	if err = o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || calls != 1 || fixture.creates != 1 {
		t.Fatal("failed attempt was retried", err)
	}
	o.app.ai.mu.Lock()
	busy := o.app.ai.busy
	o.app.ai.mu.Unlock()
	if busy {
		t.Fatal("manager AI slot remained busy")
	}
}
