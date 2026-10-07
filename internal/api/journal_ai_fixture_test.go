package api

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"localrmm/internal/analysis"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateJournalAIFixture = flag.Bool("update-journal-ai-fixture", false, "Regenerate synthetic journal AI Go/UI wire fixture; no provider or journal access")

// Real authenticated handlers generate every view. Only random configuration
// identifiers and the model result's generation ID/time are stabilized.
func TestJournalAIGoDTOFixture(t *testing.T) {
	o, clock, f, csrf := journalAIFixture(t)
	clock.now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	clock.inputs[0].AuthorityUntil = clock.now.Add(time.Hour)
	_, disabled := o.call(t, "GET", "/api/ai/journal", nil, "", nil)
	enableJournalFixture(t, o, f, csrf)
	openJournalIncident(t, o, clock)
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil {
		t.Fatal(err)
	}
	f.accept(t, 20)
	calls := 0
	o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls++
		return []byte(`{"observedEvidenceIDs":["journal-row-010"],"hypotheses":[{"statement":"Die protokollierte Fehlermeldung könnte den Dienstvorfall erklären.","evidenceIDs":["journal-row-010"]}],"counterevidence":[],"missingData":["Nur ein begrenztes Zeitfenster wurde gelesen."],"nextCheck":"service"}`), nil
	}})
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	attempts, err := o.app.store.JournalAIAttempts(context.Background())
	if err != nil || len(attempts) != 1 {
		t.Fatal(err)
	}
	entry := o.app.journalAI.results[journalAIKey(attempts[0].DeviceID, attempts[0].IncidentID)]
	if entry == nil {
		t.Fatal("missing fixture model result")
	}
	entry.result.ID = "analysis-" + strings.Repeat("d", 32)
	entry.result.GeneratedAt = clock.now
	fixture := map[string]any{"offSettings": disabled}
	paths := map[string]string{
		"settings":       "/api/ai/journal",
		"source":         "/api/ai/journal/source/" + attempts[0].DeviceID,
		"investigations": "/api/investigations",
		"result":         "/api/ai/journal/" + attempts[0].DeviceID + "/" + attempts[0].IncidentID,
	}
	for key, path := range paths {
		res, v := o.call(t, "GET", path, nil, "", nil)
		if res.StatusCode != 200 {
			t.Fatal(key, res.StatusCode, v)
		}
		fixture[key] = v
	}
	var normalize func(any)
	normalize = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, value := range x {
				if text, ok := value.(string); ok && strings.HasPrefix(text, "cfg-") {
					x[key] = "cfg-" + strings.Repeat("e", 32)
				} else {
					normalize(value)
				}
			}
		case []any:
			for _, value := range x {
				normalize(value)
			}
		}
	}
	normalize(fixture)
	raw, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "web", "src", "journal-ai-go-fixture.json")
	if *updateJournalAIFixture {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, raw) {
		t.Fatal("Journal AI Go/UI fixture differs; review and explicitly regenerate synthetic bytes")
	}
}
