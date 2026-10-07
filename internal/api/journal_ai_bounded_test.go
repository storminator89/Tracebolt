package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"localrmm/internal/analysis"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/proactivejournal"
	"localrmm/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func changeToRetainedAI(f *aiJournalFixture) {
	f.retained = true
	f.generation = journalgeneration.Tuple{Revision: 2, Generation: strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64)}
}
func TestJournalAIRetainedScopeChangeRequiresFreshApprovalIncludingAfterRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "restart"}[restart], func(t *testing.T) {
			o, clock, f, csrf := journalAIFixture(t)
			path := filepath.Join(t.TempDir(), "scope.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { o.app.store.Close() }()
			o.app.store = st
			o.app.health.store = st
			enableJournalFixture(t, o, f, csrf)
			original, err := st.JournalAIReceipt(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			changeToRetainedAI(f)
			if restart {
				if err := st.Close(); err != nil {
					t.Fatal(err)
				}
				st, err = store.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				o.app.store = st
				o.app.health.store = st
			}
			res, v := o.call(t, "GET", "/api/ai/journal", nil, "", nil)
			if res.StatusCode != 200 || v["ready"] != false || v["enabled"] != true {
				t.Fatal("scope change hidden", res.StatusCode, v)
			}
			saved, err := st.JournalAIReceipt(context.Background())
			if err != nil || saved.Revision != original.Revision || saved.Targets[0].Generation != original.Targets[0].Generation || !saved.ApprovedAt.Equal(original.ApprovedAt) {
				t.Fatal("read/restart rebound approval", err)
			}
			if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || f.creates != 0 {
				t.Fatal("old scope captured", err)
			}
			body := journalApproval(t, o, f)
			body["targets"] = original.Targets
			if res, _ := o.call(t, "POST", "/api/ai/journal", body, csrf, nil); res.StatusCode != 409 {
				t.Fatal("old generation approved", res.StatusCode)
			}
			body = journalApproval(t, o, f)
			body["acknowledgeExport"] = false
			if res, _ := o.call(t, "POST", "/api/ai/journal", body, csrf, nil); res.StatusCode != 400 {
				t.Fatal("local v4 grant became export approval", res.StatusCode)
			}
			body = journalApproval(t, o, f)
			body["lookbackMinutes"] = 15
			if res, _ := o.call(t, "POST", "/api/ai/journal", body, csrf, nil); res.StatusCode != 200 {
				t.Fatal("fresh bounded v4 review denied", res.StatusCode)
			}
			renewed, err := st.JournalAIReceipt(context.Background())
			if err != nil || renewed.Revision == original.Revision || renewed.Targets[0].Generation != f.generation || renewed.LookbackMinutes != 15 || f.creates != 0 {
				t.Fatal("renewed scope incorrectly bound", err)
			}
			if restart {
				if err := st.Close(); err != nil {
					t.Fatal(err)
				}
				st, err = store.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				o.app.store, o.app.health.store = st, st
				restored, err := st.JournalAIReceipt(context.Background())
				if err != nil || restored.Revision != renewed.Revision || !restored.ApprovedAt.Equal(renewed.ApprovedAt) || restored.Targets[0].Generation != f.generation {
					t.Fatal("new-generation restart changed consent", err)
				}
			}
			openJournalIncident(t, o, clock)
			if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || f.creates != 1 {
				t.Fatal("new scope capture", err)
			}
			if f.record.Description.SchemaVersion != journalrequest.SchemaVersionV2 || f.record.Description.PolicyGeneration != f.generation || f.record.Description.Query.BrowseMode != "" || f.record.Description.Query.Search != "" || f.record.Description.Query.Cursor != "" || f.record.Description.Query.End.Sub(f.record.Description.Query.Start) != 15*time.Minute {
				t.Fatal("retained traversal reached automatic capture")
			}
			f.accept(t, 20)
			calls := 0
			o.app.ai.service = analysis.NewService(proactiveFake{call: func(_ context.Context, r analysis.ProviderRequest) ([]byte, error) {
				calls++
				if !strings.Contains(r.Messages[1].Content, "journal-row-010") || strings.Contains(r.Messages[1].Content, "synthetic-log-secret") {
					t.Fatal("bounded export projection lost")
				}
				return []byte(proactiveFindings), nil
			}})
			if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || calls != 1 || f.pages != 2 {
				t.Fatal("bounded v4 analysis", err, calls, f.pages)
			}
		})
	}
}

func TestJournalAIV4PolicyChangesAndProviderReplacementBlockExports(t *testing.T) {
	for _, when := range []string{"before-capture", "before-export", "in-flight", "provider-before-capture", "provider-in-flight"} {
		t.Run(when, func(t *testing.T) {
			o, clock, f, csrf := journalAIFixture(t)
			changeToRetainedAI(f)
			enableJournalFixture(t, o, f, csrf)
			openJournalIncident(t, o, clock)
			changePolicy := func() {
				f.generation.Revision++
				f.generation.Generation = strings.Repeat("e", 64)
				f.generation.PolicyDigest = "sha256:" + strings.Repeat("f", 64)
			}
			changeProvider := func() {
				if code, _ := savePersistentFixture(t, o, csrf, "http://127.0.0.1:11434/v1", "", false); code != 200 {
					t.Fatal(code)
				}
			}
			if when == "before-capture" {
				changePolicy()
			}
			if when == "provider-before-capture" {
				changeProvider()
			}
			if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(when, "before-capture") {
				if f.creates != 0 {
					t.Fatal("stale approval captured")
				}
				return
			}
			f.accept(t, 1)
			calls := 0
			if when == "before-export" {
				n := 0
				f.change = func(action string) {
					if action == "generation" {
						n++
						if n == 2 {
							changePolicy()
						}
					}
				}
			}
			o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
				calls++
				if when == "in-flight" {
					changePolicy()
				}
				if when == "provider-in-flight" {
					changeProvider()
				}
				return []byte(proactiveFindings), nil
			}})
			if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil {
				t.Fatal(err)
			}
			if when == "before-export" && calls != 0 {
				t.Fatal("policy changed during page preparation but exported")
			}
			if len(o.app.journalAI.results) != 0 {
				t.Fatal("changed authority result published")
			}
		})
	}
}

func TestJournalAIV4UnapprovedWindowIsRejectedBeforeProvider(t *testing.T) {
	o, clock, f, csrf := journalAIFixture(t)
	path := filepath.Join(t.TempDir(), "window.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	o.app.store, o.app.health.store = db, db
	fault, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer fault.Close()

	changeToRetainedAI(f)
	enableJournalFixture(t, o, f, csrf)
	openJournalIncident(t, o, clock)
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil {
		t.Fatal(err)
	}
	attempts, err := o.app.store.JournalAIAttempts(context.Background())
	if err != nil || len(attempts) != 1 {
		t.Fatal(err)
	}
	old := f.record.Description
	q := old.Query
	q.Start = q.End.Add(-15 * time.Minute)
	replacement, err := journalrequest.NewWithGeneration(old.DeviceID, old.CertificateHash, old.Identity.Sequence, q, old.PolicyGeneration, old.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	f.record = &replacement
	// Simulate corrupted metadata consistent with the available source: even a
	// valid bounded capture cannot replace the separately approved 5-minute one.
	a := attempts[0]
	a.Capture = &proactivejournal.Capture{Description: replacement.Description}
	raw, err := json.Marshal(a.Capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fault.ExecContext(context.Background(), "UPDATE journal_ai_attempts SET capture=? WHERE device=? AND incident=?", raw, a.DeviceID, a.IncidentID); err != nil {
		t.Fatal(err)
	}
	f.accept(t, 1)
	calls := 0
	o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		calls++
		return []byte(proactiveFindings), nil
	}})
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || calls != 0 {
		t.Fatal("unapproved window exported", err)
	}
}

func TestJournalAIOldBoundedApprovalCannotCaptureUnderRetainedScope(t *testing.T) {
	o, clock, f, csrf := journalAIFixture(t)
	enableJournalFixture(t, o, f, csrf)
	changeToRetainedAI(f)
	openJournalIncident(t, o, clock)
	if err := o.app.runJournalAIStep(context.Background(), o.app.health); err != nil || f.creates != 0 {
		t.Fatal("new incident used old local scope approval", err)
	}
}
