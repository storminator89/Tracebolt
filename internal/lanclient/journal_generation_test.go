//go:build linux

package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/agentloop"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalwire"
	"net/http"
	"strings"
	"testing"
	"time"
)

func migrateFixture(t *testing.T, f *journalFixture) {
	t.Helper()
	f.local.policy.SchemaVersion = journalpolicy.VersionV2
	f.local.policy.Revision = 1
	f.local.policy.Generation = strings.Repeat("e", 64)
	var e error
	f.local.generation, e = journalpolicy.PolicyGeneration(f.local.policy)
	if e != nil {
		t.Fatal(e)
	}
	m := f.s.material
	st, e := journalgenerationstate.Initialize(context.Background(), journalGenerationDirectory(m.config), journalgenerationstate.Record{SchemaVersion: journalgenerationstate.Version, SenderBinding: m.binding, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), PolicyGeneration: f.local.generation})
	if e != nil {
		t.Fatal(e)
	}
	st.Close()
	original := f.s.exchange
	f.s.exchange = func(ctx context.Context, path string, seq uint64, raw []byte) ([]byte, int, error) {
		if path == journalwire.GenerationPath {
			report, e := journalwire.DecodeGenerationReport(raw)
			if e != nil || report.Sequence != seq || report.Tuple != f.local.generation {
				t.Fatal("invalid generation report", e)
			}
			return raw, http.StatusOK, nil
		}
		return original(ctx, path, seq, raw)
	}
}
func TestGenerationBoundSenderRejectsOldRequestsWithoutCapture(t *testing.T) {
	f := newJournalFixture(t)
	migrateFixture(t, f)
	if status := f.s.Run(context.Background()); status != "denied" || f.claims != 0 || f.captures != 0 {
		t.Fatal(status, f.claims, f.captures)
	}
	var e error
	f.record, e = journalrequest.NewWithGeneration(f.s.material.config.AgentID, journalLeaf(f.s.material), 9, f.record.Description.Query, f.local.generation, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if status := f.s.Run(context.Background()); status != "pending_retained" || f.claims != 1 || f.captures != 1 {
		t.Fatal(status, f.claims, f.captures)
	}
	if f.s.pending.grant.Description.PolicyGeneration != f.local.generation {
		t.Fatal("generation lost")
	}
	st, e := journalgenerationstate.Open(context.Background(), journalGenerationDirectory(f.s.material.config))
	if e != nil {
		t.Fatal(e)
	}
	r, _ := st.Record()
	if r.ReportSequence != 2 {
		t.Fatal("report floor")
	}
	st.Close()
}
func TestGenerationChangedAfterCaptureDiscardsOldBody(t *testing.T) {
	f := newJournalFixture(t)
	migrateFixture(t, f)
	var e error
	f.record, e = journalrequest.NewWithGeneration(f.s.material.config.AgentID, journalLeaf(f.s.material), 9, f.record.Description.Query, f.local.generation, f.now)
	if e != nil {
		t.Fatal(e)
	}
	f.s.Run(context.Background())
	before := f.sends
	f.local.policy.Revision++
	f.local.policy.Generation = strings.Repeat("f", 64)
	f.local.generation, e = journalpolicy.PolicyGeneration(f.local.policy)
	if e != nil {
		t.Fatal(e)
	}
	st, e := journalgenerationstate.Open(context.Background(), journalGenerationDirectory(f.s.material.config))
	if e != nil {
		t.Fatal(e)
	}
	r, _ := st.Record()
	if e = st.Advance(context.Background(), r, f.local.generation); e != nil {
		t.Fatal(e)
	}
	st.Close()
	f.local.revision = "local-2"
	f.now = f.now.Add(time.Second)
	if status := f.s.Run(context.Background()); status != "denied" || f.s.pending != nil || f.sends != before || f.captures != 1 {
		t.Fatal(status)
	}
}
func TestGenerationReportFailureCannotReachClaim(t *testing.T) {
	for _, mode := range []string{"failure", "wrong-echo", "missing-state"} {
		t.Run(mode, func(t *testing.T) {
			f := newJournalFixture(t)
			migrateFixture(t, f)
			base := f.s.exchange
			f.s.exchange = func(ctx context.Context, path string, seq uint64, raw []byte) ([]byte, int, error) {
				if path == journalwire.GenerationPath {
					if mode == "failure" {
						return nil, 503, nil
					}
					var r journalgeneration.Report
					json.Unmarshal(raw, &r)
					r.Sequence++
					changed, _ := json.Marshal(r)
					return changed, 200, nil
				}
				return base(ctx, path, seq, raw)
			}
			if mode == "missing-state" {
				f.s.material.config.StateDirectory = t.TempDir()
			}
			if status := f.s.Run(context.Background()); status != "unavailable" || f.captures != 0 || f.claims != 0 {
				t.Fatal(status)
			}
		})
	}
}

func TestGenerationFailureKeepsOrdinaryAgentLoopRunning(t *testing.T) {
	f := newJournalFixture(t)
	migrateFixture(t, f)
	f.s.exchange = func(_ context.Context, path string, _ uint64, _ []byte) ([]byte, int, error) {
		if path != journalwire.GenerationPath {
			t.Fatal("generation failure reached request flow")
		}
		return nil, 503, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &instantClock{at: f.now}
	waits, ordinary := 0, 0
	summary, err := agentloop.Run(ctx, agentloop.Config{Interval: 15 * time.Second}, agentloop.Dependencies{Clock: clock, Random: func(int64) int64 { return 0 }, Attempt: func(ctx context.Context) agentloop.Result {
		ordinary++
		f.now = clock.Now()
		return agentloop.Result{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: uint64(ordinary), JournalStatus: f.s.Run(ctx)}}
	}, Observe: func(event agentloop.Event) error {
		if event.Phase == agentloop.Finished && event.Metadata.JournalStatus != "unavailable" {
			t.Fatal("unbounded status escaped")
		}
		if event.Phase == agentloop.Waiting {
			waits++
			if waits == 2 {
				cancel()
			}
		}
		return nil
	}})
	if !errors.Is(err, context.Canceled) || summary.Reason != agentloop.Cancelled || summary.Attempts != 2 || ordinary != 2 || waits != 2 || f.captures != 0 || f.claims != 0 {
		t.Fatal(summary, err, ordinary, waits)
	}
}
