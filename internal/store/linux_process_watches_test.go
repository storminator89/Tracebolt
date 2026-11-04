package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"localrmm/internal/linuxprocesswatch"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func processWatchInput() (linuxprocesswatch.Input, linuxprocesswatch.ConfigureRequest, time.Time) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	in := linuxprocesswatch.Input{DeviceID: "agent_" + strings.Repeat("a", 32), Identity: strings.Repeat("b", 64), Epoch: strings.Repeat("c", 32), SourceToken: "processsource_" + strings.Repeat("d", 32), Authorized: true, Available: true, Reason: "none", AuthorityUntil: at.Add(time.Hour), Sample: &linuxprocesswatch.Generation{Sequence: "1", GenerationID: "sample_" + strings.Repeat("e", 32), ManifestHash: strings.Repeat("f", 64), CaptureStartedAt: at, CaptureFinishedAt: at, ReceivedAt: at, TotalRows: 1}, Counts: []linuxprocesswatch.Count{{Name: "daemon"}}}
	r := linuxprocesswatch.ConfigureRequest{RequestID: fmt.Sprintf("processrequest_%032x", 1), SourceToken: in.SourceToken, Enabled: true, Names: []string{"daemon"}, ConsecutiveFailures: 2, RetentionAcknowledged: true}
	return in, r, at
}
func processWatchRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if e := s.db.QueryRow(`SELECT body FROM linux_process_watches WHERE id=?`, id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestLinuxProcessWatchDefaultOffReadAndEvaluation(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, _, now := processWatchInput()
	if v, e := s.LinuxProcessWatchState(ctx, in.DeviceID); e != nil || v.Policy.Enabled {
		t.Fatal(v, e)
	}
	if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, nil, nil, true, func() time.Time { return now }, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"linux_process_watches", "linux_process_watch_markers"} {
		var n int
		if e := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("default-off write", table, n, e)
		}
	}
}
func TestLinuxProcessWatchGuardsRollbackEveryBoundary(t *testing.T) {
	for _, stop := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			s := contactStore(t)
			in, r, now := processWatchInput()
			calls := 0
			denied := errors.New("source or session expired")
			_, _, e := s.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, func() time.Time { return now }, func(time.Time) error {
				calls++
				if calls == stop {
					return denied
				}
				return nil
			})
			if !errors.Is(e, denied) || calls != stop {
				t.Fatal("guard not enforced", e, calls)
			}
			for _, table := range []string{"linux_process_watches", "linux_process_watch_markers"} {
				var n int
				if e := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); e != nil || n != 0 {
					t.Fatal("failed guard persisted", table, n, e)
				}
			}
			if _, _, e = s.UpdateLinuxProcessWatches(context.Background(), in, &r, nil, false, func() time.Time { return now }, func(time.Time) error { return nil }); e != nil {
				t.Fatal("guard failure latched storage", e)
			}
		})
	}
}
func TestLinuxProcessWatchRevisionReplayAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	ctx := context.Background()
	in, r, now := processWatchInput()
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	if v, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil || v.Revision != 1 {
		t.Fatal(v, e)
	}
	before := processWatchRaw(t, s, in.DeviceID)
	if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil || !bytes.Equal(before, processWatchRaw(t, s, in.DeviceID)) {
		t.Fatal("retry changed bytes", e)
	}
	r.RequestID = fmt.Sprintf("processrequest_%032x", 2)
	if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); !errors.Is(e, linuxprocesswatch.ErrConflict) {
		t.Fatal("stale revision accepted", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.LinuxProcessWatchState(ctx, in.DeviceID)
	if e != nil || v.Revision != 1 || !v.Policy.Enabled || !bytes.Equal(before, processWatchRaw(t, s, in.DeviceID)) {
		t.Fatal("restart changed state", e)
	}
	r.ExpectedRevision = 1
	r.Enabled = false
	r.Names = nil
	r.ConsecutiveFailures = 0
	r.RetentionAcknowledged = false
	if v, _, e = s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil || v.Revision != 2 || v.Policy.Enabled {
		t.Fatal("post-restart disable", e)
	}
}
func TestLinuxProcessWatchTamperFailsClosed(t *testing.T) {
	for _, mode := range []string{"marker_missing", "body_missing", "marker_replaced", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			in, r, now := processWatchInput()
			clock := func() time.Time { return now }
			guard := func(time.Time) error { return nil }
			if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil {
				t.Fatal(e)
			}
			var e error
			switch mode {
			case "marker_missing":
				_, e = s.db.Exec(`DELETE FROM linux_process_watch_markers`)
			case "body_missing":
				_, e = s.db.Exec(`DELETE FROM linux_process_watches`)
			case "marker_replaced":
				_, e = s.db.Exec(`UPDATE linux_process_watch_markers SET id=?`, "agent_"+strings.Repeat("9", 32))
			case "noncanonical":
				_, e = s.db.Exec(`UPDATE linux_process_watches SET body=?`, append(processWatchRaw(t, s, in.DeviceID), ' '))
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.LinuxProcessWatchState(ctx, in.DeviceID); !errors.Is(e, ErrLinuxProcessWatchUnavailable) {
				t.Fatal("tamper accepted", e)
			}
			if _, _, e = s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); !errors.Is(e, ErrLinuxProcessWatchUnavailable) {
				t.Fatal("tamper repaired", e)
			}
		})
	}
}

func TestLinuxProcessWatchByteBudgetPreservesOpenAndStorageUsability(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, r, base := processWatchInput()
	in.AuthorityUntil = base.Add(24 * time.Hour)
	cycling, open := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r.Names = []string{cycling, open}
	in.Counts = []linuxprocesswatch.Count{{Name: cycling}, {Name: open}}
	now := base
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil {
		t.Fatal(e)
	}
	seq := 2
	for episode := 0; episode < 140; episode++ {
		for _, active := range []uint32{0, 0, 1, 1} {
			now = base.Add(time.Duration(seq) * 10 * time.Second)
			in.Sample = &linuxprocesswatch.Generation{Sequence: fmt.Sprint(seq), GenerationID: fmt.Sprintf("sample_%032x", seq), ManifestHash: strings.Repeat("f", 64), CaptureStartedAt: now, CaptureFinishedAt: now, ReceivedAt: now, TotalRows: 10}
			in.Counts = []linuxprocesswatch.Count{{Name: cycling, ActiveCount: active}, {Name: open}}
			state, _, e := s.UpdateLinuxProcessWatches(ctx, in, nil, nil, true, clock, guard)
			if e != nil {
				t.Fatalf("episode %d sequence %d: %v", episode, seq, e)
			}
			raw, e := linuxprocesswatch.Encode(state)
			if e != nil || len(raw) > linuxprocesswatch.MaxBytes {
				t.Fatal("oversized persisted ledger", len(raw), e)
			}
			seq++
		}
	}
	state, e := s.LinuxProcessWatchState(ctx, in.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	if state.EarlierOmitted == 0 || uint64(len(state.Incidents))+state.EarlierOmitted != 141 {
		t.Fatal("byte-budget omission accounting", len(state.Incidents), state.EarlierOmitted)
	}
	openCount := 0
	for _, incident := range state.Incidents {
		if incident.State == "open" {
			openCount++
			if incident.Name != open || incident.ID != "processincident_0000000000000002" {
				t.Fatal("original open incident replaced")
			}
		}
	}
	if openCount != 1 {
		t.Fatal("open incident evicted", openCount)
	}
	// Still accept an explicit policy update after byte-bound pruning.
	r.ExpectedRevision = state.Revision
	r.RequestID = fmt.Sprintf("processrequest_%032x", 2)
	r.Enabled = false
	r.Names = nil
	r.ConsecutiveFailures = 0
	r.RetentionAcknowledged = false
	if _, _, e = s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil {
		t.Fatal("byte pressure latched storage unavailable", e)
	}
}

func TestLinuxProcessWatchDisableWithoutAvailableGeneration(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, r, now := processWatchInput()
	clock := func() time.Time { return now }
	guard := func(time.Time) error { return nil }
	if _, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil {
		t.Fatal(e)
	}
	in.Available = false
	in.Reason = "no_generation"
	in.Sample = nil
	in.Counts = nil
	r.ExpectedRevision = 1
	r.RequestID = fmt.Sprintf("processrequest_%032x", 2)
	r.Enabled = false
	r.Names = nil
	r.ConsecutiveFailures = 0
	r.RetentionAcknowledged = false
	if state, _, e := s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, guard); e != nil || state.Policy.Enabled || state.Revision != 2 {
		t.Fatal("authenticated unavailable source blocked disable", e)
	}
}

func TestLinuxProcessWatchListRejectsOrphanMarkerWithoutLedgers(t *testing.T) {
	s := contactStore(t)
	if _, e := s.db.Exec(`INSERT INTO linux_process_watch_markers(id) VALUES(?)`, "agent_"+strings.Repeat("a", 32)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.LinuxProcessWatchStates(context.Background()); !errors.Is(e, ErrLinuxProcessWatchUnavailable) {
		t.Fatal("missing used ledger treated as empty defaults", e)
	}
	if !s.linuxProcessWatchBlocked.Load() {
		t.Fatal("corrupt marker set did not latch")
	}
}

func TestLinuxProcessWatchRetentionOnlyNeverAdoptsOrEarnsEvidence(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, r, now := processWatchInput()
	clock := func() time.Time { return now }
	if e := s.PruneLinuxProcessWatchHistory(ctx, in.DeviceID, clock); e != nil {
		t.Fatal(e)
	}
	states, e := s.LinuxProcessWatchStates(ctx)
	if e != nil || len(states) != 0 {
		t.Fatal("retention adopted default-off state", e)
	}
	if _, _, e = s.UpdateLinuxProcessWatches(ctx, in, &r, nil, false, clock, func(time.Time) error { return nil }); e != nil {
		t.Fatal(e)
	}
	before, e := s.LinuxProcessWatchState(ctx, in.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	if e = s.PruneLinuxProcessWatchHistory(ctx, in.DeviceID, clock); e != nil {
		t.Fatal(e)
	}
	after, e := s.LinuxProcessWatchState(ctx, in.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	before.ClockFloor = now
	a, _ := linuxprocesswatch.Encode(before)
	b, _ := linuxprocesswatch.Encode(after)
	if !bytes.Equal(a, b) {
		t.Fatal("retention changed observations, policy or requests")
	}
	now = now.Add(-time.Hour)
	if e = s.PruneLinuxProcessWatchHistory(ctx, in.DeviceID, clock); e != nil {
		t.Fatal(e)
	}
	after, e = s.LinuxProcessWatchState(ctx, in.DeviceID)
	if e != nil || after.ClockFloor.Before(before.ClockFloor) {
		t.Fatal("retention decreased floor", e)
	}
}
