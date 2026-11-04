package store

import (
	"context"
	"localrmm/internal/windowsfullprocesses"
	watch "localrmm/internal/windowsprocesswatch"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func processWatchStoreFixture(t *testing.T) (watch.Input, watch.Request, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	name := "worker.exe"
	id := "agent_" + strings.Repeat("1", 32)
	c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: strings.Repeat("2", 64), GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: at}
	messages, e := windowsfullprocesses.Build(id, c, 1, windowsfullprocesses.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullprocesses.Row{{Name: &name, NameQuality: "observed"}}})
	if e != nil {
		t.Fatal(e)
	}
	p := &windowsfullprocesses.Complete{Manifest: *messages[0].Manifest, ManifestSHA256: messages[0].ManifestSHA256, ReceivedAt: at}
	in := watch.Input{DeviceID: id, InvitationID: "invite_" + strings.Repeat("4", 32), CertificateHash: strings.Repeat("5", 64), CurrentLeaf: strings.Repeat("5", 64), AuthorityUntil: at.Add(time.Hour), Complete: p, Counts: map[string]int{name: 1}}
	return in, watch.Request{Enabled: true, Names: []string{name}, Consent: true, Source: p}, at
}
func TestWindowsProcessWatchStoreCASPureReadAndMissingUsedState(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, r, at := processWatchStoreFixture(t)
	clock := func() time.Time { return at }
	guard := func(time.Time) error { return nil }
	first, e := s.WindowsProcessWatchState(ctx, in.DeviceID)
	if e != nil || first.DeviceID != "" {
		t.Fatal(e)
	}
	var n int
	if e = s.db.QueryRow(`SELECT count(*) FROM windows_process_watch_used`).Scan(&n); e != nil || n != 0 {
		t.Fatal("GET created state", e)
	}
	state, e := s.ConfigureWindowsProcessWatch(ctx, in, r, clock, guard)
	if e != nil || state.Policy.Revision != 1 {
		t.Fatal(e)
	}
	loaded, e := s.WindowsProcessWatchState(ctx, in.DeviceID)
	if e != nil || loaded.Policy.Names[0] != "worker.exe" {
		t.Fatal(e)
	}
	if _, e = s.ConfigureWindowsProcessWatch(ctx, in, r, clock, guard); e == nil {
		t.Fatal("stale request repeated")
	}
	if _, e = s.db.Exec(`DELETE FROM windows_process_watch_devices WHERE id=?`, in.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsProcessWatchState(ctx, in.DeviceID); e == nil {
		t.Fatal("missing used policy became default off")
	}
	if _, e = s.ConfigureWindowsProcessWatch(ctx, in, r, clock, guard); e == nil {
		t.Fatal("missing used policy reinitialized")
	}
}
func TestWindowsProcessWatchStorePostWaitAndFinalGuards(t *testing.T) {
	for _, mode := range []string{"valid", "source-age", "session", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			s := contactStore(t)
			ctx := context.Background()
			in, r, at := processWatchStoreFixture(t)
			conn, e := s.db.Conn(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			waits := s.db.Stats().WaitCount
			var shifted atomic.Bool
			clock := func() time.Time {
				if shifted.Load() {
					switch mode {
					case "valid":
						return at.Add(time.Second)
					case "source-age":
						return at.Add(5 * time.Minute)
					case "rollback":
						return at.Add(-time.Second)
					}
				}
				return at
			}
			result := make(chan error, 1)
			go func() {
				_, e := s.ConfigureWindowsProcessWatch(ctx, in, r, clock, func(now time.Time) error {
					if mode == "session" && shifted.Load() || now.Before(at) {
						return watch.ErrInvalid
					}
					return nil
				})
				result <- e
			}()
			until := time.Now().Add(5 * time.Second)
			for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if s.db.Stats().WaitCount == waits {
				conn.Close()
				t.Fatal("did not wait")
			}
			shifted.Store(true)
			conn.Close()
			e = <-result
			if (e == nil) != (mode == "valid") {
				t.Fatal("post-wait admission", e)
			}
			state, e := s.WindowsProcessWatchState(ctx, in.DeviceID)
			if e != nil || state.Policy.Enabled != (mode == "valid") {
				t.Fatal(e)
			}
		})
	}
	s := contactStore(t)
	ctx := context.Background()
	in, r, at := processWatchStoreFixture(t)
	calls := 0
	_, e := s.ConfigureWindowsProcessWatch(ctx, in, r, func() time.Time { return at }, func(time.Time) error {
		calls++
		if calls == 2 {
			return watch.ErrInvalid
		}
		return nil
	})
	if e == nil {
		t.Fatal("final guard ignored")
	}
	state, e := s.WindowsProcessWatchState(ctx, in.DeviceID)
	if e != nil || state.DeviceID != "" {
		t.Fatal("failed final guard committed", e)
	}
}

func TestWindowsProcessWatchRestartRetainsExactPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watch.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	in, r, at := processWatchStoreFixture(t)
	want, e := s.ConfigureWindowsProcessWatch(context.Background(), in, r, func() time.Time { return at }, func(time.Time) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.WindowsProcessWatchState(context.Background(), in.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := watch.Encode(want)
	b, _ := watch.Encode(got)
	if string(a) != string(b) {
		t.Fatal("restart replaced policy")
	}
}
