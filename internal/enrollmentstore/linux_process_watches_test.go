package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/linuxprocesswatch"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readProcessWatch(t *testing.T, s *Store, device string, names []string, epoch string, at time.Time) linuxprocesswatch.Input {
	t.Helper()
	var got linuxprocesswatch.Input
	e := s.WithLinuxProcessWatch(context.Background(), device, names, epoch, func() time.Time { return at }, func(in linuxprocesswatch.Input, guard func(time.Time) error) error { got = in; return guard(at) })
	if e != nil {
		t.Fatal(e)
	}
	return got
}
func TestLinuxProcessWatchExactCountsAndSourceBinding(t *testing.T) {
	f, s, path, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	epoch := strings.Repeat("a", 32)
	source := completeoverview.Empty(id("sample", 900), at, completeoverview.ReasonReadFailed)
	names := []string{"daemon", "daemon", "daemon", "daemon", "daemon", "daemon", "daemon", "daemon", "daemon", "Daemon", "daemon-helper", " daemon ", `literal\name`}
	states := []string{"R", "S", "D", "I", "P", "T", "t", "Z", "X", "R", "R", "R", "R"}
	// Put an exact match beyond several chunk boundaries; prefixes never count.
	for i := 0; i < 600; i++ {
		names = append(names, "daemon-helper")
		states = append(states, "R")
	}
	names = append(names, "daemon")
	states = append(states, "R")
	for i, name := range names {
		fields := make([]string, 50)
		for j := range fields {
			fields[j] = "0"
		}
		fields[0], fields[1], fields[17] = states[i], "2", "1"
		pid := uint32(i + 1)
		row, e := completeoverview.ParseProcessStat([]byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))), pid, 4096, 100)
		if e != nil {
			t.Fatal(e)
		}
		source.Processes.Items = append(source.Processes.Items, row)
	}
	source.Processes.Items = append(source.Processes.Items, completeoverview.Process{PID: 999, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	count := uint64(len(source.Processes.Items))
	source.Processes.Meta = completeoverview.SectionMeta{GenerationID: source.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: count - 1, Denied: 1}}
	generation, _ := overviewwire.GenerationID(device, "processes", 1)
	m, chunks, e := overviewgeneration.Build(ctx, source, "processes", generation, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := overviewgeneration.ManifestDigest(m)
	b := OverviewBinding{"processes", 1, generation, hash}
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	selected := []string{"daemon", "Daemon", "missing", `literal\name`}
	in := readProcessWatch(t, s, device, selected, epoch, at)
	want := []linuxprocesswatch.Count{{Name: "daemon", ActiveCount: 6, NonRunningCount: 4}, {Name: "Daemon", ActiveCount: 1}, {Name: "missing"}, {Name: `literal\name`, ActiveCount: 1}}
	if !in.Authorized || !in.Available || in.Reason != "none" || in.Sample == nil || in.Sample.UnidentifiedRows != 1 || in.Sample.TotalRows != uint32(count) || !reflect.DeepEqual(in.Counts, want) {
		t.Fatalf("wrong exact source counts: %+v", in)
	}
	if len(in.Identity) != 64 || !strings.HasPrefix(in.SourceToken, "processsource_") {
		t.Fatal("missing authenticated source binding")
	}
	s.Close()
	s = f.open(t, path)
	again := readProcessWatch(t, s, device, selected, epoch, at.Add(time.Second))
	if !reflect.DeepEqual(in, again) {
		t.Fatal("restart refreshed source or counts")
	}
	changed := readProcessWatch(t, s, device, selected, strings.Repeat("b", 32), at.Add(time.Second))
	if changed.Identity != in.Identity || changed.SourceToken == in.SourceToken {
		t.Fatal("epoch not bound to source token")
	}
	ctrl := control(snap, 91)
	ctrl.Now = at.Add(2 * time.Second).Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctrl, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	called := false
	e = s.WithLinuxProcessWatch(ctx, device, selected, epoch, func() time.Time { return at.Add(3 * time.Second) }, func(linuxprocesswatch.Input, func(time.Time) error) error { called = true; return nil })
	if e == nil || called {
		t.Fatal("revoked source reached callback", e)
	}
}
func TestLinuxProcessWatchRejectsIncompleteNewerAndStaleSources(t *testing.T) {
	for _, mode := range []string{"none", "partial", "newer_partial", "newer_failed", "stale"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			device := snap.Approval.DeviceID
			want := "no_generation"
			if mode != "none" {
				b, m, c := overviewGeneration(t, device, 1, 300, at)
				if mode == "partial" {
					stageOverview(t, s, snap, cert, b, m, c[:1], at)
				} else {
					promoteOverview(t, s, snap, cert, b, m, c, at)
				}
			}
			if strings.HasPrefix(mode, "newer_") {
				b, m, c := overviewGeneration(t, device, 2, 300, at.Add(time.Second))
				stageOverview(t, s, snap, cert, b, m, c[:1], at.Add(time.Second))
				if mode == "newer_failed" {
					if e := s.OverviewAbort(context.Background(), snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second)); e != nil {
						t.Fatal(e)
					}
				}
				want = "newer_attempt"
			}
			now := at.Add(2 * time.Second)
			if mode == "stale" {
				now = at.Add(linuxprocesswatch.MaxAge)
				want = "stale"
			}
			in := readProcessWatch(t, s, device, []string{"daemon"}, strings.Repeat("a", 32), now)
			if in.Available || in.Sample != nil || len(in.Counts) != 0 || in.Reason != want {
				t.Fatalf("unsafe source admitted: %+v", in)
			}
		})
	}
}
func TestLinuxProcessWatchGuardExpiryAndValidation(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	b, m, c := overviewGeneration(t, device, 1, 1, at)
	promoteOverview(t, s, snap, cert, b, m, c, at)
	epoch := strings.Repeat("a", 32)
	for _, names := range [][]string{{"daemon", "daemon"}, {"bad\nname"}} {
		called := false
		e := s.WithLinuxProcessWatch(context.Background(), device, names, epoch, func() time.Time { return at }, func(linuxprocesswatch.Input, func(time.Time) error) error { called = true; return nil })
		if !errors.Is(e, enrollmentstate.ErrInvalid) || called {
			t.Fatal("invalid selection admitted", e)
		}
	}
	for _, mode := range []string{"rollback", "lease", "sample_stale"} {
		t.Run(mode, func(t *testing.T) {
			now := at
			if mode == "sample_stale" {
				now = at.Add(linuxprocesswatch.MaxAge - time.Second)
			}
			e := s.WithLinuxProcessWatch(context.Background(), device, []string{"daemon"}, epoch, func() time.Time { return now }, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
				switch mode {
				case "rollback":
					now = now.Add(-time.Second)
				case "lease":
					now = now.Add(6 * time.Second)
				case "sample_stale":
					now = now.Add(time.Second)
				}
				return guard(at)
			})
			if e == nil {
				t.Fatal("expired source lease accepted")
			}
		})
	}
}

func TestLinuxProcessWatchCorruptOriginalChunksNeverReachCallback(t *testing.T) {
	for _, mode := range []string{"missing", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
			promoteOverview(t, s, snap, cert, b, m, c, at)
			if e := s.transact(ctx, func(tx *transaction) error {
				if mode == "missing" {
					_, e := tx.conn.ExecContext(ctx, `DELETE FROM co_chunks WHERE device=? AND generation=? AND ordinal=0`, overviewDevice(snap.Approval.DeviceID, "processes"), b.GenerationID)
					return e
				}
				_, e := tx.conn.ExecContext(ctx, `UPDATE co_chunks SET body=CAST(body || ' ' AS BLOB) WHERE device=? AND generation=? AND ordinal=0`, overviewDevice(snap.Approval.DeviceID, "processes"), b.GenerationID)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			called := false
			e := s.WithLinuxProcessWatch(ctx, snap.Approval.DeviceID, []string{"daemon"}, strings.Repeat("a", 32), func() time.Time { return at }, func(linuxprocesswatch.Input, func(time.Time) error) error { called = true; return nil })
			if !errors.Is(e, ErrStorage) || called {
				t.Fatal("corrupt original source admitted", e)
			}
		})
	}
}
