package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullprocesses"
	"reflect"
	"testing"
	"time"
)

func TestProcessesBackendReviewPostCommitRevocationHidesPage(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	if _, e := f.apply(t, m, f.at); e != nil {
		t.Fatal(e)
	}
	calls := 0
	ctx := WithWindowsFullProcessesClock(context.Background(), func() time.Time {
		calls++
		if calls == 3 {
			ctl := f.f.control(f.snap, 20)
			ctl.Now = f.at.Add(time.Second).Unix()
			if _, e := f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); e != nil {
				t.Fatal("revoke", e)
			}
		}
		return f.at.Add(time.Second)
	})
	p, e := f.s.WindowsFullProcessesPage(ctx, f.snap.Approval.DeviceID, processesQuery(), f.at)
	if calls < 3 {
		t.Fatalf("clock hook count %d", calls)
	}
	if e == nil || !reflect.DeepEqual(p, windowsfullprocesses.Page{}) {
		t.Fatalf("revoked identity disclosed page: error=%v status=%s rows=%d", e, p.Status, len(p.Rows))
	}
}

func TestProcessesBackendReviewPostCommitRevocationHidesReceipt(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	raw, _ := windowsfullprocesses.EncodeMessage(m)
	calls := 0
	ctx := WithWindowsFullProcessesClock(context.Background(), func() time.Time {
		calls++
		if calls == 3 {
			ctl := f.f.control(f.snap, 20)
			ctl.Now = f.at.Add(time.Second).Unix()
			if _, e := f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); e != nil {
				t.Fatal("revoke", e)
			}
		}
		return f.at.Add(time.Second)
	})
	r, e := f.s.ApplyWindowsFullProcesses(WithWindowsFullProcessesIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
	if calls < 3 {
		t.Fatalf("clock hook count %d", calls)
	}
	if e == nil || r != (windowsfullprocesses.Receipt{}) {
		t.Fatalf("revoked identity disclosed receipt: error=%v status=%s", e, r.Status)
	}
}

func TestProcessesBackendReviewMissingSearchIndexCannotProveAbsence(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	if _, e := f.apply(t, m, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.db.Exec(`UPDATE wfp_rows SET search=''`); e != nil {
		t.Fatal(e)
	}
	q := processesQuery()
	q.Search = "InventedProcess00000"
	p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e == nil || !reflect.DeepEqual(p, windowsfullprocesses.Page{}) {
		t.Fatalf("inconsistent normalized row returned false absence: error=%v status=%s count=%d rows=%d", e, p.Status, p.MatchingCount, len(p.Rows))
	}
}

func TestProcessesBackendReviewExpiredPendingHasUnavailableStatus(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	if _, e := f.apply(t, f.messages(t, 1, 129, f.at)[0], f.at); e != nil {
		t.Fatal(e)
	}
	p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at.Add(15*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if p.Status != "unavailable" || p.LatestAttempt == nil || p.LatestAttempt.Status != "expired" {
		raw, _ := json.Marshal(p)
		t.Fatalf("expired pending mislabeled: %s", raw)
	}
}
