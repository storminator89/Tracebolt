package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsnetworkcontext"
	"reflect"
	"testing"
	"time"
)

func TestNetworkContextBackendReviewPostCommitRevocationHidesPage(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	if _, e := f.apply(t, m, f.at); e != nil {
		t.Fatal(e)
	}
	calls := 0
	ctx := WithWindowsNetworkContextClock(context.Background(), func() time.Time {
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
	p, e := f.s.WindowsNetworkContextPage(ctx, f.snap.Approval.DeviceID, networkContextQuery(), f.at)
	if calls < 3 {
		t.Fatalf("clock hook count %d", calls)
	}
	if e == nil || !reflect.DeepEqual(p, windowsnetworkcontext.Page{}) {
		t.Fatalf("revoked identity disclosed page: error=%v status=%s rows=%d", e, p.Status, len(p.Rows))
	}
}

func TestNetworkContextBackendReviewPostCommitRevocationHidesReceipt(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	raw, _ := windowsnetworkcontext.EncodeMessage(m)
	calls := 0
	ctx := WithWindowsNetworkContextClock(context.Background(), func() time.Time {
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
	r, e := f.s.ApplyWindowsNetworkContext(WithWindowsNetworkContextIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
	if calls < 3 {
		t.Fatalf("clock hook count %d", calls)
	}
	if e == nil || r != (windowsnetworkcontext.Receipt{}) {
		t.Fatalf("revoked identity disclosed receipt: error=%v status=%s", e, r.Status)
	}
}

func TestNetworkContextBackendReviewMissingSearchIndexCannotProveAbsence(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	if _, e := f.apply(t, m, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.db.Exec(`UPDATE wnc_rows SET search=''`); e != nil {
		t.Fatal(e)
	}
	q := networkContextQuery()
	q.Search = "2001:db8::/128"
	p, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, q, f.at)
	if e == nil || !reflect.DeepEqual(p, windowsnetworkcontext.Page{}) {
		t.Fatalf("inconsistent normalized row returned false absence: error=%v status=%s count=%d rows=%d", e, p.Status, p.MatchingCount, len(p.Rows))
	}
}

func TestNetworkContextBackendReviewExpiredPendingHasUnavailableStatus(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	if _, e := f.apply(t, f.messages(t, 1, 129, f.at)[0], f.at); e != nil {
		t.Fatal(e)
	}
	p, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, networkContextQuery(), f.at.Add(15*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if p.Status != "unavailable" || p.LatestAttempt == nil || p.LatestAttempt.Status != "expired" {
		raw, _ := json.Marshal(p)
		t.Fatalf("expired pending mislabeled: %s", raw)
	}
}
