package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"os"
	"strings"
	"testing"
	"time"
)

type historyStoreFixture struct {
	eventStoreFixture
	cap    windowshistorywire.Capability
	search windowseventhistory.Search
}

func historyFixture(t *testing.T) historyStoreFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsHistory(context.Background()); e != nil {
		t.Fatal(e)
	}
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	cap, e := windowshistorywire.CapabilityFor(c, windowshistoryrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: snap.Approval.DeviceID, CertificateHash: cert.CertificateHash()}, 1, at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReportWindowsHistoryCapability(context.Background(), snap.Approval.DeviceID, cert.CertificateHash(), cap, at); e != nil {
		t.Fatal(e)
	}
	return historyStoreFixture{eventStoreFixture: eventStoreFixture{f: f, s: s, path: path, snap: snap, cert: cert, at: at}, cap: cap, search: windowseventhistory.Search{Channel: "Application", Start: at.Add(-time.Hour), End: at}}
}
func (f historyStoreFixture) result(t *testing.T, empty bool) (windowshistoryrequest.Description, windowshistorywire.Result, windowshistoryrequest.Receipt) {
	t.Helper()
	ctx := context.Background()
	device, cert := f.snap.Approval.DeviceID, f.cert.CertificateHash()
	d, e := f.s.CreateWindowsHistorySearch(ctx, device, 0, f.search, f.at)
	if e != nil {
		t.Fatal(e)
	}
	claim, e := windowshistorywire.ClaimFor(d, f.cap.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ClaimWindowsHistoryRequest(ctx, device, cert, claim, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ClaimWindowsHistoryRequest(ctx, device, cert, claim, f.at); !errors.Is(e, windowshistoryrequest.ErrConsumed) {
		t.Fatal("second claim", e)
	}
	rows := []windowseventhistory.Result{}
	if !empty {
		rows = append(rows, windowseventhistory.Result{Event: windowseventhistory.Event{Channel: "Application", RecordID: 18446744073709551615, EventID: 42, Level: 2, Provider: "Synthetic history fixture", Timestamp: f.at.Add(-time.Minute)}, Quality: "observed", Complete: true})
	}
	result := windowshistorywire.Result{Claim: claim, Report: windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: "observed", CollectedAt: f.at, Complete: true, Events: rows, Search: windowseventhistory.CloneSearch(&f.search)}}
	receipt, first, e := f.s.AcceptWindowsHistoryResult(ctx, device, cert, result, f.at)
	if e != nil || !first {
		t.Fatal("accept", e)
	}
	retry, first, e := f.s.AcceptWindowsHistoryResult(ctx, device, cert, result, f.at)
	if e != nil || first || retry != receipt {
		t.Fatal("retry", e)
	}
	return d, result, receipt
}
func TestWindowsHistorySearchMessagesReceiptExpiryAndNoDurableText(t *testing.T) {
	f := historyFixture(t)
	d, result, receipt := f.result(t, false)
	ctx := context.Background()
	device, cert := f.snap.Approval.DeviceID, f.cert.CertificateHash()
	selected := []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}
	changed := receipt
	changed.ResultDigest = "sha256:" + strings.Repeat("f", 64)
	if _, e := f.s.CreateWindowsHistoryMessages(ctx, device, 1, changed, result.Report, selected, f.at); e == nil {
		t.Fatal("changed receipt authorized")
	}
	messages, e := f.s.CreateWindowsHistoryMessages(ctx, device, 1, receipt, result.Report, selected, f.at.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if messages.CreatedAt != d.CreatedAt || messages.ExpiresAt != d.ExpiresAt || messages.SearchReceipt == nil || *messages.SearchReceipt != receipt {
		t.Fatal("followup refreshed authority")
	}
	claim, _ := windowshistorywire.ClaimFor(messages, f.cap.PolicyDigest)
	if _, e = f.s.ClaimWindowsHistoryRequest(ctx, device, cert, claim, f.at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	text := "synthetic-history-message-never-durable"
	content := windowshistorywire.Result{Claim: claim, Report: windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: "observed", CollectedAt: f.at.Add(time.Second), Complete: true, Events: []windowseventhistory.Result{{Event: messages.Query.Events[0], Message: text, Quality: "observed", Complete: true}}}}
	if _, first, e := f.s.AcceptWindowsHistoryResult(ctx, device, cert, content, f.at.Add(time.Second)); e != nil || !first {
		t.Fatal(e)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, _ := os.ReadFile(f.path + suffix)
		if strings.Contains(string(raw), text) {
			t.Fatal("message persisted")
		}
	}
	if _, e = f.s.CreateWindowsHistoryMessages(ctx, device, 2, receipt, result.Report, selected, f.at.Add(2*time.Second)); e == nil {
		t.Fatal("search receipt reused")
	}
	if _, _, e = f.s.AcceptWindowsHistoryResult(ctx, device, cert, content, d.ExpiresAt); e == nil {
		t.Fatal("exact expiry accepted")
	}
}
func TestWindowsHistoryEmptyIsAcceptedButHasNoMessages(t *testing.T) {
	f := historyFixture(t)
	_, r, receipt := f.result(t, true)
	if _, e := f.s.CreateWindowsHistoryMessages(context.Background(), f.snap.Approval.DeviceID, 1, receipt, r.Report, []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "1"}}, f.at); e == nil {
		t.Fatal("invented row accepted")
	}
}
func TestWindowsHistoryFinalLiveExpiryAndSessionGuardRollback(t *testing.T) {
	for _, kind := range []string{"expiry", "session", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := historyFixture(t)
			ctx := context.Background()
			d, e := f.s.CreateWindowsHistorySearch(ctx, f.snap.Approval.DeviceID, 0, f.search, f.at)
			if e != nil {
				t.Fatal(e)
			}
			claim, _ := windowshistorywire.ClaimFor(d, f.cap.PolicyDigest)
			calls := 0
			active := true
			live := WithWindowsHistoryClock(ctx, func() time.Time {
				calls++
				if calls >= 2 {
					if kind == "expiry" {
						return d.ExpiresAt
					}
					if kind == "session" {
						active = false
					}
					if kind == "rollback" {
						return f.at.Add(-time.Second)
					}
				}
				return f.at
			})
			live = WithWindowsHistorySession(live, f.at.Add(time.Hour), func() bool { return active })
			if _, e = f.s.ClaimWindowsHistoryRequest(live, f.snap.Approval.DeviceID, f.cert.CertificateHash(), claim, f.at); e == nil {
				t.Fatal("late boundary accepted")
			}
			status, e := f.s.WindowsHistoryStatus(ctx, f.snap.Approval.DeviceID, f.at)
			if e != nil || status.Request == nil || status.Request.State != windowshistoryrequest.Pending {
				t.Fatal("failed transaction consumed request", e)
			}
		})
	}
}
func TestWindowsHistoryOldContentConsentAndMissingUsedStateFailClosed(t *testing.T) {
	f := historyFixture(t)
	old := f.cap
	old.Consent.SchemaVersion = "tracebolt.windows-event-content-consent.v1"
	old.Consent.Scope = "windows-selected-application-system-event-content-v1"
	if _, e := f.s.ReportWindowsHistoryCapability(context.Background(), f.snap.Approval.DeviceID, f.cert.CertificateHash(), old, f.at); e == nil {
		t.Fatal("old scope promoted")
	}
	if e := f.s.transact(context.Background(), func(tx *transaction) error {
		_, e := tx.conn.ExecContext(context.Background(), "DELETE FROM enrollment_windows_history_authority")
		return e
	}); !errors.Is(e, ErrStorage) {
		t.Fatal("missing used authority accepted", e)
	}
	if _, e := f.s.WindowsHistoryStatus(context.Background(), f.snap.Approval.DeviceID, f.at.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("rollback accepted", e)
	}
}

func TestWindowsHistoryFinalBatchClockCannotLowerFloor(t *testing.T) {
	f := historyFixture(t)
	calls := 0
	ctx := WithWindowsHistoryClock(context.Background(), func() time.Time {
		calls++
		if calls == 2 {
			return f.at.Add(2 * time.Second)
		}
		if calls >= 3 {
			return f.at.Add(time.Second)
		}
		return f.at
	})
	err := f.s.windowsHistoryTransaction(ctx, f.at, func(tx *transaction, at time.Time) error {
		for range 2 {
			if _, err := f.s.windowsHistoryIdentity(tx, f.snap.Approval.DeviceID, "", at); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("batch lowered its live floor", err)
	}
	if _, err = f.s.WindowsHistoryStatus(context.Background(), f.snap.Approval.DeviceID, f.at); err != nil {
		t.Fatal("failed batch changed floor", err)
	}
}
