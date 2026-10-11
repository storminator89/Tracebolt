package windowshistorycache

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	record      windowshistoryrequest.Record
	cap         windowshistorywire.Capability
	fail        bool
	accepted    int
	afterAccept func()
	afterStatus func()
	authority   time.Time
	orphans     int
}

func (f *fakeStore) CreateWindowsHistorySearch(context.Context, string, uint64, windowseventhistory.Search, time.Time) (windowshistoryrequest.Description, error) {
	return f.record.Description, nil
}
func (f *fakeStore) CreateWindowsHistoryMessages(_ context.Context, device string, floor uint64, receipt windowshistoryrequest.Receipt, report windowseventhistory.Report, selected []windowshistoryrequest.Selection, now time.Time) (windowshistoryrequest.Description, error) {
	if f.record.Receipt == nil || *f.record.Receipt != receipt {
		return windowshistoryrequest.Description{}, windowshistoryrequest.ErrConflict
	}
	r, e := windowshistoryrequest.NewMessages(device, f.cap.CertificateHash, floor+1, f.cap.Consent.GrantID, f.record, report, selected, now)
	if e == nil {
		f.record = r
	}
	return r.Description, e
}
func (f *fakeStore) AuthorizeWindowsHistoryReply(context.Context, string, string, windowshistoryrequest.Identity, time.Time) error {
	return nil
}
func (f *fakeStore) CancelWindowsHistoryRequest(_ context.Context, _ string, id windowshistoryrequest.Identity, now time.Time) error {
	r, e := windowshistoryrequest.Cancel(f.record, id, now)
	if e == nil {
		f.record = r
	}
	return e
}
func (f *fakeStore) WindowsHistoryStatus(context.Context, string, time.Time) (enrollmentstore.WindowsHistoryStatus, error) {
	r := f.record
	if f.afterStatus != nil {
		f.afterStatus()
	}
	return enrollmentstore.WindowsHistoryStatus{DeviceID: r.Description.DeviceID, ExpectedFloor: "1", LocalStatus: "enabled", Request: &r, Capability: &f.cap, AuthorityUntil: f.authority}, nil
}
func (f *fakeStore) ReportWindowsHistoryCapability(_ context.Context, _, _ string, c windowshistorywire.Capability, _ time.Time) (windowshistorywire.Capability, error) {
	f.cap = c
	return c, nil
}
func (f *fakeStore) PeekWindowsHistoryRequest(context.Context, string, string, time.Time) (*windowshistoryrequest.Description, error) {
	d := f.record.Description
	return &d, nil
}
func (f *fakeStore) ClaimWindowsHistoryRequest(_ context.Context, _, _ string, c windowshistorywire.Claim, now time.Time) (windowshistorywire.Grant, error) {
	r, e := windowshistoryrequest.Claim(f.record, c.Identity, f.cap.Consent, f.local(), now)
	if e != nil {
		return windowshistorywire.Grant{}, e
	}
	f.record = r
	return windowshistorywire.GrantFor(r)
}
func (f *fakeStore) local() windowshistoryrequest.LocalContext {
	return windowshistoryrequest.LocalContext{SenderBinding: f.cap.Consent.SenderBinding, Profile: "tls", DeviceID: f.cap.DeviceID, CertificateHash: f.cap.CertificateHash}
}
func (f *fakeStore) AcceptWindowsHistoryResult(_ context.Context, _, _ string, v windowshistorywire.Result, now time.Time) (windowshistoryrequest.Receipt, bool, error) {
	f.accepted++
	if f.fail {
		return windowshistoryrequest.Receipt{}, false, enrollmentstore.ErrStorage
	}
	if f.record.Receipt != nil {
		return *f.record.Receipt, false, nil
	}
	r, e := windowshistoryrequest.Accept(f.record, v.Claim.Identity, f.cap.Consent, f.local(), v.Report, now)
	if e != nil {
		return windowshistoryrequest.Receipt{}, false, e
	}
	f.record = r
	if f.afterAccept != nil {
		f.afterAccept()
	}
	return *r.Receipt, true, nil
}
func (f *fakeStore) ReportWindowsHistoryStatus(context.Context, string, string, windowshistorywire.StatusInput, time.Time) error {
	return nil
}
func (f *fakeStore) MaintainWindowsHistory(context.Context, time.Time, bool) error { return nil }
func (f *fakeStore) CancelUnownedWindowsHistoryRequests(_ context.Context, live map[string]windowshistoryrequest.Identity, now time.Time) error {
	if f.record.State == windowshistoryrequest.Pending || f.record.State == windowshistoryrequest.Claimed {
		if live[f.record.Description.DeviceID] != f.record.Description.Identity {
			f.orphans++
			return f.CancelWindowsHistoryRequest(context.Background(), f.record.Description.DeviceID, f.record.Description.Identity, now)
		}
	}
	return nil
}
func (f *fakeStore) MaintainWindowsHistoryAuthorities(ctx context.Context, live map[string]windowshistoryrequest.Identity, now time.Time) (map[string]enrollmentstore.WindowsHistoryStatus, error) {
	if err := f.CancelUnownedWindowsHistoryRequests(ctx, live, now); err != nil {
		return nil, err
	}
	status, err := f.WindowsHistoryStatus(ctx, f.record.Description.DeviceID, now)
	if err != nil {
		return nil, err
	}
	return map[string]enrollmentstore.WindowsHistoryStatus{status.DeviceID: status}, nil
}
func cacheFixture(t *testing.T) (*Cache, *fakeStore, Owner, windowshistorywire.Result, *time.Time, context.CancelFunc) {
	t.Helper()
	now := time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)
	device := "agent_" + strings.Repeat("a", 32)
	cert := strings.Repeat("b", 64)
	consent := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("c", 64), GrantID: strings.Repeat("d", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	local := windowshistoryrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: "tls", DeviceID: device, CertificateHash: cert}
	cap, e := windowshistorywire.CapabilityFor(consent, local, 1, now)
	if e != nil {
		t.Fatal(e)
	}
	search := windowseventhistory.Search{Channel: "Application", Start: now.Add(-time.Hour), End: now}
	record, e := windowshistoryrequest.NewSearch(device, cert, 1, consent.GrantID, search, now)
	if e != nil {
		t.Fatal(e)
	}
	record, e = windowshistoryrequest.Claim(record, record.Description.Identity, consent, local, now)
	if e != nil {
		t.Fatal(e)
	}
	store := &fakeStore{record: record, cap: cap, authority: now.Add(time.Hour)}
	life, cancel := context.WithCancel(context.Background())
	owner := Owner{ID: "server-derived-session-id", ExpiresAt: now.Add(10 * time.Minute), Lifetime: life, Active: func() bool { return life.Err() == nil }}
	c := &Cache{&cacheState{store: store, now: func() time.Time { return now }, entries: map[string]*entry{device: {id: record.Description.Identity, owner: owner, expires: owner.ExpiresAt}}}}
	claim, _ := windowshistorywire.ClaimFor(record.Description, cap.PolicyDigest)
	result := windowshistorywire.Result{Claim: claim, Report: windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, CollectedAt: now, Quality: "observed", Complete: true, Search: windowseventhistory.CloneSearch(&search), Events: []windowseventhistory.Result{{Event: windowseventhistory.Event{Channel: "Application", RecordID: 18446744073709551615, EventID: 42, Level: 2, Provider: "Synthetic", Timestamp: now.Add(-time.Minute)}, Quality: "observed", Complete: true}}}}
	t.Cleanup(cancel)
	t.Cleanup(c.Close)
	return c, store, owner, result, &now, cancel
}

func TestHistoryCacheReceiptBeforePublishAndLostSearchCannotRefillOrSelect(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	device, cert := result.Claim.DeviceID, result.Claim.CertificateHash
	s.fail = true
	if _, e := c.Accept(ctx, device, cert, result, *now); e == nil {
		t.Fatal("failed durable commit published")
	}
	if len(c.entries[device].raw) != 0 {
		t.Fatal("bytes before receipt")
	}
	s.fail = false
	receipt, e := c.Accept(ctx, device, cert, result, *now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Query(ctx, device, o, result.Claim.Identity, *now); e != nil {
		t.Fatal(e)
	}
	clear(c.entries[device].raw)
	c.entries[device].raw = nil
	if got, e := c.Accept(ctx, device, cert, result, *now); e != nil || got != receipt {
		t.Fatal("retry receipt", e)
	}
	if len(c.entries[device].raw) != 0 {
		t.Fatal("retry refilled lost search")
	}
	if _, e = c.CreateMessages(ctx, device, o, 1, receipt, []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, *now); e == nil {
		t.Fatal("lost search authorized followup")
	}
}
func TestHistoryCacheSameSessionFollowupOriginalExpiryAndReplacement(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	device, cert := result.Claim.DeviceID, result.Claim.CertificateHash
	receipt, e := c.Accept(ctx, device, cert, result, *now)
	if e != nil {
		t.Fatal(e)
	}
	other := o
	other.ID = "other-session"
	selected := []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}
	if _, e = c.CreateMessages(ctx, device, other, 1, receipt, selected, *now); e == nil {
		t.Fatal("other session selected private search")
	}
	d, e := c.CreateMessages(ctx, device, o, 1, receipt, selected, *now)
	if e != nil {
		t.Fatal(e)
	}
	if d.ExpiresAt != receipt.ExpiresAt || d.SearchReceipt == nil || *d.SearchReceipt != receipt || len(c.entries[device].raw) != 0 || s.record.State != windowshistoryrequest.Pending {
		t.Fatal("followup lifetime/cache")
	}
	if e = c.Cancel(ctx, device, o, receipt.Identity, *now); e == nil {
		t.Fatal("predecessor cancellation altered replacement")
	}
	if c.entries[device] == nil || c.entries[device].id != d.Identity {
		t.Fatal("stale cancellation lost replacement")
	}
}
func TestHistoryCacheWaitedSessionExpiryDropsAcceptedBytes(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	s.afterAccept = func() { *now = o.ExpiresAt }
	if _, e := c.Accept(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result, *now); e != nil {
		t.Fatal(e)
	}
	if e := c.entries[result.Claim.DeviceID]; e != nil && len(e.raw) > 0 {
		t.Fatal("late session received bytes")
	}
}
