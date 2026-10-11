package windowseventcache

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	record      windowseventrequest.Record
	cap         windowseventwire.Capability
	fail        bool
	accepted    int
	afterAccept func()
	afterStatus func()
	authority   time.Time
	orphans     int
}

func (f *fakeStore) CreateWindowsEventRequest(context.Context, string, uint64, string, string, []windowseventrequest.Selection, time.Time) (windowseventrequest.Description, error) {
	return f.record.Description, nil
}
func (f *fakeStore) CancelWindowsEventRequest(_ context.Context, _ string, id windowseventrequest.Identity, now time.Time) error {
	r, e := windowseventrequest.Cancel(f.record, id, now)
	if e == nil {
		f.record = r
	}
	return e
}
func (f *fakeStore) WindowsEventContentStatus(context.Context, string, time.Time) (enrollmentstore.WindowsEventStatus, error) {
	r := f.record
	if f.afterStatus != nil {
		f.afterStatus()
	}
	return enrollmentstore.WindowsEventStatus{DeviceID: r.Description.DeviceID, ExpectedFloor: "1", LocalStatus: "enabled", Request: &r, Capability: &f.cap, AuthorityUntil: f.authority}, nil
}
func (f *fakeStore) ReportWindowsEventCapability(_ context.Context, _, _ string, c windowseventwire.Capability, _ time.Time) (windowseventwire.Capability, error) {
	f.cap = c
	return c, nil
}
func (f *fakeStore) PeekWindowsEventRequest(context.Context, string, string, time.Time) (*windowseventrequest.Description, error) {
	d := f.record.Description
	return &d, nil
}
func (f *fakeStore) ClaimWindowsEventRequest(_ context.Context, _, _ string, c windowseventwire.Claim, now time.Time) (windowseventwire.Grant, error) {
	r, e := windowseventrequest.Claim(f.record, c.Identity, f.cap.Consent, f.local(), now)
	if e != nil {
		return windowseventwire.Grant{}, e
	}
	f.record = r
	return windowseventwire.GrantFor(r)
}
func (f *fakeStore) local() windowseventrequest.LocalContext {
	return windowseventrequest.LocalContext{SenderBinding: f.cap.Consent.SenderBinding, Profile: "tls", DeviceID: f.cap.DeviceID, CertificateHash: f.cap.CertificateHash}
}
func (f *fakeStore) AcceptWindowsEventResult(_ context.Context, _, _ string, v windowseventwire.Result, now time.Time) (windowseventrequest.Receipt, bool, error) {
	f.accepted++
	if f.fail {
		return windowseventrequest.Receipt{}, false, enrollmentstore.ErrStorage
	}
	if f.record.Receipt != nil {
		return *f.record.Receipt, false, nil
	}
	r, e := windowseventrequest.Accept(f.record, v.Claim.Identity, f.cap.Consent, f.local(), v.Report, now)
	if e != nil {
		return windowseventrequest.Receipt{}, false, e
	}
	f.record = r
	if f.afterAccept != nil {
		f.afterAccept()
	}
	return *r.Receipt, true, nil
}
func (f *fakeStore) ReportWindowsEventStatus(context.Context, string, string, windowseventwire.StatusInput, time.Time) error {
	return nil
}
func (f *fakeStore) MaintainWindowsEventContent(context.Context, time.Time, bool) error { return nil }
func (f *fakeStore) CancelUnownedWindowsEventRequests(_ context.Context, live map[string]windowseventrequest.Identity, now time.Time) error {
	if f.record.State == windowseventrequest.Pending || f.record.State == windowseventrequest.Claimed {
		if live[f.record.Description.DeviceID] != f.record.Description.Identity {
			f.orphans++
			return f.CancelWindowsEventRequest(context.Background(), f.record.Description.DeviceID, f.record.Description.Identity, now)
		}
	}
	return nil
}
func (f *fakeStore) MaintainWindowsEventAuthorities(ctx context.Context, live map[string]windowseventrequest.Identity, now time.Time) (map[string]enrollmentstore.WindowsEventStatus, error) {
	if err := f.CancelUnownedWindowsEventRequests(ctx, live, now); err != nil {
		return nil, err
	}
	status, err := f.WindowsEventContentStatus(ctx, f.record.Description.DeviceID, now)
	if err != nil {
		return nil, err
	}
	return map[string]enrollmentstore.WindowsEventStatus{status.DeviceID: status}, nil
}
func cacheFixture(t *testing.T) (*Cache, *fakeStore, Owner, windowseventwire.Result, *time.Time, context.CancelFunc) {
	t.Helper()
	now := time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)
	device := "agent_" + strings.Repeat("a", 32)
	cert := strings.Repeat("b", 64)
	consent := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("c", 64), GrantID: strings.Repeat("d", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	local := windowseventrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: "tls", DeviceID: device, CertificateHash: cert}
	cap, e := windowseventwire.CapabilityFor(consent, local, 1, now)
	if e != nil {
		t.Fatal(e)
	}
	headers := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("e", 32), GenerationID: "sample_" + strings.Repeat("f", 32), CollectedAt: now, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", Provider: "Synthetic", Timestamp: now, Level: 2, EventID: 1}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	record, e := windowseventrequest.New(device, cert, 1, consent.GrantID, headers, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, now)
	if e != nil {
		t.Fatal(e)
	}
	record, e = windowseventrequest.Claim(record, record.Description.Identity, consent, local, now)
	if e != nil {
		t.Fatal(e)
	}
	store := &fakeStore{record: record, cap: cap, authority: now.Add(time.Hour)}
	life, cancel := context.WithCancel(context.Background())
	owner := Owner{ID: "server-derived-session-id", ExpiresAt: now.Add(10 * time.Minute), Lifetime: life, Active: func() bool { return life.Err() == nil }}
	c := &Cache{&cacheState{store: store, now: func() time.Time { return now }, entries: map[string]*entry{device: {id: record.Description.Identity, owner: owner, expires: owner.ExpiresAt}}}}
	claim, _ := windowseventwire.ClaimFor(record.Description, cap.PolicyDigest)
	result := windowseventwire.Result{Claim: claim, Report: windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, CollectedAt: now, Quality: "observed", Complete: true, Events: []windowseventcontent.Result{{Event: record.Description.Query.Events[0], Message: "Synthetic <script>alert('untrusted')</script> text", Quality: "observed", Complete: true}}}}
	t.Cleanup(cancel)
	t.Cleanup(c.Close)
	return c, store, owner, result, &now, cancel
}
func TestDigestCommitBeforePublicationAndRetryNeverRehydrates(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	device, cert := result.Claim.DeviceID, result.Claim.CertificateHash
	s.fail = true
	if _, e := c.Accept(ctx, device, cert, result, *now); e == nil {
		t.Fatal("commit failure accepted")
	}
	if len(c.entries[device].raw) != 0 {
		t.Fatal("content published before commit")
	}
	s.fail = false
	receipt, e := c.Accept(ctx, device, cert, result, *now)
	if e != nil {
		t.Fatal(e)
	}
	page, e := c.Query(ctx, device, o, result.Claim.Identity, *now)
	if e != nil || page.Receipt != receipt || page.Report.Events[0].Event.RecordID != "18446744073709551615" {
		t.Fatal("browser identity or publication", e)
	}
	c.remove(device)
	retry, e := c.Accept(ctx, device, cert, result, *now)
	if e != nil || retry != receipt || len(c.entries) != 0 {
		t.Fatal("retry rehydrated lost cache", e)
	}
	_, status, e := c.Status(ctx, device, o, *now)
	if e != nil || status != "result_lost" {
		t.Fatal("lost receipt truth", e)
	}
	// An explicit administrator cancellation can close an orphaned receipt;
	// ownership is never reconstructed and no content is returned.
	if e = c.Cancel(ctx, device, o, result.Claim.Identity, *now); e != nil || s.record.State != windowseventrequest.Canceled {
		t.Fatal("orphan cancel failed", e)
	}
}
func TestSessionOwnershipCannotTransferAndLossStopsAccept(t *testing.T) {
	c, s, o, result, now, cancel := cacheFixture(t)
	ctx := context.Background()
	device, cert := result.Claim.DeviceID, result.Claim.CertificateHash
	if _, e := c.Accept(ctx, device, cert, result, *now); e != nil {
		t.Fatal(e)
	}
	other := o
	other.ID = "another-session"
	if _, e := c.Query(ctx, device, other, result.Claim.Identity, *now); !errors.Is(e, ErrUnavailable) {
		t.Fatal("session ownership transferred", e)
	}
	if e := c.Cancel(ctx, device, other, result.Claim.Identity, *now); !errors.Is(e, ErrSession) {
		t.Fatal("foreign live owner canceled", e)
	}
	cancel()
	if _, e := c.Query(ctx, device, o, result.Claim.Identity, *now); e == nil {
		t.Fatal("logout exposed content")
	}
	if len(c.entries) != 0 || s.record.State != windowseventrequest.Canceled {
		t.Fatal("logout did not invalidate")
	}
	c2, s2, _, r2, n2, cancel2 := cacheFixture(t)
	cancel2()
	if _, e := c2.Accept(ctx, r2.Claim.DeviceID, r2.Claim.CertificateHash, r2, *n2); e == nil || s2.accepted != 0 {
		t.Fatal("sessionless new acceptance")
	}
}
func TestSessionLossDuringDigestCommitDiscardsBytes(t *testing.T) {
	c, s, _, result, now, cancel := cacheFixture(t)
	s.afterAccept = cancel
	if _, e := c.Accept(context.Background(), result.Claim.DeviceID, result.Claim.CertificateHash, result, *now); e != nil {
		t.Fatal(e)
	}
	if len(c.entries) != 0 {
		t.Fatal("committed result survived session loss")
	}
}
func TestHeaderRetentionAndCertificateBoundDisclosure(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	if _, e := c.Accept(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result, *now); e != nil {
		t.Fatal(e)
	}
	s.authority = now.Add(time.Second)
	if _, e := c.Query(ctx, result.Claim.DeviceID, o, result.Claim.Identity, *now); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Second)
	if _, e := c.Query(ctx, result.Claim.DeviceID, o, result.Claim.Identity, *now); e == nil || len(c.entries) != 0 {
		t.Fatal("certificate cutoff exceeded")
	}
}
func TestFinalReplyChecksExactOwnerGrantAndSlowRead(t *testing.T) {
	c, s, _, result, now, cancel := cacheFixture(t)
	ctx := context.Background()
	if e := c.AuthorizeReply(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result.Claim.Identity, *now); e != nil {
		t.Fatal(e)
	}
	grant := s.cap.Consent.GrantID
	s.cap.Consent.GrantID = strings.Repeat("0", 32)
	if e := c.AuthorizeReply(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result.Claim.Identity, *now); e == nil {
		t.Fatal("replacement grant survived final check")
	}
	s.cap.Consent.GrantID = grant
	s.afterStatus = func() { *now = now.Add(20 * time.Minute) }
	if e := c.AuthorizeReply(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result.Claim.Identity, *now); e == nil {
		t.Fatal("slow read outlived owner")
	}
	cancel()
}
func TestOrphanMaintenanceAndCachedDigestCheck(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	c.remove(result.Claim.DeviceID)
	if e := c.Maintain(context.Background(), *now); e != nil || s.orphans != 1 || s.record.State != windowseventrequest.Canceled {
		t.Fatal("orphan maintenance", e)
	}
	c2, _, o2, r2, n2, _ := cacheFixture(t)
	if _, e := c2.Accept(context.Background(), r2.Claim.DeviceID, r2.Claim.CertificateHash, r2, *n2); e != nil {
		t.Fatal(e)
	}
	r2.Report.Events[0].Message = "changed"
	raw, _ := windowseventwire.EncodeResult(r2)
	c2.entries[r2.Claim.DeviceID].raw = raw
	if _, e := c2.Query(context.Background(), r2.Claim.DeviceID, o2, r2.Claim.Identity, *n2); e == nil {
		t.Fatal("cache content did not match committed digest")
	}
	_ = o
}

func TestMaintenanceResamplesAfterMutexAndRejectsRealRollback(t *testing.T) {
	c, s, o, result, now, _ := cacheFixture(t)
	ctx := context.Background()
	if _, e := c.Accept(ctx, result.Claim.DeviceID, result.Claim.CertificateHash, result, *now); e != nil {
		t.Fatal(e)
	}
	// Simulate the scheduler sampling time before waiting behind another call.
	earlier := *now
	c.mu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); done <- c.Maintain(ctx, earlier) }()
	<-started
	*now = now.Add(time.Second)
	c.mu.Unlock()
	if e := <-done; e != nil {
		t.Fatal("queued old timestamp treated as clock rollback", e)
	}
	if _, e := c.Query(ctx, result.Claim.DeviceID, o, result.Claim.Identity, *now); e != nil {
		t.Fatal("normal contention discarded content", e)
	}
	// A genuine trusted-clock step backwards is distinct and must fail closed.
	*now = earlier
	if e := c.Maintain(ctx, *now); !errors.Is(e, ErrClock) || len(c.entries) != 0 || s.record.Receipt == nil {
		t.Fatal("real clock rollback did not discard memory and preserve receipt", e)
	}
}

func TestStatusRechecksCapabilityAfterSlowStoreRead(t *testing.T) {
	c, s, o, r, now, _ := cacheFixture(t)
	ctx := context.Background()
	if _, e := c.Accept(ctx, r.Claim.DeviceID, r.Claim.CertificateHash, r, *now); e != nil {
		t.Fatal(e)
	}
	*now = s.cap.CollectedAt.Add(5*time.Minute - time.Nanosecond)
	s.afterStatus = func() { *now = s.cap.CollectedAt.Add(5 * time.Minute) }
	view, status, e := c.Status(ctx, r.Claim.DeviceID, o, *now)
	if e != nil || status == "available" || view.LocalStatus != "stale" || len(c.entries[r.Claim.DeviceID].raw) != 0 {
		t.Fatal("slow store read crossed original capability cutoff", e)
	}
}
func TestQueuedStatusAndQueryUseFreshClock(t *testing.T) {
	c, _, o, r, now, _ := cacheFixture(t)
	ctx := context.Background()
	if _, e := c.Accept(ctx, r.Claim.DeviceID, r.Claim.CertificateHash, r, *now); e != nil {
		t.Fatal(e)
	}
	earlier := *now
	*now = now.Add(time.Second)
	if _, status, e := c.Status(ctx, r.Claim.DeviceID, o, earlier); e != nil || status != "available" {
		t.Fatal("queued status discarded content", e)
	}
	*now = now.Add(time.Second)
	if _, e := c.Query(ctx, r.Claim.DeviceID, o, r.Claim.Identity, earlier); e != nil {
		t.Fatal("queued query discarded content", e)
	}
}

func TestCacheHandleCopiesShareStateAndRedactEveryFormat(t *testing.T) {
	c, _, _, r, now, _ := cacheFixture(t)
	if _, e := c.Accept(context.Background(), r.Claim.DeviceID, r.Claim.CertificateHash, r, *now); e != nil {
		t.Fatal(e)
	}
	copy := *c
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, v := range []any{c, *c, &copy, copy} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, "Synthetic") || strings.Contains(out, "alert") || strings.Contains(out, "raw:") {
				t.Fatal("cache formatting exposed content")
			}
		}
	}
	copy.Close()
	if len(c.entries) != 0 {
		t.Fatal("copied handle detached ownership state")
	}
}
