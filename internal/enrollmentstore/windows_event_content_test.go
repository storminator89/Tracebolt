package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type eventStoreFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	cap     windowseventwire.Capability
	headers windowseventhealth.Snapshot
}

func eventFixture(t *testing.T) eventStoreFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	if e := s.InitializeWindowsEventContent(ctx); e != nil {
		t.Fatal(e)
	}
	c := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	cap, e := windowseventwire.CapabilityFor(c, windowseventrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: snap.Approval.DeviceID, CertificateHash: cert.CertificateHash()}, 1, at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReportWindowsEventCapability(ctx, snap.Approval.DeviceID, cert.CertificateHash(), cap, at); e != nil {
		t.Fatal(e)
	}
	h := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("c", 32), GenerationID: id("sample", 1), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 14, Level: 2, Provider: "Synthetic fixture", Timestamp: at}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	eventFrame(t, s, snap, cert, 1, at, h)
	return eventStoreFixture{f, s, path, snap, cert, at, cap, h}
}
func eventFrame(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, seq uint64, at time.Time, h windowseventhealth.Snapshot) {
	t.Helper()
	var frame lanstore.Frame
	if json.Unmarshal(windowsStoreFrame(t, seq, at), &frame) != nil {
		t.Fatal("decode")
	}
	frame.SchemaVersion = lanstore.FrameWindowsEventsVersion
	frame.WindowsEvents = &h
	raw, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveObservation(context.Background(), snap.InvitationID, cert.CertificateHash(), raw, at); e != nil {
		t.Fatal(e)
	}
}
func (f eventStoreFixture) create(t *testing.T) windowseventrequest.Description {
	t.Helper()
	s, e := f.s.WindowsEventContentStatus(context.Background(), f.snap.Approval.DeviceID, f.at)
	if e != nil || s.Headers == nil {
		t.Fatal("status", e)
	}
	d, e := f.s.CreateWindowsEventRequest(context.Background(), f.snap.Approval.DeviceID, 0, s.Headers.GenerationID, s.Headers.SnapshotDigest, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, f.at)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func eventResult(t *testing.T, d windowseventrequest.Description, policy string, at time.Time) windowseventwire.Result {
	t.Helper()
	claim, e := windowseventwire.ClaimFor(d, policy)
	if e != nil {
		t.Fatal(e)
	}
	r := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: "observed", CollectedAt: at, Complete: true, Events: []windowseventcontent.Result{{Event: d.Query.Events[0], Message: "synthetic-private-event-message-never-durable", Quality: "observed", Complete: true}}}
	if e = windowseventcontent.ValidateReport(r, d.Query); e != nil {
		t.Fatal(e)
	}
	return windowseventwire.Result{Claim: claim, Report: r}
}
func TestWindowsEventAtomicClaimImmutableSelectionDigestRetry(t *testing.T) {
	f := eventFixture(t)
	d := f.create(t)
	ctx := context.Background()
	claim, _ := windowseventwire.ClaimFor(d, f.cap.PolicyDigest)
	// A later accepted metadata generation must not reinterpret this request.
	newer := f.headers
	newer.GenerationID = id("sample", 2)
	newer.CollectedAt = f.at.Add(time.Second)
	newer.Channels = append([]windowseventhealth.Channel(nil), f.headers.Channels...)
	newer.Channels[0].Rows = []windowseventhealth.Event{{RecordID: "2", EventID: 22, Level: 2, Provider: "Different fixture", Timestamp: newer.CollectedAt}}
	eventFrame(t, f.s, f.snap, f.cert, 2, newer.CollectedAt, newer)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.s.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), claim, newer.CollectedAt)
			if e == nil {
				wins.Add(1)
			} else if !errors.Is(e, windowseventrequest.ErrConsumed) {
				t.Errorf("claim outcome: %v", e)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("claim was not atomic")
	}
	result := eventResult(t, d, f.cap.PolicyDigest, newer.CollectedAt)
	receipt, first, e := f.s.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), result, newer.CollectedAt)
	if e != nil || !first {
		t.Fatal("accept", e)
	}
	retry, first, e := f.s.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), result, newer.CollectedAt.Add(time.Second))
	if e != nil || first || retry != receipt {
		t.Fatal("exact retry changed receipt", e)
	}
	result.Report.Events[0].Message = "different"
	if _, _, e = f.s.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), result, newer.CollectedAt.Add(time.Second)); !errors.Is(e, windowseventrequest.ErrConflict) {
		t.Fatal("changed result accepted", e)
	}
	// Canonical persisted metadata and every SQLite sidecar must exclude content.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, _ := os.ReadFile(f.path + suffix)
		if strings.Contains(string(raw), "synthetic-private-event-message") {
			t.Fatal("content persisted")
		}
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	if e = f.s.MaintainWindowsEventContent(ctx, newer.CollectedAt.Add(2*time.Second), true); e != nil {
		t.Fatal(e)
	}
	result = eventResult(t, d, f.cap.PolicyDigest, newer.CollectedAt)
	retry, first, e = f.s.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), result, newer.CollectedAt.Add(2*time.Second))
	if e != nil || first || retry != receipt {
		t.Fatal("restart retry receipt", e)
	}
}
func TestWindowsEventFloorClockGrantAndRestart(t *testing.T) {
	f := eventFixture(t)
	d := f.create(t)
	ctx := context.Background()
	if e := f.s.MaintainWindowsEventContent(ctx, f.at.Add(time.Second), true); e != nil {
		t.Fatal(e)
	}
	status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at.Add(time.Second))
	if e != nil || status.Request.State != windowseventrequest.Canceled || status.ExpectedFloor != "1" {
		t.Fatal("restart reset authority", e)
	}
	if _, e = f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("rollback accepted", e)
	}
	cap := f.cap
	cap.Sequence = 2
	cap.CollectedAt = f.at.Add(2 * time.Second)
	cap.Consent.GrantID = strings.Repeat("d", 32)
	cap.PolicyDigest, _ = windowseventwire.PolicyDigest(cap.Consent)
	if _, e = f.s.ReportWindowsEventCapability(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), cap, cap.CollectedAt); e != nil {
		t.Fatal(e)
	}
	claim, _ := windowseventwire.ClaimFor(d, f.cap.PolicyDigest)
	if _, e = f.s.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), claim, cap.CollectedAt); e == nil {
		t.Fatal("replaced grant reused")
	}
	if _, e = f.s.ReportWindowsEventCapability(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), f.cap, cap.CollectedAt); !errors.Is(e, windowseventrequest.ErrConflict) {
		t.Fatal("capability floor regressed", e)
	}
	if e = f.s.MaintainWindowsEventContent(ctx, f.at.Add(25*time.Hour), false); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	var floor, seq string
	if e = f.s.db.QueryRow(`SELECT floor,capability_sequence FROM enrollment_windows_event_authority`).Scan(&floor, &seq); e != nil || floor != "1" || seq != "2" {
		t.Fatal("purge reset floor", e)
	}
}
func TestWindowsEventMissingUsedSchemaNeverReinitialized(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(strconv.FormatBool(all), func(t *testing.T) {
			f := eventFixture(t)
			f.create(t)
			if all {
				for _, name := range []string{"enrollment_windows_event_requests", "enrollment_windows_event_authority", "enrollment_windows_event_meta"} {
					if _, e := f.s.db.Exec("DROP TABLE " + name); e != nil {
						t.Fatal(e)
					}
				}
			} else {
				if _, e := f.s.db.Exec(`DROP TABLE enrollment_windows_event_requests`); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.s.InitializeWindowsEventContent(context.Background()); !errors.Is(e, ErrStorage) {
				t.Fatal("used state recreated", e)
			}
			f.s.Close()
			if s, e := Open(f.path, f.f.config, f.f.issuerDER); e == nil {
				s.Close()
				t.Fatal("partial used database reopened")
			}
		})
	}
}
func TestWindowsEventCanonicalUint64Floors(t *testing.T) {
	f := eventFixture(t)
	ctx := context.Background()
	if _, e := f.s.db.Exec(`UPDATE enrollment_windows_event_authority SET floor=?`, strconv.FormatUint(math.MaxUint64-1, 10)); e != nil {
		t.Fatal(e)
	}
	status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at)
	if e != nil {
		t.Fatal(e)
	}
	d, e := f.s.CreateWindowsEventRequest(ctx, f.snap.Approval.DeviceID, math.MaxUint64-1, status.Headers.GenerationID, status.Headers.SnapshotDigest, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, f.at)
	if e != nil || d.Identity.Sequence != math.MaxUint64 {
		t.Fatal("SQLite integer truncation", e)
	}
	if e = f.s.CancelWindowsEventRequest(ctx, f.snap.Approval.DeviceID, d.Identity, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateWindowsEventRequest(ctx, f.snap.Approval.DeviceID, math.MaxUint64, status.Headers.GenerationID, status.Headers.SnapshotDigest, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, f.at); !errors.Is(e, windowseventrequest.ErrConflict) {
		t.Fatal("floor wrapped", e)
	}
}
func TestWindowsEventCommitFailureLeavesClaimed(t *testing.T) {
	f := eventFixture(t)
	d := f.create(t)
	ctx := context.Background()
	claim, _ := windowseventwire.ClaimFor(d, f.cap.PolicyDigest)
	if _, e := f.s.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), claim, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.db.Exec(`PRAGMA query_only=ON`); e != nil {
		t.Fatal(e)
	}
	r := eventResult(t, d, f.cap.PolicyDigest, f.at)
	if _, first, e := f.s.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), r, f.at); e == nil || first {
		t.Fatal("failed commit reported accepted")
	}
	if _, e := f.s.db.Exec(`PRAGMA query_only=OFF`); e != nil {
		t.Fatal(e)
	}
	status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at)
	if e != nil || status.Request.State != windowseventrequest.Claimed || status.Request.Receipt != nil {
		t.Fatal("failed acceptance mutated receipt", e)
	}
}
func TestWindowsEventFreshCapabilityNotLegacyHeaderGrant(t *testing.T) {
	f := eventFixture(t)
	ctx := context.Background()
	status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at.Add(5*time.Minute))
	if e != nil || status.Headers != nil || status.LocalStatus != "stale" {
		t.Fatal("stale original capability refreshed", e)
	}
	if _, e = f.s.ReportWindowsEventCapability(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), f.cap, f.at.Add(5*time.Minute)); e == nil {
		t.Fatal("exact retry refreshed capture age")
	}
}

func TestWindowsEventCapabilityClockRegressionAndMetadataPurge(t *testing.T) {
	f := eventFixture(t)
	d := f.create(t)
	ctx := context.Background()
	c := f.cap
	c.Sequence = 2
	c.CollectedAt = f.at.Add(-time.Second)
	if _, e := f.s.ReportWindowsEventCapability(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), c, f.at); !errors.Is(e, windowseventrequest.ErrConflict) {
		t.Fatal("larger sequence accepted older capture", e)
	}
	if e := f.s.CancelUnownedWindowsEventRequests(ctx, map[string]windowseventrequest.Identity{f.snap.Approval.DeviceID: d.Identity}, f.at); e != nil {
		t.Fatal(e)
	}
	status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at)
	if e != nil || status.Request.State != windowseventrequest.Pending {
		t.Fatal("maintenance canceled owned work", e)
	}
	if e = f.s.CancelUnownedWindowsEventRequests(ctx, map[string]windowseventrequest.Identity{}, f.at); e != nil {
		t.Fatal(e)
	}
	status, e = f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at)
	if e != nil || status.Request.State != windowseventrequest.Canceled {
		t.Fatal("unowned work remained capturable", e)
	}
	if e = f.s.MaintainWindowsEventContent(ctx, f.at.Add(24*time.Hour), false); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.s.db.QueryRow(`SELECT count(*) FROM enrollment_windows_event_requests`).Scan(&n); e != nil || n != 0 {
		t.Fatal("old selected headers retained", e)
	}
	var floor string
	if e = f.s.db.QueryRow(`SELECT floor FROM enrollment_windows_event_authority`).Scan(&floor); e != nil || floor != "1" {
		t.Fatal("metadata purge reset floor", e)
	}
}
func TestWindowsEventTerminalEndpointStatusAndGrantDisable(t *testing.T) {
	for _, reason := range []string{"denied", "reader_unavailable", "result_lost"} {
		t.Run(reason, func(t *testing.T) {
			f := eventFixture(t)
			d := f.create(t)
			ctx := context.Background()
			claim, _ := windowseventwire.ClaimFor(d, f.cap.PolicyDigest)
			if _, e := f.s.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), claim, f.at); e != nil {
				t.Fatal(e)
			}
			if e := f.s.ReportWindowsEventStatus(ctx, f.snap.Approval.DeviceID, f.cert.CertificateHash(), windowseventwire.StatusInput{Claim: claim, LocalStatus: reason}, f.at); e != nil {
				t.Fatal(e)
			}
			status, e := f.s.WindowsEventContentStatus(ctx, f.snap.Approval.DeviceID, f.at)
			if e != nil || status.Request.State != windowseventrequest.Canceled || status.EndpointStatus != reason {
				t.Fatal("endpoint terminal truth lost", e)
			}
		})
	}
	f := eventFixture(t)
	d := f.create(t)
	c := f.cap
	c.Sequence = 2
	c.Consent.Enabled = false
	c.PolicyDigest, _ = windowseventwire.PolicyDigest(c.Consent)
	if _, e := f.s.ReportWindowsEventCapability(context.Background(), f.snap.Approval.DeviceID, f.cert.CertificateHash(), c, f.at); e != nil {
		t.Fatal(e)
	}
	status, e := f.s.WindowsEventContentStatus(context.Background(), f.snap.Approval.DeviceID, f.at)
	if e != nil || status.LocalStatus != "disabled" || status.Headers != nil || status.Request.State != windowseventrequest.Canceled || status.Request.Description.Identity != d.Identity {
		t.Fatal("disable invalidation", e)
	}
}

func TestWindowsEventMissingUsedAuthorityRowsNeverReset(t *testing.T) {
	for _, kind := range []string{"request", "authority-and-request"} {
		t.Run(kind, func(t *testing.T) {
			f := eventFixture(t)
			f.create(t)
			if _, e := f.s.db.Exec(`DELETE FROM enrollment_windows_event_requests`); e != nil {
				t.Fatal(e)
			}
			if kind == "authority-and-request" {
				if _, e := f.s.db.Exec(`DELETE FROM enrollment_windows_event_authority`); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.s.InitializeWindowsEventContent(context.Background()); !errors.Is(e, ErrStorage) {
				t.Fatal("used rows reinitialized", e)
			}
			f.s.Close()
			if s, e := Open(f.path, f.f.config, f.f.issuerDER); e == nil {
				s.Close()
				t.Fatal("used-row loss reopened as fresh")
			}
		})
	}
}

// Exercise the real normalized authority path at its maximum identity count.
// Cache tests separately assert one batch call and no per-device reloads; the
// external production-deadline fixture measures end-to-end retained content.
func TestWindowsEventBatchMaintenanceAtCapacity(t *testing.T) {
	base := eventFixture(t)
	ctx := context.Background()
	live := make(map[string]windowseventrequest.Identity)
	receipts := make(map[string]windowseventrequest.Receipt)
	for k := 1; k <= 25; k++ {
		f := base
		if k > 1 {
			v := base.f
			v.requestOffset = k * 100
			v.secret = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(k + 32)}, 32))
			v.challenge.InvitationID = id("invite", k)
			v.challenge.ClaimID = id("claim", k)
			create := v.createCommand()
			create.Platform = "windows"
			snap, err := base.s.CreateInvitation(ctx, create)
			if err != nil {
				t.Fatal(err)
			}
			snap, err = base.s.Claim(ctx, enrollmentstate.ClaimCommand{Control: v.control(snap, 2), ClaimID: v.challenge.ClaimID}, v.claim(t))
			if err != nil {
				t.Fatal(err)
			}
			snap, err = base.s.Approve(ctx, enrollmentstate.ApproveCommand{Control: v.control(snap, 3), DeviceID: id("agent", k), KeyFingerprint: snap.Claim.KeyFingerprint})
			if err != nil {
				t.Fatal(err)
			}
			snap, err = base.s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: v.control(snap, 4), IntentID: id("intent", k), SerialHex: fmt.Sprintf("%032x", k), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 86400})
			if err != nil {
				t.Fatal(err)
			}
			intent, err := base.s.SigningIntent(ctx, snap.InvitationID, snap.UpdatedAt)
			if err != nil {
				t.Fatal(err)
			}
			cert := v.issue(t, intent)
			snap, err = base.s.CommitIssued(ctx, v.control(snap, 5), cert)
			if err != nil {
				t.Fatal(err)
			}
			control := v.control(snap, 6)
			snap, err = base.s.Activate(ctx, control, v.activation(t, cert, control))
			if err != nil {
				t.Fatal(err)
			}
			cap, err := windowseventwire.CapabilityFor(base.cap.Consent, windowseventrequest.LocalContext{SenderBinding: base.cap.Consent.SenderBinding, Profile: "tls", DeviceID: snap.Approval.DeviceID, CertificateHash: cert.CertificateHash()}, 1, base.at)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = base.s.ReportWindowsEventCapability(ctx, snap.Approval.DeviceID, cert.CertificateHash(), cap, base.at); err != nil {
				t.Fatal(err)
			}
			eventFrame(t, base.s, snap, cert, 1, base.at, base.headers)
			f = eventStoreFixture{f: v, s: base.s, path: base.path, snap: snap, cert: cert, at: base.at, cap: cap, headers: base.headers}
		}
		d := f.create(t)
		live[d.DeviceID] = d.Identity
		if k%3 != 1 {
			result := eventResult(t, d, f.cap.PolicyDigest, f.at)
			if _, err := f.s.ClaimWindowsEventRequest(ctx, d.DeviceID, d.CertificateHash, result.Claim, f.at); err != nil {
				t.Fatal(err)
			}
			if k%3 == 0 {
				receipt, first, err := f.s.AcceptWindowsEventResult(ctx, d.DeviceID, d.CertificateHash, result, f.at)
				if err != nil || !first {
					t.Fatal("accept", err)
				}
				receipts[d.DeviceID] = receipt
			}
		}
	}
	statuses, err := base.s.MaintainWindowsEventAuthorities(ctx, live, base.at)
	if err != nil || len(statuses) != 25 {
		t.Fatal("capacity batch", len(statuses), err)
	}
	for device, status := range statuses {
		if status.Request == nil || status.Request.Description.Identity != live[device] || status.LocalStatus != "enabled" || status.ExpectedFloor != "1" || status.Headers != nil {
			t.Fatal("batch authority mismatch")
		}
	}
	// Cancel only exact unowned pending/claimed work. Missing ownership does not
	// reconstruct content or erase an accepted digest receipt.
	delete(live, id("agent", 1))
	delete(live, id("agent", 2))
	delete(live, id("agent", 3))
	statuses, err = base.s.MaintainWindowsEventAuthorities(ctx, live, base.at)
	if err != nil {
		t.Fatal(err)
	}
	for k := 1; k <= 3; k++ {
		status := statuses[id("agent", k)]
		if k < 3 && status.Request.State != windowseventrequest.Canceled {
			t.Fatal("orphan not canceled")
		}
		if k == 3 && (status.Request.State != windowseventrequest.Accepted || status.Request.Receipt == nil || *status.Request.Receipt != receipts[id("agent", k)]) {
			t.Fatal("accepted receipt changed")
		}
	}
	statuses, err = base.s.MaintainWindowsEventAuthorities(ctx, nil, base.at)
	if err != nil {
		t.Fatal(err)
	}
	for device, status := range statuses {
		if receipt, accepted := receipts[device]; accepted {
			if status.Request.State != windowseventrequest.Accepted || status.Request.Receipt == nil || *status.Request.Receipt != receipt {
				t.Fatal("nil live snapshot changed accepted receipt")
			}
		} else if status.Request.State != windowseventrequest.Canceled {
			t.Fatal("nil live snapshot retained unowned work")
		}
	}
	statuses, err = base.s.MaintainWindowsEventAuthorities(ctx, live, base.at.Add(24*time.Hour))
	if err != nil || len(statuses) != 25 {
		t.Fatal("batch purge", err)
	}
	for _, status := range statuses {
		if status.Request != nil || status.Capability != nil || status.ExpectedFloor != "1" {
			t.Fatal("purge lost floor or retained metadata")
		}
	}
	if _, err = base.s.MaintainWindowsEventAuthorities(ctx, live, base.at); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("batch allowed clock rollback", err)
	}
	// The batched path must retain the same independent used-row checks.
	if _, err = base.s.db.Exec(`DELETE FROM enrollment_windows_event_authority WHERE device=?`, id("agent", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err = base.s.MaintainWindowsEventAuthorities(ctx, live, base.at.Add(24*time.Hour)); !errors.Is(err, ErrStorage) {
		t.Fatal("batch accepted missing used authority", err)
	}
}
