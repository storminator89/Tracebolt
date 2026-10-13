package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
)

type macInventoryFixture struct {
	f      fixture
	s      *Store
	path   string
	snap   enrollmentstate.Snapshot
	cert   enrollmentcrypto.VerifiedCertificate
	at     time.Time
	enable macosinventorywire.Control
}

func newMacInventoryFixture(t *testing.T) macInventoryFixture {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = macosinventorywire.Profile
	f.config.Platform = "darwin"
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	f.challenge.CollectionProfile = macosinventorywire.Profile
	path := filepath.Join(t.TempDir(), "private", "mac-inventory.db")
	s := f.open(t, path)
	ctx := context.Background()
	create := f.createCommand()
	create.Platform = "darwin"
	v, e := s.CreateInvitation(ctx, create)
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(v, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(v, 3), DeviceID: id("agent", 1), KeyFingerprint: v.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(v, 4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 7*86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := s.SigningIntent(ctx, v.InvitationID, v.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := f.issue(t, intent)
	v, e = s.CommitIssued(ctx, f.control(v, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	ctrl := f.control(v, 6)
	v, e = s.Activate(ctx, ctrl, f.activation(t, cert, ctrl))
	if e != nil {
		t.Fatal(e)
	}
	at := time.Unix(testNow+10, 0).UTC()
	enable := macosinventorywire.Control{SchemaVersion: macosinventorywire.ControlVersion, Binding: macOSInventoryBinding(v, v.Binding.Origin), GrantID: strings.Repeat("a", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: at}
	return macInventoryFixture{f, s, path, v, cert, at, enable}
}
func (f macInventoryFixture) ctx() context.Context {
	return WithMacOSInventoryIngressOrigin(context.Background(), f.snap.Binding.Origin)
}
func (f macInventoryFixture) session() context.Context {
	return WithMacOSInventorySession(context.Background(), "fixture-session", f.at.Add(6*24*time.Hour), func() bool { return true })
}
func (f macInventoryFixture) grant(t *testing.T) []byte {
	t.Helper()
	raw, _ := macosinventorywire.EncodeControl(f.enable)
	receipt, e := f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at)
	if e != nil {
		t.Fatal("enable", e)
	}
	return receipt
}
func (f macInventoryFixture) report(t *testing.T, seq uint64, at time.Time, n int) []byte {
	t.Helper()
	generation, e := macosinventorywire.GenerationID(f.enable.Binding, f.enable.GrantID, 1, seq)
	if e != nil {
		t.Fatal(e)
	}
	status := func(source string) macosinventory.Status {
		return macosinventory.Status{Source: source, Quality: "observed"}
	}
	processes := make([]macosinventory.Process, n)
	for i := range processes {
		processes[i] = macosinventory.Process{PID: uint32(i + 1), ParentPID: 0, AccountingName: "Fixture", NameQuality: "observed"}
	}
	snapshot := macosinventory.Snapshot{SchemaVersion: macosinventory.SchemaVersion, Scope: macosinventory.Scope, GrantID: f.enable.GrantID, GenerationID: generation, CollectedAt: at, Hardware: macosinventory.Hardware{Status: status(macosinventory.HardwareSource), ModelIdentifier: "Mac14,2", PhysicalCPUs: 8, LogicalCPUs: 8, MemoryCapacityBytes: 1 << 34}, Receipts: macosinventory.Receipts{Status: status(macosinventory.ReceiptSource), Identifiers: []string{"org.example.private-fixture"}}, Processes: macosinventory.Processes{Status: status(macosinventory.ProcessSource), Rows: processes}, Network: macosinventory.Network{IPv4: macosinventory.Interfaces{Status: status(macosinventory.IPv4Source), Rows: []macosinventory.Interface{{Name: "en0", MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{{IP: "192.0.2.7", PrefixBits: 24}}}}}, IPv6: macosinventory.Interfaces{Status: status(macosinventory.IPv6Source), Rows: []macosinventory.Interface{{Name: "en0", MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{}}}}}}
	report, e := macosinventorywire.BuildReport(f.enable, seq, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := macosinventorywire.EncodeReport(report)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (f macInventoryFixture) apply(raw []byte, at time.Time) ([]byte, error) {
	return f.s.ApplyMacOSInventoryReport(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), raw, at)
}
func (f macInventoryFixture) summary(t *testing.T, at time.Time) MacOSInventoryPage {
	t.Helper()
	p, e := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, MacOSInventoryQuery{Section: "summary", Limit: 100}, at)
	if e != nil {
		t.Fatal("summary", e)
	}
	return p
}
func TestMacOSInventoryAtomicLifecycleRetryDisable(t *testing.T) {
	f := newMacInventoryFixture(t)
	p := f.summary(t, f.at)
	if p.Status != "not-enabled" || len(p.Processes) != 0 {
		t.Fatal("default-off")
	}
	raw := f.report(t, 1, f.at, 230)
	if _, e := f.apply(raw, f.at); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("before enable", e)
	}
	ack := f.grant(t)
	enableRaw, _ := macosinventorywire.EncodeControl(f.enable)
	retry, e := f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), enableRaw, f.at.Add(time.Second))
	if e != nil || !bytes.Equal(ack, retry) {
		t.Fatal("enable retry", e)
	}
	receipt, e := f.apply(raw, f.at.Add(time.Second))
	if e != nil {
		t.Fatal("report", e)
	}
	retry, e = f.apply(raw, f.at.Add(2*time.Second))
	if e != nil || !bytes.Equal(receipt, retry) {
		t.Fatal("report retry", e)
	}
	p = f.summary(t, f.at.Add(2*time.Second))
	if p.Status != "fresh" || p.SourceQuality != "full" || p.Hardware != nil || len(p.Processes) > 0 || len(p.ReceiptIDs) > 0 {
		t.Fatal("summary privacy")
	}
	q := MacOSInventoryQuery{Section: "processes", GenerationID: p.GenerationID, Limit: 100}
	page, e := f.s.MacOSInventoryPage(f.session(), p.DeviceID, q, f.at.Add(2*time.Second))
	if e != nil || len(page.Processes) != 100 || page.Total != 230 || page.NextOffset == nil || *page.NextOffset != 100 {
		t.Fatal("page", e)
	}
	data, _ := json.Marshal(page)
	if len(data) > MacOSInventoryMaxPageBytes || bytes.Contains(data, []byte("org.example.private")) {
		t.Fatal("page budget/section leak")
	}
	altered := f.report(t, 1, f.at, 229)
	if _, e = f.apply(altered, f.at.Add(3*time.Second)); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("same sequence conflict", e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	retry, e = f.apply(raw, f.at.Add(4*time.Second))
	if e != nil || !bytes.Equal(receipt, retry) {
		t.Fatal("reopen exact receipt", e)
	}
	second := f.report(t, 3, f.at.Add(time.Minute), 5)
	if _, e = f.apply(second, f.at.Add(time.Minute)); e != nil {
		t.Fatal("skipped reserved floors", e)
	}
	if e = f.s.RecheckMacOSInventoryPage(f.session(), page, f.at.Add(time.Minute)); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("old page survived replacement", e)
	}
	if _, e = f.apply(raw, f.at.Add(time.Minute)); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("rollback", e)
	}
	disabled, _ := macosinventorywire.Disable(f.enable, 5, f.at.Add(time.Minute))
	disableRaw, _ := macosinventorywire.EncodeControl(disabled)
	disableReceipt, e := f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), disableRaw, f.at.Add(time.Minute))
	if e != nil {
		t.Fatal("disable", e)
	}
	retry, e = f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), disableRaw, f.at.Add(2*time.Minute))
	if e != nil || !bytes.Equal(disableReceipt, retry) {
		t.Fatal("disable exact receipt", e)
	}
	for _, body := range [][]byte{raw, second, f.report(t, 6, f.at.Add(2*time.Minute), 1)} {
		if _, e = f.apply(body, f.at.Add(2*time.Minute)); !errors.Is(e, macosinventorywire.ErrDisabled) {
			t.Fatal("disabled admitted report", e)
		}
	}
	if _, e = f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), enableRaw, f.at.Add(2*time.Minute)); !errors.Is(e, macosinventorywire.ErrDisabled) {
		t.Fatal("reenable", e)
	}
	p = f.summary(t, f.at.Add(2*time.Minute))
	if p.Status != "disabled" || len(p.Processes) > 0 {
		t.Fatal("disabled view")
	}
}
func TestMacOSInventoryPrivateAdmissionExpiryAndMaintenance(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	if _, e := f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.MacOSInventoryPage(context.Background(), f.snap.Approval.DeviceID, MacOSInventoryQuery{Section: "summary", Limit: 100}, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("missing session", e)
	}
	p := f.summary(t, f.at)
	if !p.AuthorityUntil.Equal(f.at.Add(24 * time.Hour)) {
		t.Fatal("original expiry", p.AuthorityUntil)
	}
	if e := f.s.RecheckMacOSInventoryPage(f.session(), p, f.at.Add(24*time.Hour)); e == nil {
		t.Fatal("expired private page")
	}
	if _, e := f.apply(raw, f.at.Add(24*time.Hour)); !errors.Is(e, macosinventorywire.ErrExpired) {
		t.Fatal("expired report", e)
	}
	if e := f.s.MaintainMacOSInventory(context.Background(), f.at.Add(24*time.Hour)); e != nil {
		t.Fatal("maintenance", e)
	}
	var body []byte
	if e := f.s.db.QueryRow(`SELECT body FROM enrollment_macos_inventory`).Scan(&body); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(body, []byte("org.example.private-fixture")) || bytes.Contains(body, []byte("192.0.2.7")) || bytes.Contains(body, []byte("accountingName")) {
		t.Fatal("expired rows retained")
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	p = f.summary(t, f.at.Add(24*time.Hour))
	if p.Status != "expired" || p.GenerationID == "" || p.CollectedAt == nil || !p.CollectedAt.Equal(f.at) {
		t.Fatal("expired tombstone lost")
	}
	if _, e := f.apply(raw, f.at.Add(23*time.Hour)); e == nil {
		t.Fatal("clock rollback resurrected")
	}
}
func TestMacOSInventoryRejectsMalformedAndForeignAuthority(t *testing.T) {
	f := newMacInventoryFixture(t)
	enable, _ := macosinventorywire.EncodeControl(f.enable)
	for _, raw := range [][]byte{append([]byte(" "), enable...), append(bytes.Clone(enable), '\n'), bytes.Replace(enable, []byte(`"grantRevision":1`), []byte(`"grantRevision":1,"grantRevision":1`), 1), bytes.Repeat([]byte("x"), macosinventorywire.MaxControlBytes+1)} {
		if _, e := f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	if _, e := f.s.ApplyMacOSInventoryReport(WithAuthenticatedCertificate(f.ctx(), strings.Repeat("f", 64)), f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("actual transport hash ignored", e)
	}
	if _, e := f.s.ApplyMacOSInventoryReport(WithMacOSInventoryIngressOrigin(context.Background(), "https://other.example"), f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("origin rebound", e)
	}
	_, basic, _, _, _ := activeFixture(t)
	if _, e := basic.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), enable, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("basic promoted", e)
	}
	_, windows, _, _, _ := activeWindowsStore(t, "tls")
	if _, e := windows.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), enable, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("Windows promoted", e)
	}
	if _, e := f.apply(raw, time.Unix(f.snap.Intent.NotAfter, 0).UTC()); !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal("expired leaf", e)
	}
}
func TestMacOSInventoryLostUsedStateBlocksReopen(t *testing.T) {
	for _, kind := range []string{"record", "table", "clock"} {
		t.Run(kind, func(t *testing.T) {
			f := newMacInventoryFixture(t)
			f.grant(t)
			query := map[string]string{"record": `DELETE FROM enrollment_macos_inventory`, "table": `DROP TABLE enrollment_macos_inventory`, "clock": `DELETE FROM enrollment_macos_inventory_meta`}[kind]
			if _, e := f.s.db.Exec(query); e != nil {
				t.Fatal(e)
			}
			f.s.Close()
			if reopened, e := OpenExisting(f.path, f.f.config, f.f.issuerDER); e == nil {
				reopened.Close()
				t.Fatal("missing used state repaired")
			}
		})
	}
}
func TestMacOSInventoryFinalClockSessionAndRollback(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	calls := 0
	ctx := WithMacOSInventoryClock(f.ctx(), func() time.Time {
		calls++
		if calls == 1 {
			return f.at
		}
		return time.Unix(f.snap.Intent.NotAfter, 0).UTC()
	})
	if _, e := f.s.ApplyMacOSInventoryReport(ctx, f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal("final expiry", e)
	}
	p := f.summary(t, f.at)
	if p.Status != "unavailable" {
		t.Fatal("rolled back report committed")
	}
	if _, e := f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	liveCalls := 0
	session := WithMacOSInventorySession(context.Background(), "s", f.at.Add(time.Hour), func() bool { liveCalls++; return liveCalls < 2 })
	if p, e := f.s.MacOSInventoryPage(session, f.snap.Approval.DeviceID, MacOSInventoryQuery{Section: "summary", Limit: 100}, f.at); e == nil || p.DeviceID != "" {
		t.Fatal("session ended before commit exposed", e)
	}
	if e := f.s.MaintainMacOSInventory(context.Background(), f.at.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.apply(raw, f.at); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("cross request clock rollback", e)
	}
}
func TestMacOSInventoryDisableSerializesWithOtherStore(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	other, e := OpenExisting(f.path, f.f.config, f.f.issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	disabled, _ := macosinventorywire.Disable(f.enable, 4, f.at.Add(time.Minute))
	raw, _ := macosinventorywire.EncodeControl(disabled)
	if _, e := other.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := f.apply(f.report(t, uint64(i+1), f.at.Add(time.Duration(i+1)*time.Minute), 1), f.at.Add(5*time.Minute))
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if !errors.Is(e, macosinventorywire.ErrDisabled) && !errors.Is(e, ErrInventoryBusy) {
			t.Fatal("disable raced report", e)
		}
	}
}
func TestMacOSInventoryRevocationAndDeviceSummaryPrivacy(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	if _, e := f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	views, e := f.s.DeviceViews(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(views)
	if bytes.Contains(encoded, []byte("org.example.private")) || bytes.Contains(encoded, []byte("192.0.2.7")) || bytes.Contains(encoded, []byte("accountingName")) {
		t.Fatal("private rows in summary")
	}
	p := f.summary(t, f.at)
	control := f.f.control(f.snap, 50)
	control.Now = f.at.Add(time.Second).Unix()
	if _, e = f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.apply(raw, f.at.Add(time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked report", e)
	}
	if e = f.s.RecheckMacOSInventoryPage(f.session(), p, f.at.Add(time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked private page", e)
	}
}

func TestMacOSInventoryWholeRowBytePagesAndSessionPin(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	r, e := macosinventorywire.DecodeReport(raw)
	if e != nil {
		t.Fatal(e)
	}
	r.Snapshot.Network.IPv6.Rows = nil
	for i := 0; i < 128; i++ {
		row := macosinventory.Interface{Name: fmt.Sprintf("en%03d", i), MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{}}
		for j := 0; j < 16; j++ {
			row.Addresses = append(row.Addresses, macosinventory.Address{IP: fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", j), PrefixBits: 64})
		}
		r.Snapshot.Network.IPv6.Rows = append(r.Snapshot.Network.IPv6.Rows, row)
	}
	r, e = macosinventorywire.BuildReport(f.enable, 1, r.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = macosinventorywire.EncodeReport(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	q := MacOSInventoryQuery{Section: "ipv6", GenerationID: r.GenerationID, Limit: 100}
	seen := 0
	for {
		p, e := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, q, f.at)
		if e != nil {
			t.Fatal(e)
		}
		encoded, _ := json.Marshal(p)
		if len(encoded) > MacOSInventoryMaxPageBytes || len(p.Interfaces) == 0 || p.Total != 128 {
			t.Fatal("invalid bounded page")
		}
		for _, row := range p.Interfaces {
			if len(row.Addresses) != 16 {
				t.Fatal("truncated source row")
			}
		}
		seen += len(p.Interfaces)
		wrong := WithMacOSInventorySession(context.Background(), "other-session", f.at.Add(time.Hour), func() bool { return true })
		if e = f.s.RecheckMacOSInventoryPage(wrong, p, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal("page changed owner", e)
		}
		if p.NextOffset == nil {
			break
		}
		if *p.NextOffset != seen || len(p.Interfaces) >= 100 {
			t.Fatal("wrong byte boundary")
		}
		q.Offset = *p.NextOffset
	}
	if seen != 128 {
		t.Fatal("lost rows", seen)
	}
}
func TestMacOSInventoryEnableAcknowledgementPrecedesCapture(t *testing.T) {
	f := newMacInventoryFixture(t)
	enable, _ := macosinventorywire.EncodeControl(f.enable)
	if _, e := f.s.ApplyMacOSInventoryControl(f.ctx(), f.snap.InvitationID, f.cert.CertificateHash(), enable, f.at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.apply(f.report(t, 1, f.at, 1), f.at.Add(time.Second)); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("capture preceded original acknowledgement", e)
	}
	if _, e := f.apply(f.report(t, 2, f.at.Add(time.Second), 1), f.at.Add(time.Second)); e != nil {
		t.Fatal("valid post-ack", e)
	}
	if _, e := f.apply(f.report(t, 3, f.at.Add(60*time.Second), 1), f.at.Add(60*time.Second)); !errors.Is(e, macosinventorywire.ErrConflict) {
		t.Fatal("capture paced faster than minute", e)
	}
}
func TestMacOSInventoryTransactionCancellationRollsBackFloorAndReceipt(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	ctx, cancel := context.WithCancel(f.ctx())
	calls := 0
	ctx = WithMacOSInventoryClock(ctx, func() time.Time {
		calls++
		if calls == 2 {
			cancel()
		}
		return f.at
	})
	if _, e := f.s.ApplyMacOSInventoryReport(ctx, f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel", e)
	}
	if p := f.summary(t, f.at); p.Status != "unavailable" {
		t.Fatal("canceled transaction retained report")
	}
	if _, e := f.apply(raw, f.at); e != nil {
		t.Fatal("canceled transaction consumed durable floor", e)
	}
}

func TestMacOSInventoryRecheckFinalSessionExpiryAndHighWater(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	if _, e := f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	p := f.summary(t, f.at)
	calls := 0
	ctx := WithMacOSInventoryClock(f.session(), func() time.Time {
		calls++
		if calls == 1 {
			return f.at
		}
		return f.at.Add(24 * time.Hour)
	})
	if e := f.s.RecheckMacOSInventoryPage(ctx, p, f.at); e == nil {
		t.Fatal("final original expiry ignored")
	}
	calls = 0
	ctx = WithMacOSInventoryClock(f.ctx(), func() time.Time {
		calls++
		if calls == 1 {
			return f.at
		}
		return f.at.Add(time.Second)
	})
	if e := f.s.RecheckMacOSInventoryReport(ctx, f.snap.InvitationID, f.cert.CertificateHash(), raw, f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.apply(raw, f.at); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("committed final watermark forgotten", e)
	}
}

func TestMacOSInventoryFractionalAuthorityBudgetAtBoundary(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.at = f.at.Add(123456789 * time.Nanosecond)
	f.enable.ChangedAt = f.at
	f.grant(t)
	r, e := macosinventorywire.DecodeReport(f.report(t, 1, f.at, 1))
	if e != nil {
		t.Fatal(e)
	}
	r.Snapshot.Network.IPv6.Rows = nil
	for i := 0; i < 128; i++ {
		row := macosinventory.Interface{Name: fmt.Sprintf("en%03d", i), MTU: 1500, Up: true, Running: true, Addresses: []macosinventory.Address{}}
		for j := 0; j < 16; j++ {
			row.Addresses = append(row.Addresses, macosinventory.Address{IP: fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", j), PrefixBits: 64})
		}
		r.Snapshot.Network.IPv6.Rows = append(r.Snapshot.Network.IPv6.Rows, row)
	}
	// Build the exact typed envelope to place a legal whole-row boundary in the
	// final fractional timestamp overhead. Both names and addresses stay valid.
	expiry := f.at.Add(24 * time.Hour)
	sources := macOSInventorySourceStatuses(r)
	template := MacOSInventoryPage{SchemaVersion: "tracebolt.macos-read-inventory-page.v1", DeviceID: f.snap.Approval.DeviceID, Section: "ipv6", Status: "fresh", ServerNow: f.at, AuthorityUntil: expiry, GenerationID: r.GenerationID, SourceQuality: r.SourceQuality, CollectedAt: &f.at, ExpiresAt: &expiry, Sources: &sources, ReceiptIDs: []string{}, Processes: []macosinventory.Process{}, Interfaces: []macosinventory.Interface{}, Total: 128}
	rows := r.Snapshot.Network.IPv6.Rows
	n := 0
	for i := 1; i <= 100; i++ {
		template.Interfaces = rows[:i]
		template.NextOffset = &i
		encoded, _ := json.Marshal(template)
		if len(encoded) > MacOSInventoryMaxPageBytes {
			break
		}
		n = i
	}
	template.Interfaces = rows[:n]
	template.NextOffset = &n
	encoded, _ := json.Marshal(template)
	need := MacOSInventoryMaxPageBytes - len(encoded) + 1
	// Replace selected 35-character address forms by 39-character canonical forms
	// to add up to four bytes each, then extend sorted interface labels for exactness.
	for i := 0; i < n && need >= 4; i++ {
		for j := 0; j < 16 && need >= 4; j++ {
			rows[i].Addresses[j].IP = fmt.Sprintf("2001:db80:ffff:ffff:ffff:ffff:ffff:2%03x", j)
			need -= 4
		}
	}
	for i := 0; i < n && need > 0; i++ {
		add := need
		if add > 10 {
			add = 10
		}
		rows[i].Name += strings.Repeat("x", add)
		need -= add
	}
	if need != 0 {
		t.Fatal("fixture cannot reach boundary")
	}
	// Canonical address order is now different after replacement, so sort it.
	for i := range rows {
		sort.Slice(rows[i].Addresses, func(a, b int) bool { return rows[i].Addresses[a].IP < rows[i].Addresses[b].IP })
	}
	template.Interfaces = rows[:n]
	encoded, _ = json.Marshal(template)
	if len(encoded) != MacOSInventoryMaxPageBytes+1 {
		t.Fatal("fixture boundary", len(encoded))
	}
	r.Snapshot.Network.IPv6.Rows = rows
	r, e = macosinventorywire.BuildReport(f.enable, 1, r.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := macosinventorywire.EncodeReport(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.apply(raw, f.at); e != nil {
		t.Fatal(e)
	}
	p, e := f.s.MacOSInventoryPage(f.session(), f.snap.Approval.DeviceID, MacOSInventoryQuery{Section: "ipv6", GenerationID: r.GenerationID, Limit: 100}, f.at)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ = json.Marshal(p)
	if len(encoded) > MacOSInventoryMaxPageBytes || len(p.Interfaces) != n-1 || p.NextOffset == nil || *p.NextOffset != n-1 {
		t.Fatal("fractional authority broke whole-row budget", len(encoded), len(p.Interfaces), n)
	}
}
