package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsusersoftware"
	"strings"
	"testing"
	"time"
)

type userSoftwareFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	consent windowsusersoftware.Consent
}

func newUserSoftwareFixture(t *testing.T, profile string) userSoftwareFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, profile)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsUserSoftware(context.Background()); e != nil {
		t.Fatal("initialize", e)
	}
	c := windowsusersoftware.Consent{SchemaVersion: windowsusersoftware.ConsentVersion, Scope: windowsusersoftware.Scope, SenderBinding: windowsusersoftware.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return userSoftwareFixture{f, s, path, snap, cert, at, c}
}
func (f userSoftwareFixture) apply(t *testing.T, m windowsusersoftware.Message, now time.Time) (windowsusersoftware.Receipt, error) {
	t.Helper()
	raw, e := windowsusersoftware.EncodeMessage(m)
	if e != nil {
		t.Fatal("encode", e)
	}
	return f.s.ApplyWindowsUserSoftware(WithWindowsUserSoftwareIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, now)
}
func (f userSoftwareFixture) scope() windowsusersoftware.Message {
	return windowsusersoftware.Message{SchemaVersion: windowsusersoftware.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}
}
func (f userSoftwareFixture) grant(t *testing.T) {
	t.Helper()
	if _, e := f.apply(t, f.scope(), f.at); e != nil {
		t.Fatal("scope", e)
	}
}
func (f userSoftwareFixture) messages(t *testing.T, seq uint64, n int, at time.Time) []windowsusersoftware.Message {
	t.Helper()
	rows := make([]windowsusersoftware.Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedSoftware%05d", i)
		version := fmt.Sprintf("%05d", i)
		publisher := fmt.Sprintf("Fiktive Firma %05d 東京", i)
		rows[i] = windowsusersoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), Source: "hkcu", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	m, e := windowsusersoftware.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsusersoftware.Capture{AccountContextID: strings.Repeat("d", 64), AccountLabel: "Selected account dddddddd", CaptureNonce: strings.Repeat("e", 64), HKCUStatus: "complete", MSIXStatus: "unsupported", StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f userSoftwareFixture) page(t *testing.T, q windowsusersoftware.Query, at time.Time) windowsusersoftware.Page {
	t.Helper()
	p, e := f.s.WindowsUserSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, at)
	if e != nil {
		t.Fatal("page", e)
	}
	return p
}
func userSoftwareQuery() windowsusersoftware.Query {
	return windowsusersoftware.Query{Sort: "name-asc", Limit: 100}
}
func TestWindowsUserSoftwarePartialAssemblyAccountSourceCursorIsolation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newUserSoftwareFixture(t, profile)
			defer func() { f.s.Close() }()
			f.grant(t)
			ms := f.messages(t, 1, 257, f.at)
			first, e := f.apply(t, ms[0], f.at)
			if e != nil {
				t.Fatal(e)
			}
			p := f.page(t, userSoftwareQuery(), f.at)
			if p.Complete != nil || len(p.Rows) != 0 {
				t.Fatal("incomplete generation prefix disclosed")
			}
			retry, e := f.apply(t, ms[0], f.at.Add(time.Second))
			if e != nil || retry != first {
				t.Fatal("retry changed original receipt", e)
			}
			for _, m := range ms[1:] {
				if _, e = f.apply(t, m, f.at.Add(time.Second)); e != nil {
					t.Fatal(e)
				}
			}
			p = f.page(t, userSoftwareQuery(), f.at.Add(time.Second))
			if p.Status != "ready" || p.MatchingCount != 257 || len(p.Rows) != 100 || p.NextCursor == "" || p.Complete.Manifest.Coverage != windowsusersoftware.PartialCoverage || p.AccountContextID != strings.Repeat("d", 64) {
				t.Fatal("wrong bounded selected-account page")
			}
			q := userSoftwareQuery()
			q.Cursor = p.NextCursor
			q.Source = "msix"
			if _, e = f.s.WindowsUserSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, f.at.Add(time.Second)); !errors.Is(e, windowsusersoftware.ErrConflict) {
				t.Fatal("source filter transplant", e)
			}
			q = userSoftwareQuery()
			q.AccountContextID = strings.Repeat("f", 64)
			if _, e = f.s.WindowsUserSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, f.at.Add(time.Second)); !errors.Is(e, windowsusersoftware.ErrConflict) {
				t.Fatal("account transplant", e)
			}
			q = userSoftwareQuery()
			q.Source = "msix"
			empty := f.page(t, q, f.at.Add(time.Second))
			if empty.MatchingCount != 0 || empty.Complete.Manifest.MSIXStatus != "unsupported" {
				t.Fatal("unavailable source labeled complete")
			}
			f.s.Close()
			f.s = f.f.open(t, f.path)
			q = userSoftwareQuery()
			q.Cursor = p.NextCursor
			next := f.page(t, q, f.at.Add(time.Second))
			if next.Offset != 100 || len(next.Rows) != 100 {
				t.Fatal("restart cursor")
			}
			// Another verified account replaces the current generation, never joins it.
			second := f.messages(t, 2, 1, f.at.Add(time.Minute))
			for i := range second {
				second[i].Manifest.AccountContextID = strings.Repeat("f", 64)
				second[i].Manifest.AccountLabel = "Selected account ffffffff"
				second[i].Manifest.CaptureNonce = strings.Repeat("1", 64)
				second[i].ManifestSHA256, _ = windowsusersoftware.ManifestDigest(*second[i].Manifest)
				if _, e = f.apply(t, second[i], f.at.Add(time.Minute)); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = f.s.WindowsUserSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, f.at.Add(time.Minute)); !errors.Is(e, windowsusersoftware.ErrConflict) {
				t.Fatal("old account cursor survived replacement", e)
			}
			if e = f.s.RecheckWindowsUserSoftwarePage(context.Background(), p, f.at.Add(time.Minute)); !errors.Is(e, windowsusersoftware.ErrConflict) {
				t.Fatal("prepared old-account disclosure survived replacement", e)
			}
		})
	}
}
func TestWindowsUserSoftwareFinalClockSessionExpiryAndUsedFence(t *testing.T) {
	f := newUserSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	ms := f.messages(t, 1, 1, f.at)
	for _, m := range ms {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	until := f.at.Add(time.Hour)
	active := true
	ctx := WithWindowsUserSoftwareSession(context.Background(), "session-a", until, func() bool { return active })
	p, e := f.s.WindowsUserSoftwarePage(ctx, f.snap.Approval.DeviceID, userSoftwareQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	active = false
	if e = f.s.RecheckWindowsUserSoftwarePage(ctx, p, f.at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("session revocation", e)
	}
	if e = f.s.RecheckWindowsUserSoftwarePage(context.Background(), p, f.at.Add(windowsusersoftware.Retention)); !errors.Is(e, windowsusersoftware.ErrConflict) && !errors.Is(e, enrollmentstate.ErrExpired) {
		t.Fatal("original expiry", e)
	}
	if _, e = f.s.db.Exec("DROP TABLE wus_rows"); e != nil {
		t.Fatal(e)
	}
	if e = f.s.InitializeWindowsUserSoftware(context.Background()); !errors.Is(e, ErrStorage) {
		t.Fatal("missing used state reinitialized", e)
	}
}
func TestWindowsUserSoftwareFailureKeepsExplicitAttemptAccount(t *testing.T) {
	f := newUserSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 1, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	at := f.at.Add(time.Minute)
	m := windowsusersoftware.Message{SchemaVersion: windowsusersoftware.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "deadline", AccountContextID: strings.Repeat("f", 64), AccountLabel: "Selected account ffffffff", CaptureNonce: strings.Repeat("2", 64)}
	if _, e := f.apply(t, m, at); e != nil {
		t.Fatal(e)
	}
	p := f.page(t, userSoftwareQuery(), at)
	if p.AccountContextID != strings.Repeat("d", 64) || p.LatestAttempt.AccountContextID != m.AccountContextID || p.Complete.Manifest.AccountContextID != p.AccountContextID {
		t.Fatal("failed other-account attempt relabeled retained rows")
	}
}

func TestWindowsUserSoftwareSharesReservationsAndAdmission(t *testing.T) {
	f := newUserSoftwareFixture(t, "tls")
	defer f.s.Close()
	ctx := context.Background()
	for _, initialize := range []func(context.Context) error{f.s.InitializeWindowsFullServices, f.s.InitializeWindowsFullSoftware, f.s.InitializeWindowsFullProcesses, f.s.InitializeWindowsNetworkContext} {
		if e := initialize(ctx); e != nil {
			t.Fatal(e)
		}
	}
	f.grant(t)
	for _, m := range f.messages(t, 1, 1024, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	e := f.s.transact(ctx, func(tx *transaction) error {
		var reserved int64
		if e := tx.conn.QueryRowContext(ctx, `SELECT sum(reserved_bytes) FROM wus_generations`).Scan(&reserved); e != nil {
			return e
		}
		for _, other := range []func(context.Context, *transaction) (int64, error){windowsFullServicesOtherBytes, windowsFullSoftwareOtherBytes, windowsFullProcessesOtherBytes, windowsNetworkContextOtherBytes} {
			n, e := other(ctx, tx)
			if e != nil {
				return e
			}
			if n < reserved {
				t.Fatal("selected-account reservation omitted from shared cap")
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < cap(f.s.inventoryCalls); i++ {
		f.s.inventoryCalls <- struct{}{}
	}
	_, e = f.s.WindowsUserSoftwarePage(ctx, f.snap.Approval.DeviceID, userSoftwareQuery(), f.at)
	for i := 0; i < cap(f.s.inventoryCalls); i++ {
		<-f.s.inventoryCalls
	}
	if !errors.Is(e, ErrInventoryBusy) {
		t.Fatal("separate unbounded admission", e)
	}
}

func TestWindowsUserSoftwareAttemptOriginalExpiryFinalDisclosure(t *testing.T) {
	at := time.Unix(testNow+10, 0).UTC()
	until := at.Add(48 * time.Hour)
	p := windowsusersoftware.Page{ServerNow: at, Status: "unavailable", AuthorityUntil: &until, LatestAttempt: &windowsusersoftware.Attempt{AttemptedAt: at, Sequence: 1, Status: "source_failed", Reason: "unavailable", AccountContextID: strings.Repeat("d", 64), AccountLabel: "Selected account dddddddd", CaptureNonce: strings.Repeat("e", 64)}}
	if e := ValidateWindowsUserSoftwarePageAt(p, at.Add(windowsusersoftware.Retention)); !errors.Is(e, windowsusersoftware.ErrConflict) {
		t.Fatal("attempt metadata lifetime refreshed", e)
	}
}
