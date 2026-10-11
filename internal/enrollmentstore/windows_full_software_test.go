package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fullSoftwareFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	consent windowsfullsoftware.Consent
}

func newFullSoftwareFixture(t *testing.T, profile string) fullSoftwareFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, profile)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsFullSoftware(context.Background()); e != nil {
		t.Fatal("initialize", e)
	}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: windowsfullsoftware.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return fullSoftwareFixture{f, s, path, snap, cert, at, c}
}
func (f fullSoftwareFixture) apply(t *testing.T, m windowsfullsoftware.Message, now time.Time) (windowsfullsoftware.Receipt, error) {
	t.Helper()
	raw, e := windowsfullsoftware.EncodeMessage(m)
	if e != nil {
		t.Fatal("encode", e)
	}
	return f.s.ApplyWindowsFullSoftware(WithWindowsFullSoftwareIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, now)
}
func (f fullSoftwareFixture) scope() windowsfullsoftware.Message {
	return windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}
}
func (f fullSoftwareFixture) grant(t *testing.T) {
	t.Helper()
	if _, e := f.apply(t, f.scope(), f.at); e != nil {
		t.Fatal("scope", e)
	}
}
func (f fullSoftwareFixture) messages(t *testing.T, seq uint64, n int, at time.Time) []windowsfullsoftware.Message {
	t.Helper()
	rows := make([]windowsfullsoftware.Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedSoftware%05d", i)
		version := fmt.Sprintf("%05d", i)
		publisher := fmt.Sprintf("Fiktive Firma %05d 東京", i)
		rows[i] = windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), RegistryView: "64", Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	m, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f fullSoftwareFixture) page(t *testing.T, q windowsfullsoftware.Query, at time.Time) windowsfullsoftware.Page {
	t.Helper()
	p, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, at)
	if e != nil {
		t.Fatal("page", e)
	}
	return p
}
func softwareQuery() windowsfullsoftware.Query {
	return windowsfullsoftware.Query{Sort: "name-asc", Limit: 100}
}
func TestWindowsFullSoftwareLargeGenerationRetryRestartPagingAndFailure(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFullSoftwareFixture(t, profile)
			defer func() { f.s.Close() }()
			ctx := context.Background()
			p := f.page(t, softwareQuery(), f.at)
			if p.Status != "not_configured" || p.AuthorityUntil != nil || p.Complete != nil {
				t.Fatal("ungranted is not empty complete")
			}
			f.grant(t)
			messages := f.messages(t, 1, 2051, f.at)
			first, e := f.apply(t, messages[0], f.at)
			if e != nil {
				t.Fatal(e)
			}
			p = f.page(t, softwareQuery(), f.at)
			if p.Status != "awaiting" || p.Complete != nil || p.LatestAttempt == nil || p.LatestAttempt.Status != "pending" {
				t.Fatal("prefix exposed")
			}
			retry, e := f.apply(t, messages[0], f.at)
			if e != nil || retry != first {
				t.Fatal("retry", e)
			}
			bad := messages[0]
			bad.Rows = append([]windowsfullsoftware.Row{}, bad.Rows...)
			conflictName := "Aconflicting"
			bad.Rows[0].Name = &conflictName
			if _, e = f.apply(t, bad, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
				t.Fatal("conflicting retry", e)
			}
			f.s.Close()
			f.s = f.f.open(t, f.path)
			retry, e = f.apply(t, messages[0], f.at)
			if e != nil || retry != first {
				t.Fatal("restart receipt", e)
			}
			for _, m := range messages[1:] {
				if _, e = f.apply(t, m, f.at); e != nil {
					t.Fatal("append", m.Index, e)
				}
			}
			last, e := f.apply(t, messages[len(messages)-1], f.at.Add(time.Second))
			if e != nil || last.Status != "complete" || !last.ReceivedAt.Equal(f.at) {
				t.Fatal("final retry changed age", e)
			}
			q := softwareQuery()
			seen := []string{}
			for {
				p = f.page(t, q, f.at.Add(time.Second))
				if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 2051 || p.MatchingCount != 2051 {
					t.Fatal("wrong complete", p.Status)
				}
				for _, r := range p.Rows {
					seen = append(seen, *r.Name)
				}
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
			}
			if len(seen) != 2051 || seen[128] != "InventedSoftware00128" || seen[2049] != "InventedSoftware02049" {
				t.Fatal("full pages omitted later rows")
			}
			q = softwareQuery()
			q.Search = "02049"
			p = f.page(t, q, f.at.Add(time.Second))
			if p.MatchingCount != 1 || len(p.Rows) != 1 || *p.Rows[0].Name != seen[2049] {
				t.Fatal("later row not searchable")
			}
			at := f.at.Add(time.Second)
			failure := windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"}
			if _, e = f.apply(t, failure, at); e != nil {
				t.Fatal(e)
			}
			p = f.page(t, softwareQuery(), at)
			if p.Complete == nil || !p.Complete.ReceivedAt.Equal(f.at) || p.LatestAttempt.Status != "source_failed" || p.LatestAttempt.Reason != "access_denied" {
				t.Fatal("failure erased or refreshed complete")
			}
			if e = f.s.InitializeWindowsEventContent(ctx); e != nil {
				t.Fatal("optional schemas cannot coexist", e)
			}
		})
	}
}
func TestWindowsFullSoftwareZeroScopeDisableFloorsAndCursorIsolation(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 140, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := softwareQuery()
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	changed := q
	changed.Search = "Invented"
	if _, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, changed, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("cross-query cursor", e)
	}
	malformed := q
	malformed.Cursor = "aaa.bbb"
	if _, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, malformed, f.at); !errors.Is(e, windowsfullsoftware.ErrInvalid) {
		t.Fatal("malformed cursor", e)
	}
	sessionA := WithWindowsFullSoftwareSession(context.Background(), "session-a", f.at.Add(time.Hour), func() bool { return true })
	p, e := f.s.WindowsFullSoftwarePage(sessionA, f.snap.Approval.DeviceID, softwareQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = p.NextCursor
	sessionB := WithWindowsFullSoftwareSession(context.Background(), "session-b", f.at.Add(time.Hour), func() bool { return true })
	if _, e = f.s.WindowsFullSoftwarePage(sessionB, f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("cross-session cursor", e)
	}
	for _, m := range f.messages(t, 2, 0, f.at.Add(time.Minute)) {
		if _, e = f.apply(t, m, f.at.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.s.WindowsFullSoftwarePage(sessionA, f.snap.Approval.DeviceID, q, f.at.Add(time.Minute)); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("generation cursor spliced", e)
	}
	p = f.page(t, softwareQuery(), f.at.Add(time.Minute))
	if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 0 || p.MatchingCount != 0 || p.Rows == nil || len(p.Rows) != 0 {
		t.Fatal("zero not explicit")
	}
	f.consent.Revision = 2
	f.consent.Enabled = false
	f.consent.ChangedAt = f.at.Add(2 * time.Minute)
	if _, e = f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal("disable", e)
	}
	p = f.page(t, softwareQuery(), f.consent.ChangedAt)
	if p.Status != "disabled" || p.Complete != nil {
		t.Fatal("disable exposed rows")
	}
	for range 3 {
		if e = f.s.MaintainWindowsFullSoftware(context.Background(), f.consent.ChangedAt); e != nil {
			t.Fatal(e)
		}
	}
	f.consent.Revision = 3
	f.consent.Enabled = true
	f.consent.GrantID = strings.Repeat("c", 32)
	f.consent.ChangedAt = f.at.Add(3 * time.Minute)
	if _, e = f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal("reenable", e)
	}
	if _, e = f.apply(t, f.messages(t, 1, 0, f.consent.ChangedAt)[0], f.consent.ChangedAt); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("floor reset across grant", e)
	}
}
func TestWindowsFullSoftwareDigestReservationAndCommitAtomicity(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 129, f.at)
	if _, e := f.apply(t, messages[1], f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("out of order accepted", e)
	}
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	bad := messages[1]
	bad.Rows = append([]windowsfullsoftware.Row{}, bad.Rows...)
	newDisplay := "Changed display"
	bad.Rows[0].Publisher = &newDisplay
	if _, e := f.apply(t, bad, f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("bad final digest", e)
	}
	p := f.page(t, softwareQuery(), f.at)
	if p.Complete != nil {
		t.Fatal("bad final promoted")
	}
	// A real SQLite deferred constraint fails COMMIT after provisional promotion.
	final := messages[1]
	raw, _ := windowsfullsoftware.EncodeMessage(final)
	got, e := inventoryledger.CommitResult(context.Background(), func(ctx context.Context, action func(inventoryledger.Transaction) error) error {
		return f.s.transact(ctx, func(tx *transaction) error {
			if e := action(tx.conn); e != nil {
				return e
			}
			tx.beforeCommit = append(tx.beforeCommit, func() error {
				if _, e := tx.conn.ExecContext(ctx, `PRAGMA defer_foreign_keys=ON`); e != nil {
					return e
				}
				_, e := tx.conn.ExecContext(ctx, `DELETE FROM enrollment_credentials WHERE invitation_id=?`, f.snap.InvitationID)
				return e
			})
			return nil
		})
	}, func(tx inventoryledger.Transaction) (windowsfullsoftware.Receipt, error) {
		r, e := ledger.LoadRecord(context.Background(), tx, f.snap.Approval.DeviceID)
		if e != nil {
			return windowsfullsoftware.Receipt{}, e
		}
		out, e := ledger.Apply(context.Background(), tx, final, raw, &r, f.at, 0)
		if e != nil {
			return windowsfullsoftware.Receipt{}, e
		}
		e = ledger.SaveRecord(context.Background(), tx, f.snap.Approval.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r)
		return out, e
	})
	if e == nil || got != (windowsfullsoftware.Receipt{}) {
		t.Fatal("failed COMMIT leaked receipt", e)
	}
	if _, e = f.apply(t, final, f.at); e != nil {
		t.Fatal("rollback lost pending generation", e)
	}
}
func TestWindowsFullSoftwareCurrentAuthorityClockAndUsedState(t *testing.T) {
	t.Run("final-clock", func(t *testing.T) {
		f := newFullSoftwareFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 1, f.at)[0]
		raw, _ := windowsfullsoftware.EncodeMessage(m)
		calls := 0
		ctx := WithWindowsFullSoftwareClock(context.Background(), func() time.Time {
			calls++
			if calls >= 2 {
				return time.Unix(f.snap.Intent.NotAfter, 0).UTC()
			}
			return f.at
		})
		got, e := f.s.ApplyWindowsFullSoftware(WithWindowsFullSoftwareIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
		if e == nil || got != (windowsfullsoftware.Receipt{}) {
			t.Fatal("late receipt output", e)
		}
		p := f.page(t, softwareQuery(), f.at)
		if p.Complete != nil {
			t.Fatal("expired transaction committed")
		}
	})
	t.Run("revocation", func(t *testing.T) {
		f := newFullSoftwareFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 1, f.at)[0]
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
		ctl := f.f.control(f.snap, 20)
		ctl.Now = f.at.Add(time.Second).Unix()
		if _, e := f.s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); e != nil {
			t.Fatal(e)
		}
		if got, e := f.apply(t, m, f.at.Add(time.Second)); e == nil || got != (windowsfullsoftware.Receipt{}) {
			t.Fatal("revoked exact retry", e)
		}
		if p, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at.Add(time.Second)); e == nil || !reflect.DeepEqual(p, windowsfullsoftware.Page{}) {
			t.Fatal("revoked page", e)
		}
	})
	t.Run("used-floor-missing", func(t *testing.T) {
		f := newFullSoftwareFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		if _, e := f.s.db.Exec(`DELETE FROM wfw_authority`); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at); !errors.Is(e, ErrStorage) {
			t.Fatal("missing used floor adopted", e)
		}
		if e := f.s.InitializeWindowsFullSoftware(context.Background()); !errors.Is(e, ErrStorage) {
			t.Fatal("missing floor recreated", e)
		}
	})
}

func TestWindowsFullSoftwareTrustedIngressOriginRequiredAndDurable(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer func() { f.s.Close() }()
	origin := "https://agent-ingress.example:8444"
	f.consent.SenderBinding = windowsfullsoftware.SenderBinding("tls", origin, f.cert.CertificateHash(), f.snap.Approval.DeviceID)
	m := f.scope()
	raw, _ := windowsfullsoftware.EncodeMessage(m)
	if got, e := f.s.ApplyWindowsFullSoftware(context.Background(), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil || got != (windowsfullsoftware.Receipt{}) {
		t.Fatal("missing trusted origin admitted", e)
	}
	for _, bad := range []string{f.snap.Binding.Origin, "https://agent-ingress.example:8444/", "https://agent-ingress.example:8444?origin=trusted", "http://agent-ingress.example:8444", "https://user@agent-ingress.example:8444"} {
		ctx := WithWindowsFullSoftwareIngressOrigin(context.Background(), bad)
		if _, e := f.s.ApplyWindowsFullSoftware(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil {
			t.Fatal("wrong/malformed configured origin admitted", bad)
		}
	}
	ctx := WithWindowsFullSoftwareIngressOrigin(context.Background(), origin)
	if _, e := f.s.ApplyWindowsFullSoftware(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal("distinct agent origin rejected", e)
	}
	m = f.messages(t, 1, 1, f.at)[0]
	raw, _ = windowsfullsoftware.EncodeMessage(m)
	if _, e := f.s.ApplyWindowsFullSoftware(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	p := f.page(t, softwareQuery(), f.at)
	if p.Complete == nil || p.Complete.Manifest.SenderBinding != f.consent.SenderBinding {
		t.Fatal("durable agent origin lost")
	}
	if _, e := f.s.RecheckWindowsFullSoftware(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e != nil {
		t.Fatal(e)
	}
	changed := WithWindowsFullSoftwareIngressOrigin(context.Background(), "https://other-ingress.example:8444")
	if _, e := f.s.RecheckWindowsFullSoftware(changed, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e == nil {
		t.Fatal("changed configured origin accepted")
	}
	if _, e := f.s.db.Exec(`UPDATE wfw_authority SET body=CAST(json_remove(body,'$.ingressOrigin') AS BLOB)`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at); !errors.Is(e, ErrStorage) {
		t.Fatal("missing durable origin reconstructed", e)
	}
}
func TestWindowsFullSoftwareCompleteSearchIntegrityBoundedCost(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 8192, f.at)
	for _, m := range messages {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := softwareQuery()
	q.Search = "no such invented service"
	start := time.Now()
	for range 5 {
		p := f.page(t, q, f.at)
		if p.MatchingCount != 0 || p.Complete == nil || p.Complete.Manifest.RowCount != 8192 {
			t.Fatal("bounded full search")
		}
	}
	elapsed := time.Since(start)
	t.Logf("Verified five complete-generation searches: rows=8192 canonicalBytes=%d elapsed=%s mean=%s", messages[0].Manifest.RowsBytes, elapsed, elapsed/5)
	// A search key mismatch anywhere in the generation must fail even when that
	// row would otherwise be excluded by a zero-match query.
	if _, e := f.s.db.Exec(`UPDATE wfw_rows SET search='' WHERE ordinal=8191`); e != nil {
		t.Fatal(e)
	}
	if p, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, q, f.at); e == nil || !reflect.DeepEqual(p, windowsfullsoftware.Page{}) {
		t.Fatal("late derived corruption concealed by filtering", e)
	}
}

func TestWindowsFullSoftwareNonUTCSessionExpiryKeepsExactCursorDeadline(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	expiry := f.at.Add(10 * time.Minute).In(time.FixedZone("fixture-local", -4*60*60))
	ctx := WithWindowsFullSoftwareSession(context.Background(), "fixture-session", expiry, func() bool { return true })
	q := softwareQuery()
	first, e := f.s.WindowsFullSoftwarePage(ctx, f.snap.Approval.DeviceID, q, f.at)
	if e != nil || first.CursorExpiresAt == nil || first.CursorExpiresAt.Location() != time.UTC || !first.CursorExpiresAt.Equal(expiry) || first.NextCursor == "" {
		t.Fatal("session deadline not canonical and exact", e)
	}
	q.Cursor = first.NextCursor
	next, e := f.s.WindowsFullSoftwarePage(ctx, f.snap.Approval.DeviceID, q, f.at.Add(time.Second))
	if e != nil || next.Offset != 100 || !next.CursorExpiresAt.Equal(expiry) {
		t.Fatal("self-issued local-time cursor rejected or renewed", e)
	}
}
