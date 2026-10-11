package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullprocesses"
	ledger "localrmm/internal/windowsfullprocessesledger"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fullProcessesFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	consent windowsfullprocesses.Consent
}

func newFullProcessesFixture(t *testing.T, profile string) fullProcessesFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, profile)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsFullProcesses(context.Background()); e != nil {
		t.Fatal("initialize", e)
	}
	c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: windowsfullprocesses.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return fullProcessesFixture{f, s, path, snap, cert, at, c}
}
func (f fullProcessesFixture) apply(t *testing.T, m windowsfullprocesses.Message, now time.Time) (windowsfullprocesses.Receipt, error) {
	t.Helper()
	raw, e := windowsfullprocesses.EncodeMessage(m)
	if e != nil {
		t.Fatal("encode", e)
	}
	return f.s.ApplyWindowsFullProcesses(WithWindowsFullProcessesIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, now)
}
func (f fullProcessesFixture) scope() windowsfullprocesses.Message {
	return windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}
}
func (f fullProcessesFixture) grant(t *testing.T) {
	t.Helper()
	if _, e := f.apply(t, f.scope(), f.at); e != nil {
		t.Fatal("scope", e)
	}
}
func (f fullProcessesFixture) messages(t *testing.T, seq uint64, n int, at time.Time) []windowsfullprocesses.Message {
	t.Helper()
	rows := make([]windowsfullprocesses.Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedProcess%05d", i)
		rows[i] = windowsfullprocesses.Row{PID: uint32(i), ParentPID: uint32(i / 2), Name: &name, NameQuality: "observed", Threads: uint32(i%16 + 1)}
	}
	m, e := windowsfullprocesses.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullprocesses.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f fullProcessesFixture) page(t *testing.T, q windowsfullprocesses.Query, at time.Time) windowsfullprocesses.Page {
	t.Helper()
	p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, q, at)
	if e != nil {
		t.Fatal("page", e)
	}
	return p
}
func processesQuery() windowsfullprocesses.Query {
	return windowsfullprocesses.Query{Sort: "name-asc", Limit: 100}
}
func TestWindowsFullProcessesLargeGenerationRetryRestartPagingAndFailure(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFullProcessesFixture(t, profile)
			defer func() { f.s.Close() }()
			ctx := context.Background()
			p := f.page(t, processesQuery(), f.at)
			if p.Status != "not_configured" || p.AuthorityUntil != nil || p.Complete != nil {
				t.Fatal("ungranted is not empty complete")
			}
			f.grant(t)
			messages := f.messages(t, 1, 2051, f.at)
			first, e := f.apply(t, messages[0], f.at)
			if e != nil {
				t.Fatal(e)
			}
			p = f.page(t, processesQuery(), f.at)
			if p.Status != "awaiting" || p.Complete != nil || p.LatestAttempt == nil || p.LatestAttempt.Status != "pending" {
				t.Fatal("prefix exposed")
			}
			retry, e := f.apply(t, messages[0], f.at)
			if e != nil || retry != first {
				t.Fatal("retry", e)
			}
			bad := messages[0]
			bad.Rows = append([]windowsfullprocesses.Row{}, bad.Rows...)
			conflictName := "Aconflicting"
			bad.Rows[0].Name = &conflictName
			if _, e = f.apply(t, bad, f.at); !errors.Is(e, windowsfullprocesses.ErrConflict) {
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
			q := processesQuery()
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
			if len(seen) != 2051 || seen[128] != "InventedProcess00128" || seen[2049] != "InventedProcess02049" {
				t.Fatal("full pages omitted later rows")
			}
			q = processesQuery()
			q.Search = "02049"
			p = f.page(t, q, f.at.Add(time.Second))
			if p.MatchingCount != 1 || len(p.Rows) != 1 || *p.Rows[0].Name != seen[2049] {
				t.Fatal("later row not searchable")
			}
			at := f.at.Add(time.Second)
			failure := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"}
			if _, e = f.apply(t, failure, at); e != nil {
				t.Fatal(e)
			}
			p = f.page(t, processesQuery(), at)
			if p.Complete == nil || !p.Complete.ReceivedAt.Equal(f.at) || p.LatestAttempt.Status != "source_failed" || p.LatestAttempt.Reason != "access_denied" {
				t.Fatal("failure erased or refreshed complete")
			}
			if e = f.s.InitializeWindowsEventContent(ctx); e != nil {
				t.Fatal("optional schemas cannot coexist", e)
			}
		})
	}
}
func TestWindowsFullProcessesZeroScopeDisableFloorsAndCursorIsolation(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 140, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := processesQuery()
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	changed := q
	changed.Search = "Invented"
	if _, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, changed, f.at); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("cross-query cursor", e)
	}
	malformed := q
	malformed.Cursor = "aaa.bbb"
	if _, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, malformed, f.at); !errors.Is(e, windowsfullprocesses.ErrInvalid) {
		t.Fatal("malformed cursor", e)
	}
	sessionA := WithWindowsFullProcessesSession(context.Background(), "session-a", f.at.Add(time.Hour), func() bool { return true })
	p, e := f.s.WindowsFullProcessesPage(sessionA, f.snap.Approval.DeviceID, processesQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = p.NextCursor
	sessionB := WithWindowsFullProcessesSession(context.Background(), "session-b", f.at.Add(time.Hour), func() bool { return true })
	if _, e = f.s.WindowsFullProcessesPage(sessionB, f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("cross-session cursor", e)
	}
	for _, m := range f.messages(t, 2, 0, f.at.Add(time.Minute)) {
		if _, e = f.apply(t, m, f.at.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.s.WindowsFullProcessesPage(sessionA, f.snap.Approval.DeviceID, q, f.at.Add(time.Minute)); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("generation cursor spliced", e)
	}
	p = f.page(t, processesQuery(), f.at.Add(time.Minute))
	if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 0 || p.MatchingCount != 0 || p.Rows == nil || len(p.Rows) != 0 {
		t.Fatal("zero not explicit")
	}
	f.consent.Revision = 2
	f.consent.Enabled = false
	f.consent.ChangedAt = f.at.Add(2 * time.Minute)
	if _, e = f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal("disable", e)
	}
	p = f.page(t, processesQuery(), f.consent.ChangedAt)
	if p.Status != "disabled" || p.Complete != nil {
		t.Fatal("disable exposed rows")
	}
	for range 3 {
		if e = f.s.MaintainWindowsFullProcesses(context.Background(), f.consent.ChangedAt); e != nil {
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
	if _, e = f.apply(t, f.messages(t, 1, 0, f.consent.ChangedAt)[0], f.consent.ChangedAt); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("floor reset across grant", e)
	}
}
func TestWindowsFullProcessesDigestReservationAndCommitAtomicity(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 129, f.at)
	if _, e := f.apply(t, messages[1], f.at); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("out of order accepted", e)
	}
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	bad := messages[1]
	bad.Rows = append([]windowsfullprocesses.Row{}, bad.Rows...)
	newDisplay := "Changed display"
	bad.Rows[0].Name = &newDisplay
	if _, e := f.apply(t, bad, f.at); !errors.Is(e, windowsfullprocesses.ErrConflict) {
		t.Fatal("bad final digest", e)
	}
	p := f.page(t, processesQuery(), f.at)
	if p.Complete != nil {
		t.Fatal("bad final promoted")
	}
	// A real SQLite deferred constraint fails COMMIT after provisional promotion.
	final := messages[1]
	raw, _ := windowsfullprocesses.EncodeMessage(final)
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
	}, func(tx inventoryledger.Transaction) (windowsfullprocesses.Receipt, error) {
		r, e := ledger.LoadRecord(context.Background(), tx, f.snap.Approval.DeviceID)
		if e != nil {
			return windowsfullprocesses.Receipt{}, e
		}
		out, e := ledger.Apply(context.Background(), tx, final, raw, &r, f.at, 0)
		if e != nil {
			return windowsfullprocesses.Receipt{}, e
		}
		e = ledger.SaveRecord(context.Background(), tx, f.snap.Approval.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r)
		return out, e
	})
	if e == nil || got != (windowsfullprocesses.Receipt{}) {
		t.Fatal("failed COMMIT leaked receipt", e)
	}
	if _, e = f.apply(t, final, f.at); e != nil {
		t.Fatal("rollback lost pending generation", e)
	}
}
func TestWindowsFullProcessesCurrentAuthorityClockAndUsedState(t *testing.T) {
	t.Run("final-clock", func(t *testing.T) {
		f := newFullProcessesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 1, f.at)[0]
		raw, _ := windowsfullprocesses.EncodeMessage(m)
		calls := 0
		ctx := WithWindowsFullProcessesClock(context.Background(), func() time.Time {
			calls++
			if calls >= 2 {
				return time.Unix(f.snap.Intent.NotAfter, 0).UTC()
			}
			return f.at
		})
		got, e := f.s.ApplyWindowsFullProcesses(WithWindowsFullProcessesIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
		if e == nil || got != (windowsfullprocesses.Receipt{}) {
			t.Fatal("late receipt output", e)
		}
		p := f.page(t, processesQuery(), f.at)
		if p.Complete != nil {
			t.Fatal("expired transaction committed")
		}
	})
	t.Run("revocation", func(t *testing.T) {
		f := newFullProcessesFixture(t, "tls")
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
		if got, e := f.apply(t, m, f.at.Add(time.Second)); e == nil || got != (windowsfullprocesses.Receipt{}) {
			t.Fatal("revoked exact retry", e)
		}
		if p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at.Add(time.Second)); e == nil || !reflect.DeepEqual(p, windowsfullprocesses.Page{}) {
			t.Fatal("revoked page", e)
		}
	})
	t.Run("used-floor-missing", func(t *testing.T) {
		f := newFullProcessesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		if _, e := f.s.db.Exec(`DELETE FROM wfp_authority`); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at); !errors.Is(e, ErrStorage) {
			t.Fatal("missing used floor adopted", e)
		}
		if e := f.s.InitializeWindowsFullProcesses(context.Background()); !errors.Is(e, ErrStorage) {
			t.Fatal("missing floor recreated", e)
		}
	})
}

func TestWindowsFullProcessesTrustedIngressOriginRequiredAndDurable(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer func() { f.s.Close() }()
	origin := "https://agent-ingress.example:8444"
	f.consent.SenderBinding = windowsfullprocesses.SenderBinding("tls", origin, f.cert.CertificateHash(), f.snap.Approval.DeviceID)
	m := f.scope()
	raw, _ := windowsfullprocesses.EncodeMessage(m)
	if got, e := f.s.ApplyWindowsFullProcesses(context.Background(), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil || got != (windowsfullprocesses.Receipt{}) {
		t.Fatal("missing trusted origin admitted", e)
	}
	for _, bad := range []string{f.snap.Binding.Origin, "https://agent-ingress.example:8444/", "https://agent-ingress.example:8444?origin=trusted", "http://agent-ingress.example:8444", "https://user@agent-ingress.example:8444"} {
		ctx := WithWindowsFullProcessesIngressOrigin(context.Background(), bad)
		if _, e := f.s.ApplyWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil {
			t.Fatal("wrong/malformed configured origin admitted", bad)
		}
	}
	ctx := WithWindowsFullProcessesIngressOrigin(context.Background(), origin)
	if _, e := f.s.ApplyWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal("distinct agent origin rejected", e)
	}
	m = f.messages(t, 1, 1, f.at)[0]
	raw, _ = windowsfullprocesses.EncodeMessage(m)
	if _, e := f.s.ApplyWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	p := f.page(t, processesQuery(), f.at)
	if p.Complete == nil || p.Complete.Manifest.SenderBinding != f.consent.SenderBinding {
		t.Fatal("durable agent origin lost")
	}
	if _, e := f.s.RecheckWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e != nil {
		t.Fatal(e)
	}
	changed := WithWindowsFullProcessesIngressOrigin(context.Background(), "https://other-ingress.example:8444")
	if _, e := f.s.RecheckWindowsFullProcesses(changed, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e == nil {
		t.Fatal("changed configured origin accepted")
	}
	if _, e := f.s.db.Exec(`UPDATE wfp_authority SET body=CAST(json_remove(body,'$.ingressOrigin') AS BLOB)`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at); !errors.Is(e, ErrStorage) {
		t.Fatal("missing durable origin reconstructed", e)
	}
}
func TestWindowsFullProcessesCompleteSearchIntegrityBoundedCost(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 8192, f.at)
	for _, m := range messages {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := processesQuery()
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
	if _, e := f.s.db.Exec(`UPDATE wfp_rows SET search='' WHERE ordinal=8191`); e != nil {
		t.Fatal(e)
	}
	if p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, q, f.at); e == nil || !reflect.DeepEqual(p, windowsfullprocesses.Page{}) {
		t.Fatal("late derived corruption concealed by filtering", e)
	}
}

func TestWindowsFullProcessesNonUTCSessionExpiryKeepsExactCursorDeadline(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	expiry := f.at.Add(10 * time.Minute).In(time.FixedZone("fixture-local", -4*60*60))
	ctx := WithWindowsFullProcessesSession(context.Background(), "fixture-session", expiry, func() bool { return true })
	q := processesQuery()
	first, e := f.s.WindowsFullProcessesPage(ctx, f.snap.Approval.DeviceID, q, f.at)
	if e != nil || first.CursorExpiresAt == nil || first.CursorExpiresAt.Location() != time.UTC || !first.CursorExpiresAt.Equal(expiry) || first.NextCursor == "" {
		t.Fatal("session deadline not canonical and exact", e)
	}
	q.Cursor = first.NextCursor
	next, e := f.s.WindowsFullProcessesPage(ctx, f.snap.Approval.DeviceID, q, f.at.Add(time.Second))
	if e != nil || next.Offset != 100 || !next.CursorExpiresAt.Equal(expiry) {
		t.Fatal("self-issued local-time cursor rejected or renewed", e)
	}
}
