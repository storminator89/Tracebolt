package enrollmentstore

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsnetworkcontext"
	ledger "localrmm/internal/windowsnetworkcontextledger"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

type networkContextFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	consent windowsnetworkcontext.Consent
}

func newNetworkContextFixture(t *testing.T, profile string) networkContextFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, profile)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsNetworkContext(context.Background()); e != nil {
		t.Fatal("initialize", e)
	}
	c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return networkContextFixture{f, s, path, snap, cert, at, c}
}
func (f networkContextFixture) apply(t *testing.T, m windowsnetworkcontext.Message, now time.Time) (windowsnetworkcontext.Receipt, error) {
	t.Helper()
	raw, e := windowsnetworkcontext.EncodeMessage(m)
	if e != nil {
		t.Fatal("encode", e)
	}
	return f.s.ApplyWindowsNetworkContext(WithWindowsNetworkContextIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, now)
}
func (f networkContextFixture) scope() windowsnetworkcontext.Message {
	return windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}
}
func (f networkContextFixture) grant(t *testing.T) {
	t.Helper()
	if _, e := f.apply(t, f.scope(), f.at); e != nil {
		t.Fatal("scope", e)
	}
}
func (f networkContextFixture) messages(t *testing.T, seq uint64, n int, at time.Time) []windowsnetworkcontext.Message {
	t.Helper()
	rows := make([]windowsnetworkcontext.Row, n)
	for i := range rows {
		rows[i] = windowsnetworkcontext.Row{ID: uint32(i + 1), Kind: "route", InterfaceIndex: uint32(i%256 + 1), Route: &windowsnetworkcontext.Route{Destination: netip.MustParsePrefix(fmt.Sprintf("2001:db8::%d/128", i)).String(), NextHop: "::", Metric: uint32(i), Protocol: 2}}

	}
	m, e := windowsnetworkcontext.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsnetworkcontext.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f networkContextFixture) page(t *testing.T, q windowsnetworkcontext.Query, at time.Time) windowsnetworkcontext.Page {
	t.Helper()
	p, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, q, at)
	if e != nil {
		t.Fatal("page", e)
	}
	return p
}
func networkContextQuery() windowsnetworkcontext.Query {
	return windowsnetworkcontext.Query{Kind: "all", Sort: "source-asc", Limit: 100}
}
func TestWindowsNetworkContextLargeGenerationRetryRestartPagingAndFailure(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newNetworkContextFixture(t, profile)
			defer func() { f.s.Close() }()
			ctx := context.Background()
			p := f.page(t, networkContextQuery(), f.at)
			if p.Status != "not_configured" || p.AuthorityUntil != nil || p.Complete != nil {
				t.Fatal("ungranted is not empty complete")
			}
			f.grant(t)
			messages := f.messages(t, 1, 2051, f.at)
			first, e := f.apply(t, messages[0], f.at)
			if e != nil {
				t.Fatal(e)
			}
			p = f.page(t, networkContextQuery(), f.at)
			if p.Status != "awaiting" || p.Complete != nil || p.LatestAttempt == nil || p.LatestAttempt.Status != "pending" {
				t.Fatal("prefix exposed")
			}
			retry, e := f.apply(t, messages[0], f.at)
			if e != nil || retry != first {
				t.Fatal("retry", e)
			}
			bad := messages[0]
			bad.Rows = append([]windowsnetworkcontext.Row{}, bad.Rows...)
			route := *bad.Rows[0].Route
			route.Metric++
			bad.Rows[0].Route = &route
			if _, e = f.apply(t, bad, f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
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
			q := networkContextQuery()
			seen := []string{}
			for {
				p = f.page(t, q, f.at.Add(time.Second))
				if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 2051 || p.MatchingCount != 2051 {
					t.Fatal("wrong complete", p.Status)
				}
				for _, r := range p.Rows {
					seen = append(seen, r.Route.Destination)
				}
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
			}
			if len(seen) != 2051 || seen[128] != "2001:db8::128/128" || seen[2049] != "2001:db8::2049/128" {
				t.Fatal("full pages omitted later rows")
			}
			q = networkContextQuery()
			q.Search = "::2049/"
			p = f.page(t, q, f.at.Add(time.Second))
			if p.MatchingCount != 1 || len(p.Rows) != 1 || p.Rows[0].Route.Destination != seen[2049] {
				t.Fatal("later row not searchable")
			}
			at := f.at.Add(time.Second)
			failure := windowsnetworkcontext.Message{SchemaVersion: windowsnetworkcontext.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"}
			if _, e = f.apply(t, failure, at); e != nil {
				t.Fatal(e)
			}
			p = f.page(t, networkContextQuery(), at)
			if p.Complete == nil || !p.Complete.ReceivedAt.Equal(f.at) || p.LatestAttempt.Status != "source_failed" || p.LatestAttempt.Reason != "access_denied" {
				t.Fatal("failure erased or refreshed complete")
			}
			if e = f.s.InitializeWindowsEventContent(ctx); e != nil {
				t.Fatal("optional schemas cannot coexist", e)
			}
		})
	}
}
func TestWindowsNetworkContextZeroScopeDisableFloorsAndCursorIsolation(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 140, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := networkContextQuery()
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	changed := q
	changed.Search = "Invented"
	if _, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, changed, f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("cross-query cursor", e)
	}
	malformed := q
	malformed.Cursor = "aaa.bbb"
	if _, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, malformed, f.at); !errors.Is(e, windowsnetworkcontext.ErrInvalid) {
		t.Fatal("malformed cursor", e)
	}
	sessionA := WithWindowsNetworkContextSession(context.Background(), "session-a", f.at.Add(time.Hour), func() bool { return true })
	p, e := f.s.WindowsNetworkContextPage(sessionA, f.snap.Approval.DeviceID, networkContextQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = p.NextCursor
	sessionB := WithWindowsNetworkContextSession(context.Background(), "session-b", f.at.Add(time.Hour), func() bool { return true })
	if _, e = f.s.WindowsNetworkContextPage(sessionB, f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("cross-session cursor", e)
	}
	for _, m := range f.messages(t, 2, 0, f.at.Add(time.Minute)) {
		if _, e = f.apply(t, m, f.at.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.s.WindowsNetworkContextPage(sessionA, f.snap.Approval.DeviceID, q, f.at.Add(time.Minute)); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("generation cursor spliced", e)
	}
	p = f.page(t, networkContextQuery(), f.at.Add(time.Minute))
	if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 0 || p.MatchingCount != 0 || p.Rows == nil || len(p.Rows) != 0 {
		t.Fatal("zero not explicit")
	}
	f.consent.Revision = 2
	f.consent.Enabled = false
	f.consent.ChangedAt = f.at.Add(2 * time.Minute)
	if _, e = f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal("disable", e)
	}
	p = f.page(t, networkContextQuery(), f.consent.ChangedAt)
	if p.Status != "disabled" || p.Complete != nil {
		t.Fatal("disable exposed rows")
	}
	for range 3 {
		if e = f.s.MaintainWindowsNetworkContext(context.Background(), f.consent.ChangedAt); e != nil {
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
	if _, e = f.apply(t, f.messages(t, 1, 0, f.consent.ChangedAt)[0], f.consent.ChangedAt); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("floor reset across grant", e)
	}
}
func TestWindowsNetworkContextDigestReservationAndCommitAtomicity(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 129, f.at)
	if _, e := f.apply(t, messages[1], f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("out of order accepted", e)
	}
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	bad := messages[1]
	bad.Rows = append([]windowsnetworkcontext.Row{}, bad.Rows...)
	route := *bad.Rows[0].Route
	route.Metric++
	bad.Rows[0].Route = &route
	if _, e := f.apply(t, bad, f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("bad final digest", e)
	}
	p := f.page(t, networkContextQuery(), f.at)
	if p.Complete != nil {
		t.Fatal("bad final promoted")
	}
	// A real SQLite deferred constraint fails COMMIT after provisional promotion.
	final := messages[1]
	raw, _ := windowsnetworkcontext.EncodeMessage(final)
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
	}, func(tx inventoryledger.Transaction) (windowsnetworkcontext.Receipt, error) {
		r, e := ledger.LoadRecord(context.Background(), tx, f.snap.Approval.DeviceID)
		if e != nil {
			return windowsnetworkcontext.Receipt{}, e
		}
		out, e := ledger.Apply(context.Background(), tx, final, raw, &r, f.at, 0)
		if e != nil {
			return windowsnetworkcontext.Receipt{}, e
		}
		e = ledger.SaveRecord(context.Background(), tx, f.snap.Approval.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r)
		return out, e
	})
	if e == nil || got != (windowsnetworkcontext.Receipt{}) {
		t.Fatal("failed COMMIT leaked receipt", e)
	}
	if _, e = f.apply(t, final, f.at); e != nil {
		t.Fatal("rollback lost pending generation", e)
	}
}
func TestWindowsNetworkContextCurrentAuthorityClockAndUsedState(t *testing.T) {
	t.Run("final-clock", func(t *testing.T) {
		f := newNetworkContextFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 1, f.at)[0]
		raw, _ := windowsnetworkcontext.EncodeMessage(m)
		calls := 0
		ctx := WithWindowsNetworkContextClock(context.Background(), func() time.Time {
			calls++
			if calls >= 2 {
				return time.Unix(f.snap.Intent.NotAfter, 0).UTC()
			}
			return f.at
		})
		got, e := f.s.ApplyWindowsNetworkContext(WithWindowsNetworkContextIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
		if e == nil || got != (windowsnetworkcontext.Receipt{}) {
			t.Fatal("late receipt output", e)
		}
		p := f.page(t, networkContextQuery(), f.at)
		if p.Complete != nil {
			t.Fatal("expired transaction committed")
		}
	})
	t.Run("revocation", func(t *testing.T) {
		f := newNetworkContextFixture(t, "tls")
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
		if got, e := f.apply(t, m, f.at.Add(time.Second)); e == nil || got != (windowsnetworkcontext.Receipt{}) {
			t.Fatal("revoked exact retry", e)
		}
		if p, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, networkContextQuery(), f.at.Add(time.Second)); e == nil || !reflect.DeepEqual(p, windowsnetworkcontext.Page{}) {
			t.Fatal("revoked page", e)
		}
	})
	t.Run("used-floor-missing", func(t *testing.T) {
		f := newNetworkContextFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		if _, e := f.s.db.Exec(`DELETE FROM wnc_authority`); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, networkContextQuery(), f.at); !errors.Is(e, ErrStorage) {
			t.Fatal("missing used floor adopted", e)
		}
		if e := f.s.InitializeWindowsNetworkContext(context.Background()); !errors.Is(e, ErrStorage) {
			t.Fatal("missing floor recreated", e)
		}
	})
}

func TestWindowsNetworkContextTrustedIngressOriginRequiredAndDurable(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer func() { f.s.Close() }()
	origin := "https://agent-ingress.example:8444"
	f.consent.SenderBinding = windowsnetworkcontext.SenderBinding("tls", origin, f.cert.CertificateHash(), f.snap.Approval.DeviceID)
	m := f.scope()
	raw, _ := windowsnetworkcontext.EncodeMessage(m)
	if got, e := f.s.ApplyWindowsNetworkContext(context.Background(), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil || got != (windowsnetworkcontext.Receipt{}) {
		t.Fatal("missing trusted origin admitted", e)
	}
	for _, bad := range []string{f.snap.Binding.Origin, "https://agent-ingress.example:8444/", "https://agent-ingress.example:8444?origin=trusted", "http://agent-ingress.example:8444", "https://user@agent-ingress.example:8444"} {
		ctx := WithWindowsNetworkContextIngressOrigin(context.Background(), bad)
		if _, e := f.s.ApplyWindowsNetworkContext(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil {
			t.Fatal("wrong/malformed configured origin admitted", bad)
		}
	}
	ctx := WithWindowsNetworkContextIngressOrigin(context.Background(), origin)
	if _, e := f.s.ApplyWindowsNetworkContext(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal("distinct agent origin rejected", e)
	}
	m = f.messages(t, 1, 1, f.at)[0]
	raw, _ = windowsnetworkcontext.EncodeMessage(m)
	if _, e := f.s.ApplyWindowsNetworkContext(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	p := f.page(t, networkContextQuery(), f.at)
	if p.Complete == nil || p.Complete.Manifest.SenderBinding != f.consent.SenderBinding {
		t.Fatal("durable agent origin lost")
	}
	if _, e := f.s.RecheckWindowsNetworkContext(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e != nil {
		t.Fatal(e)
	}
	changed := WithWindowsNetworkContextIngressOrigin(context.Background(), "https://other-ingress.example:8444")
	if _, e := f.s.RecheckWindowsNetworkContext(changed, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e == nil {
		t.Fatal("changed configured origin accepted")
	}
	if _, e := f.s.db.Exec(`UPDATE wnc_authority SET body=CAST(json_remove(body,'$.ingressOrigin') AS BLOB)`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, networkContextQuery(), f.at); !errors.Is(e, ErrStorage) {
		t.Fatal("missing durable origin reconstructed", e)
	}
}
func TestWindowsNetworkContextCompleteSearchIntegrityBoundedCost(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 4096, f.at)
	for _, m := range messages {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := networkContextQuery()
	q.Search = "no such invented service"
	start := time.Now()
	for range 5 {
		p := f.page(t, q, f.at)
		if p.MatchingCount != 0 || p.Complete == nil || p.Complete.Manifest.RowCount != 4096 {
			t.Fatal("bounded full search")
		}
	}
	elapsed := time.Since(start)
	t.Logf("Verified five complete-generation searches: rows=4096 canonicalBytes=%d elapsed=%s mean=%s", messages[0].Manifest.RowsBytes, elapsed, elapsed/5)
	// A search key mismatch anywhere in the generation must fail even when that
	// row would otherwise be excluded by a zero-match query.
	if _, e := f.s.db.Exec(`UPDATE wnc_rows SET search='' WHERE ordinal=4095`); e != nil {
		t.Fatal(e)
	}
	if p, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, q, f.at); e == nil || !reflect.DeepEqual(p, windowsnetworkcontext.Page{}) {
		t.Fatal("late derived corruption concealed by filtering", e)
	}
}

func TestWindowsNetworkContextNonUTCSessionExpiryKeepsExactCursorDeadline(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	expiry := f.at.Add(10 * time.Minute).In(time.FixedZone("fixture-local", -4*60*60))
	ctx := WithWindowsNetworkContextSession(context.Background(), "fixture-session", expiry, func() bool { return true })
	q := networkContextQuery()
	first, e := f.s.WindowsNetworkContextPage(ctx, f.snap.Approval.DeviceID, q, f.at)
	if e != nil || first.CursorExpiresAt == nil || first.CursorExpiresAt.Location() != time.UTC || !first.CursorExpiresAt.Equal(expiry) || first.NextCursor == "" {
		t.Fatal("session deadline not canonical and exact", e)
	}
	q.Cursor = first.NextCursor
	next, e := f.s.WindowsNetworkContextPage(ctx, f.snap.Approval.DeviceID, q, f.at.Add(time.Second))
	if e != nil || next.Offset != 100 || !next.CursorExpiresAt.Equal(expiry) {
		t.Fatal("self-issued local-time cursor rejected or renewed", e)
	}
}

func TestWindowsNetworkContextKindBoundCursorAndExactCounters(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	name := "Synthetic >53-bit counter interface"
	rows := []windowsnetworkcontext.Row{{ID: 1, Kind: "route", InterfaceIndex: 7, Route: &windowsnetworkcontext.Route{Destination: "0.0.0.0/0", NextHop: "192.0.2.1", Metric: 15, Protocol: 2}}, {ID: 2, Kind: "interface", InterfaceIndex: 7, Counters: &windowsnetworkcontext.Counters{Alias: &name, AliasQuality: "observed", InOctets: "18446744073709551615", OutOctets: "9007199254740993", InErrors: "0", OutErrors: "2", InDiscards: "0", OutDiscards: "3"}}}
	ms, e := windowsnetworkcontext.Build(f.snap.Approval.DeviceID, f.consent, 1, windowsnetworkcontext.Capture{StartedAt: f.at, FinishedAt: f.at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range ms {
		if _, e = f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := networkContextQuery()
	q.Limit = 1
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	q.Kind = "interface"
	if _, e = f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsnetworkcontext.ErrConflict) {
		t.Fatal("kind cursor splice", e)
	}
	q.Cursor = ""
	p = f.page(t, q, f.at)
	if p.Kind != "interface" || p.MatchingCount != 1 || len(p.Rows) != 1 || p.Rows[0].Counters.InOctets != "18446744073709551615" || p.Rows[0].Counters.OutOctets != "9007199254740993" || p.Rows[0].Route != nil {
		t.Fatal("wrong source or rounded counter")
	}
	q.Kind = "route"
	p = f.page(t, q, f.at)
	if p.MatchingCount != 1 || p.Rows[0].Counters != nil {
		t.Fatal("unsafe source join")
	}
}

func TestWindowsNetworkContextUsedSchemaLossCannotReinitialize(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, name := range []string{"wnc_rows_interface", "wnc_rows_kind", "wnc_rows_id", "wnc_rows", "wnc_chunks", "wnc_generations", "wnc_authority", "wnc_meta"} {
		kind := "TABLE"
		if strings.HasPrefix(name, "wnc_rows_") {
			kind = "INDEX"
		}
		if _, e := f.s.db.Exec("DROP " + kind + " " + name); e != nil {
			t.Fatal(e)
		}
	}
	if e := f.s.InitializeWindowsNetworkContext(context.Background()); !errors.Is(e, ErrStorage) {
		t.Fatal("missing used context schema recreated", e)
	}
	if _, e := f.s.WindowsNetworkContextPage(context.Background(), f.snap.Approval.DeviceID, networkContextQuery(), f.at); !errors.Is(e, ErrStorage) {
		t.Fatal("missing used schema became unconfigured", e)
	}
}

func TestWindowsNetworkContextSharesGlobalBudgetWithExistingDomains(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	if e := f.s.InitializeWindowsFullProcesses(context.Background()); e != nil {
		t.Fatal(e)
	}
	ms := f.messages(t, 1, 1, f.at)
	if _, e := f.apply(t, ms[0], f.at); e != nil {
		t.Fatal(e)
	}
	e := f.s.transact(context.Background(), func(tx *transaction) error {
		extra, e := windowsFullProcessesOtherBytes(context.Background(), tx)
		if e != nil {
			return e
		}
		var reserved int64
		if e = tx.conn.QueryRowContext(context.Background(), `SELECT sum(reserved_bytes) FROM wnc_generations`).Scan(&reserved); e != nil {
			return e
		}
		if reserved <= 0 || extra < reserved {
			t.Fatal("network reservation absent from process global accounting")
		}
		reverse, e := windowsNetworkContextOtherBytes(context.Background(), tx)
		if e != nil {
			return e
		}
		if reverse <= 0 {
			t.Fatal("base metadata excluded")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestWindowsNetworkContextAbsentSchemaPreservesSourceQuery(t *testing.T) {
	_, s, _, snap, _ := activeWindowsStore(t, "tls")
	defer s.Close()
	for _, kind := range []string{"all", "route", "interface"} {
		q := networkContextQuery()
		q.Kind = kind
		p, e := s.WindowsNetworkContextPage(context.Background(), snap.Approval.DeviceID, q, time.Unix(testNow+10, 0).UTC())
		if e != nil || p.Status != "not_configured" || p.Kind != kind || p.Complete != nil || len(p.Rows) != 0 || p.Rows == nil {
			t.Fatal("schema-absent kind", kind, e)
		}
	}
}
