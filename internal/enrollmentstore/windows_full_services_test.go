package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullservices"
	ledger "localrmm/internal/windowsfullservicesledger"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fullServicesFixture struct {
	f       fixture
	s       *Store
	path    string
	snap    enrollmentstate.Snapshot
	cert    enrollmentcrypto.VerifiedCertificate
	at      time.Time
	consent windowsfullservices.Consent
}

func newFullServicesFixture(t *testing.T, profile string) fullServicesFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, profile)
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsFullServices(context.Background()); e != nil {
		t.Fatal("initialize", e)
	}
	c := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: windowsfullservices.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return fullServicesFixture{f, s, path, snap, cert, at, c}
}
func (f fullServicesFixture) apply(t *testing.T, m windowsfullservices.Message, now time.Time) (windowsfullservices.Receipt, error) {
	t.Helper()
	raw, e := windowsfullservices.EncodeMessage(m)
	if e != nil {
		t.Fatal("encode", e)
	}
	return f.s.ApplyWindowsFullServices(WithWindowsFullServicesIngressOrigin(context.Background(), f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, now)
}
func (f fullServicesFixture) scope() windowsfullservices.Message {
	return windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}
}
func (f fullServicesFixture) grant(t *testing.T) {
	t.Helper()
	if _, e := f.apply(t, f.scope(), f.at); e != nil {
		t.Fatal("scope", e)
	}
}
func (f fullServicesFixture) messages(t *testing.T, seq uint64, n int, at time.Time) []windowsfullservices.Message {
	t.Helper()
	rows := make([]windowsfullservices.Row, n)
	for i := range rows {
		name := fmt.Sprintf("InventedService%05d", i)
		display := fmt.Sprintf("Fiktiver Dienst %05d 東京", i)
		state := "running"
		pid := uint32(i + 300)
		rows[i] = windowsfullservices.Row{Name: name, DisplayName: &display, DisplayNameQuality: "observed", State: &state, StateQuality: "observed", PID: &pid, PIDQuality: "observed"}
	}
	m, e := windowsfullservices.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullservices.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f fullServicesFixture) page(t *testing.T, q windowsfullservices.Query, at time.Time) windowsfullservices.Page {
	t.Helper()
	p, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, q, at)
	if e != nil {
		t.Fatal("page", e)
	}
	return p
}
func fullQuery() windowsfullservices.Query {
	return windowsfullservices.Query{Sort: "name-asc", Limit: 100}
}
func TestWindowsFullServicesLargeGenerationRetryRestartPagingAndFailure(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFullServicesFixture(t, profile)
			defer func() { f.s.Close() }()
			ctx := context.Background()
			p := f.page(t, fullQuery(), f.at)
			if p.Status != "not_configured" || p.AuthorityUntil != nil || p.Complete != nil {
				t.Fatal("ungranted is not empty complete")
			}
			f.grant(t)
			messages := f.messages(t, 1, 2051, f.at)
			first, e := f.apply(t, messages[0], f.at)
			if e != nil {
				t.Fatal(e)
			}
			p = f.page(t, fullQuery(), f.at)
			if p.Status != "awaiting" || p.Complete != nil || p.LatestAttempt == nil || p.LatestAttempt.Status != "pending" {
				t.Fatal("prefix exposed")
			}
			retry, e := f.apply(t, messages[0], f.at)
			if e != nil || retry != first {
				t.Fatal("retry", e)
			}
			bad := messages[0]
			bad.Rows = append([]windowsfullservices.Row{}, bad.Rows...)
			bad.Rows[0].Name = "Aconflicting"
			if _, e = f.apply(t, bad, f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
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
			q := fullQuery()
			seen := []string{}
			for {
				p = f.page(t, q, f.at.Add(time.Second))
				if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 2051 || p.MatchingCount != 2051 {
					t.Fatal("wrong complete", p.Status)
				}
				for _, r := range p.Rows {
					seen = append(seen, r.Name)
				}
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
			}
			if len(seen) != 2051 || seen[128] != "InventedService00128" || seen[2049] != "InventedService02049" {
				t.Fatal("full pages omitted later rows")
			}
			q = fullQuery()
			q.Search = "02049"
			p = f.page(t, q, f.at.Add(time.Second))
			if p.MatchingCount != 1 || len(p.Rows) != 1 || p.Rows[0].Name != seen[2049] {
				t.Fatal("later row not searchable")
			}
			at := f.at.Add(time.Second)
			failure := windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 2, AttemptedAt: &at, Reason: "access_denied"}
			if _, e = f.apply(t, failure, at); e != nil {
				t.Fatal(e)
			}
			p = f.page(t, fullQuery(), at)
			if p.Complete == nil || !p.Complete.ReceivedAt.Equal(f.at) || p.LatestAttempt.Status != "source_failed" || p.LatestAttempt.Reason != "access_denied" {
				t.Fatal("failure erased or refreshed complete")
			}
			if e = f.s.InitializeWindowsEventContent(ctx); e != nil {
				t.Fatal("optional schemas cannot coexist", e)
			}
		})
	}
}
func TestWindowsFullServicesZeroScopeDisableFloorsAndCursorIsolation(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 140, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := fullQuery()
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	changed := q
	changed.Search = "Invented"
	if _, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, changed, f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("cross-query cursor", e)
	}
	malformed := q
	malformed.Cursor = "aaa.bbb"
	if _, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, malformed, f.at); !errors.Is(e, windowsfullservices.ErrInvalid) {
		t.Fatal("malformed cursor", e)
	}
	sessionA := WithWindowsFullServicesSession(context.Background(), "session-a", f.at.Add(time.Hour), func() bool { return true })
	p, e := f.s.WindowsFullServicesPage(sessionA, f.snap.Approval.DeviceID, fullQuery(), f.at)
	if e != nil {
		t.Fatal(e)
	}
	q.Cursor = p.NextCursor
	sessionB := WithWindowsFullServicesSession(context.Background(), "session-b", f.at.Add(time.Hour), func() bool { return true })
	if _, e = f.s.WindowsFullServicesPage(sessionB, f.snap.Approval.DeviceID, q, f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("cross-session cursor", e)
	}
	for _, m := range f.messages(t, 2, 0, f.at.Add(time.Minute)) {
		if _, e = f.apply(t, m, f.at.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.s.WindowsFullServicesPage(sessionA, f.snap.Approval.DeviceID, q, f.at.Add(time.Minute)); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("generation cursor spliced", e)
	}
	p = f.page(t, fullQuery(), f.at.Add(time.Minute))
	if p.Status != "ready" || p.Complete == nil || p.Complete.Manifest.RowCount != 0 || p.MatchingCount != 0 || p.Rows == nil || len(p.Rows) != 0 {
		t.Fatal("zero not explicit")
	}
	f.consent.Revision = 2
	f.consent.Enabled = false
	f.consent.ChangedAt = f.at.Add(2 * time.Minute)
	if _, e = f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal("disable", e)
	}
	p = f.page(t, fullQuery(), f.consent.ChangedAt)
	if p.Status != "disabled" || p.Complete != nil {
		t.Fatal("disable exposed rows")
	}
	for range 3 {
		if e = f.s.MaintainWindowsFullServices(context.Background(), f.consent.ChangedAt); e != nil {
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
	if _, e = f.apply(t, f.messages(t, 1, 0, f.consent.ChangedAt)[0], f.consent.ChangedAt); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("floor reset across grant", e)
	}
}
func TestWindowsFullServicesDigestReservationAndCommitAtomicity(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 129, f.at)
	if _, e := f.apply(t, messages[1], f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("out of order accepted", e)
	}
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	bad := messages[1]
	bad.Rows = append([]windowsfullservices.Row{}, bad.Rows...)
	newDisplay := "Changed display"
	bad.Rows[0].DisplayName = &newDisplay
	if _, e := f.apply(t, bad, f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("bad final digest", e)
	}
	p := f.page(t, fullQuery(), f.at)
	if p.Complete != nil {
		t.Fatal("bad final promoted")
	}
	// A real SQLite deferred constraint fails COMMIT after provisional promotion.
	final := messages[1]
	raw, _ := windowsfullservices.EncodeMessage(final)
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
	}, func(tx inventoryledger.Transaction) (windowsfullservices.Receipt, error) {
		r, e := ledger.LoadRecord(context.Background(), tx, f.snap.Approval.DeviceID)
		if e != nil {
			return windowsfullservices.Receipt{}, e
		}
		out, e := ledger.Apply(context.Background(), tx, final, raw, &r, f.at, 0)
		if e != nil {
			return windowsfullservices.Receipt{}, e
		}
		e = ledger.SaveRecord(context.Background(), tx, f.snap.Approval.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r)
		return out, e
	})
	if e == nil || got != (windowsfullservices.Receipt{}) {
		t.Fatal("failed COMMIT leaked receipt", e)
	}
	if _, e = f.apply(t, final, f.at); e != nil {
		t.Fatal("rollback lost pending generation", e)
	}
}
func TestWindowsFullServicesCurrentAuthorityClockAndUsedState(t *testing.T) {
	t.Run("final-clock", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 1, f.at)[0]
		raw, _ := windowsfullservices.EncodeMessage(m)
		calls := 0
		ctx := WithWindowsFullServicesClock(context.Background(), func() time.Time {
			calls++
			if calls >= 2 {
				return time.Unix(f.snap.Intent.NotAfter, 0).UTC()
			}
			return f.at
		})
		got, e := f.s.ApplyWindowsFullServices(WithWindowsFullServicesIngressOrigin(ctx, f.snap.Binding.Origin), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at)
		if e == nil || got != (windowsfullservices.Receipt{}) {
			t.Fatal("late receipt output", e)
		}
		p := f.page(t, fullQuery(), f.at)
		if p.Complete != nil {
			t.Fatal("expired transaction committed")
		}
	})
	t.Run("revocation", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
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
		if got, e := f.apply(t, m, f.at.Add(time.Second)); e == nil || got != (windowsfullservices.Receipt{}) {
			t.Fatal("revoked exact retry", e)
		}
		if p, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, fullQuery(), f.at.Add(time.Second)); e == nil || !reflect.DeepEqual(p, windowsfullservices.Page{}) {
			t.Fatal("revoked page", e)
		}
	})
	t.Run("used-floor-missing", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		if _, e := f.s.db.Exec(`DELETE FROM wfs_authority`); e != nil {
			t.Fatal(e)
		}
		if _, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, fullQuery(), f.at); !errors.Is(e, ErrStorage) {
			t.Fatal("missing used floor adopted", e)
		}
		if e := f.s.InitializeWindowsFullServices(context.Background()); !errors.Is(e, ErrStorage) {
			t.Fatal("missing floor recreated", e)
		}
	})
}
func TestWindowsFullServicesSixSortsAndOriginalExpiry(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2050, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	for _, sort := range []string{"name-asc", "name-desc", "pid-asc", "pid-desc", "state-asc", "state-desc"} {
		q := fullQuery()
		q.Sort = sort
		p := f.page(t, q, f.at)
		want := "InventedService00000"
		if sort == "name-desc" || sort == "pid-desc" {
			want = "InventedService02049"
		}
		if len(p.Rows) != 100 || p.Rows[0].Name != want {
			t.Fatal(sort, "order")
		}
		q.Search = "東京"
		p = f.page(t, q, f.at)
		if p.MatchingCount != 2050 {
			t.Fatal("Unicode literal search")
		}
	}
	q := fullQuery()
	p := f.page(t, q, f.at)
	q.Cursor = p.NextCursor
	if got, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, q, f.at.Add(15*time.Minute)); !errors.Is(e, windowsfullservices.ErrConflict) || !reflect.DeepEqual(got, windowsfullservices.Page{}) {
		t.Fatal("expired cursor returned rows", e)
	}
}
func TestWindowsFullServicesExportPageFixture(t *testing.T) {
	// Typed fixture used by independently validated frontend; never host metadata.
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 3, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	p := f.page(t, fullQuery(), f.at)
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > windowsfullservices.MaxPageBytes {
		t.Fatal(e)
	}
	t.Log(string(raw))
}

func TestWindowsFullServicesExportLargeInteropVectors(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	type vector struct {
		Name  string                    `json:"name"`
		Query windowsfullservices.Query `json:"query"`
		Page  windowsfullservices.Page  `json:"page"`
	}
	vectors := []vector{}
	at := f.at
	failure := windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 1, AttemptedAt: &at, Reason: "access_denied"}
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	q := fullQuery()
	vectors = append(vectors, vector{"unavailable", q, f.page(t, q, at)})
	for _, m := range f.messages(t, 2, 2051, at) {
		if _, e := f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	p := f.page(t, q, at)
	vectors = append(vectors, vector{"first2051", q, p})
	for i := 0; i < 7; i++ {
		q.Cursor = p.NextCursor
		p = f.page(t, q, at)
	}
	if p.Offset != 700 || p.Rows[0].Name != "InventedService00700" {
		t.Fatal("later fixture offset")
	}
	vectors = append(vectors, vector{"offset700", q, p})
	q = fullQuery()
	q.Search = "Dienst 02049 東京"
	p = f.page(t, q, at)
	if p.MatchingCount != 1 {
		t.Fatal("later Unicode fixture search")
	}
	vectors = append(vectors, vector{"unicode2049", q, p})
	failure.Sequence = 3
	if _, e := f.apply(t, failure, at); e != nil {
		t.Fatal(e)
	}
	q = fullQuery()
	vectors = append(vectors, vector{"priorCompleteLatestFailed", q, f.page(t, q, at)})
	rows := make([]windowsfullservices.Row, 128)
	for i := range rows {
		name := strings.Repeat("<", 250) + fmt.Sprintf("%06d", i)
		display := strings.Repeat("<", 256)
		rows[i] = windowsfullservices.Row{Name: name, DisplayName: &display, DisplayNameQuality: "observed", StateQuality: "unavailable", PIDQuality: "unavailable"}
	}
	messages, e := windowsfullservices.Build(f.snap.Approval.DeviceID, f.consent, 4, windowsfullservices.Capture{StartedAt: at, FinishedAt: at, Rows: rows, Complete: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, at); e != nil {
			t.Fatal(e)
		}
	}
	p = f.page(t, q, at)
	if len(p.Rows) >= 100 || len(p.Rows) == 0 || p.NextCursor == "" {
		t.Fatal("byte ceiling page did not shorten")
	}
	vectors = append(vectors, vector{"byteShort", q, p})
	q.Cursor = p.NextCursor
	p = f.page(t, q, at)
	vectors = append(vectors, vector{"byteShortContinuation", q, p})
	raw, e := json.Marshal(vectors)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("WFS_VECTORS_JSON=" + string(raw))
}

func TestWindowsFullServicesQuotaReservationBeforeWriteAndCleanupFloors(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 1, f.at)[0]
	manifest := *m.Manifest
	manifest.RowsBytes = windowsfullservices.MaxSourceBytes
	m.Manifest = &manifest
	m.ManifestSHA256, _ = windowsfullservices.ManifestDigest(manifest)
	if _, e := f.apply(t, m, f.at); !errors.Is(e, windowsfullservices.ErrBudget) {
		t.Fatal("oversized reservation not rejected", e)
	}
	var generations int
	if f.s.db.QueryRow(`SELECT count(*) FROM wfs_generations`).Scan(&generations) != nil || generations != 0 {
		t.Fatal("reservation wrote generation")
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if _, e := f.apply(t, f.messages(t, seq, 0, f.at)[0], f.at); e != nil {
			t.Fatal(e)
		}
	}
	fourth := f.messages(t, 4, 0, f.at)[0]
	if _, e := f.apply(t, fourth, f.at); !errors.Is(e, windowsfullservices.ErrBudget) {
		t.Fatal("generation quota not reserved", e)
	}
	if e := f.s.MaintainWindowsFullServices(context.Background(), f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.apply(t, fourth, f.at); e != nil {
		t.Fatal("quota failure consumed next floor", e)
	}
	for range 4 {
		if e := f.s.MaintainWindowsFullServices(context.Background(), f.at); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.apply(t, f.messages(t, 1, 0, f.at)[0], f.at); !errors.Is(e, windowsfullservices.ErrConflict) {
		t.Fatal("cleanup reset floor", e)
	}
}
func TestWindowsFullServicesBoundedSteadyStateCleanup(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	// This case proves repeated bounded reclamation, not maximum ingest size.
	// 2,051 rows span 17 chunks, crossing both the 256-row and 16-chunk tick
	// limits. CompleteSearchIntegrityBoundedCost retains the 8,192-row boundary.
	for seq := uint64(1); seq <= 4; seq++ {
		at := f.at.Add(time.Duration(seq-1) * time.Minute)
		for _, m := range f.messages(t, seq, 2051, at) {
			if _, e := f.apply(t, m, at); e != nil {
				t.Fatal("capture", seq, e)
			}
		}
		if seq == 1 {
			continue
		}
		var beforeRows, beforeChunks int
		f.s.db.QueryRow(`SELECT count(*) FROM wfs_rows WHERE generation<>?`, f.page(t, fullQuery(), at).Complete.Manifest.GenerationID).Scan(&beforeRows)
		f.s.db.QueryRow(`SELECT count(*) FROM wfs_chunks WHERE generation<>?`, f.page(t, fullQuery(), at).Complete.Manifest.GenerationID).Scan(&beforeChunks)
		if beforeRows <= 256 || beforeChunks <= 16 {
			t.Fatal("fixture must exceed both cleanup tick limits")
		}
		if e := f.s.MaintainWindowsFullServices(context.Background(), at.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		var afterRows, afterChunks int
		f.s.db.QueryRow(`SELECT count(*) FROM wfs_rows WHERE generation<>?`, f.page(t, fullQuery(), at.Add(time.Second)).Complete.Manifest.GenerationID).Scan(&afterRows)
		f.s.db.QueryRow(`SELECT count(*) FROM wfs_chunks WHERE generation<>?`, f.page(t, fullQuery(), at.Add(time.Second)).Complete.Manifest.GenerationID).Scan(&afterChunks)
		if beforeRows-afterRows > 256 || beforeChunks-afterChunks > 16 {
			t.Fatal("cleanup exceeded per-tick bound")
		}
		for i := 2; i <= 33; i++ {
			if e := f.s.MaintainWindowsFullServices(context.Background(), at.Add(time.Duration(i)*time.Second)); e != nil {
				t.Fatal(e)
			}
		}
		var generations int
		if f.s.db.QueryRow(`SELECT count(*) FROM wfs_generations`).Scan(&generations) != nil || generations != 1 {
			t.Fatal("obsolete generations not reclaimed", generations)
		}
	}
}
func TestWindowsFullServicesCrossChunkFoldIdentityAndStagingExpiry(t *testing.T) {
	t.Run("fold", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 129, f.at)
		// Source canonical order remains increasing; Unicode sigma/final-sigma are
		// equivalent SCM identities split across distinct chunks.
		m[0].Rows[127].Name = "ς"
		m[1].Rows[0].Name = "σ"
		if _, e := f.apply(t, m[0], f.at); e != nil {
			t.Fatal(e)
		}
		if _, e := f.apply(t, m[1], f.at); e == nil {
			t.Fatal("casefold alias promoted")
		}
		p := f.page(t, fullQuery(), f.at)
		if p.Complete != nil {
			t.Fatal("duplicate prefix exposed")
		}
	})
	t.Run("staging-expiry", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		m := f.messages(t, 1, 129, f.at)
		if _, e := f.apply(t, m[0], f.at); e != nil {
			t.Fatal(e)
		}
		if _, e := f.apply(t, m[1], f.at.Add(15*time.Minute)); !errors.Is(e, windowsfullservices.ErrExpired) {
			t.Fatal("expired staging promoted", e)
		}
		if e := f.s.MaintainWindowsFullServices(context.Background(), f.at.Add(15*time.Minute)); e != nil {
			t.Fatal(e)
		}
		if _, e := f.apply(t, m[0], f.at.Add(15*time.Minute)); !errors.Is(e, windowsfullservices.ErrConflict) {
			t.Fatal("recreated expired staging", e)
		}
	})
}

func TestWindowsFullServicesTrustedIngressOriginRequiredAndDurable(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer func() { f.s.Close() }()
	origin := "https://agent-ingress.example:8444"
	f.consent.SenderBinding = windowsfullservices.SenderBinding("tls", origin, f.cert.CertificateHash(), f.snap.Approval.DeviceID)
	m := f.scope()
	raw, _ := windowsfullservices.EncodeMessage(m)
	if got, e := f.s.ApplyWindowsFullServices(context.Background(), f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil || got != (windowsfullservices.Receipt{}) {
		t.Fatal("missing trusted origin admitted", e)
	}
	for _, bad := range []string{f.snap.Binding.Origin, "https://agent-ingress.example:8444/", "https://agent-ingress.example:8444?origin=trusted", "http://agent-ingress.example:8444", "https://user@agent-ingress.example:8444"} {
		ctx := WithWindowsFullServicesIngressOrigin(context.Background(), bad)
		if _, e := f.s.ApplyWindowsFullServices(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e == nil {
			t.Fatal("wrong/malformed configured origin admitted", bad)
		}
	}
	ctx := WithWindowsFullServicesIngressOrigin(context.Background(), origin)
	if _, e := f.s.ApplyWindowsFullServices(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal("distinct agent origin rejected", e)
	}
	m = f.messages(t, 1, 1, f.at)[0]
	raw, _ = windowsfullservices.EncodeMessage(m)
	if _, e := f.s.ApplyWindowsFullServices(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, raw, f.at); e != nil {
		t.Fatal(e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	p := f.page(t, fullQuery(), f.at)
	if p.Complete == nil || p.Complete.Manifest.SenderBinding != f.consent.SenderBinding {
		t.Fatal("durable agent origin lost")
	}
	if _, e := f.s.RecheckWindowsFullServices(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e != nil {
		t.Fatal(e)
	}
	changed := WithWindowsFullServicesIngressOrigin(context.Background(), "https://other-ingress.example:8444")
	if _, e := f.s.RecheckWindowsFullServices(changed, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at); e == nil {
		t.Fatal("changed configured origin accepted")
	}
	if _, e := f.s.db.Exec(`UPDATE wfs_authority SET body=CAST(json_remove(body,'$.ingressOrigin') AS BLOB)`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, fullQuery(), f.at); !errors.Is(e, ErrStorage) {
		t.Fatal("missing durable origin reconstructed", e)
	}
}
func TestWindowsFullServicesCompleteSearchIntegrityBoundedCost(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	messages := f.messages(t, 1, 8192, f.at)
	for _, m := range messages {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	q := fullQuery()
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
	if _, e := f.s.db.Exec(`UPDATE wfs_rows SET search='' WHERE ordinal=8191`); e != nil {
		t.Fatal(e)
	}
	if p, e := f.s.WindowsFullServicesPage(context.Background(), f.snap.Approval.DeviceID, q, f.at); e == nil || !reflect.DeepEqual(p, windowsfullservices.Page{}) {
		t.Fatal("late derived corruption concealed by filtering", e)
	}
}

func TestWindowsFullServicesNonUTCSessionExpiryKeepsExactCursorDeadline(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for _, m := range f.messages(t, 1, 2051, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	expiry := f.at.Add(10 * time.Minute).In(time.FixedZone("fixture-local", -4*60*60))
	ctx := WithWindowsFullServicesSession(context.Background(), "fixture-session", expiry, func() bool { return true })
	q := fullQuery()
	first, e := f.s.WindowsFullServicesPage(ctx, f.snap.Approval.DeviceID, q, f.at)
	if e != nil || first.CursorExpiresAt == nil || first.CursorExpiresAt.Location() != time.UTC || !first.CursorExpiresAt.Equal(expiry) || first.NextCursor == "" {
		t.Fatal("session deadline not canonical and exact", e)
	}
	q.Cursor = first.NextCursor
	next, e := f.s.WindowsFullServicesPage(ctx, f.snap.Approval.DeviceID, q, f.at.Add(time.Second))
	if e != nil || next.Offset != 100 || !next.CursorExpiresAt.Equal(expiry) {
		t.Fatal("self-issued local-time cursor rejected or renewed", e)
	}
}
