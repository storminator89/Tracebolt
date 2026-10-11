package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullservices"
	servicesledger "localrmm/internal/windowsfullservicesledger"
	"localrmm/internal/windowsfullsoftware"
	softwareledger "localrmm/internal/windowsfullsoftwareledger"
)

func softwareText(s string) *string { return &s }
func softwareRow(n int, name, version, publisher *string, view string) windowsfullsoftware.Row {
	r := windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", n), RegistryView: view, Name: name, Version: version, Publisher: publisher, NameQuality: "unavailable", VersionQuality: "unavailable", PublisherQuality: "unavailable"}
	if name != nil {
		r.NameQuality = "observed"
	}
	if version != nil {
		r.VersionQuality = "observed"
	}
	if publisher != nil {
		r.PublisherQuality = "observed"
	}
	return r
}
func (f fullSoftwareFixture) capture(t *testing.T, seq uint64, rows []windowsfullsoftware.Row) []windowsfullsoftware.Message {
	t.Helper()
	m, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullsoftware.Capture{StartedAt: f.at, FinishedAt: f.at, Complete: true, Rows: rows})
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range m {
		if _, e = f.apply(t, v, f.at); e != nil {
			t.Fatal(e)
		}
	}
	return m
}
func TestWindowsFullSoftwareEightSortsMissingLastDuplicatesAndSearch(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	rows := []windowsfullsoftware.Row{
		softwareRow(1, softwareText("Same 東京"), softwareText("2"), softwareText("Firma"), "64"),
		softwareRow(2, softwareText("Same 東京"), softwareText("1"), softwareText("Firma"), "32"),
		softwareRow(3, nil, nil, nil, "64"),
		softwareRow(4, softwareText("Zed"), softwareText("3"), softwareText("Zulu"), "32"),
	}
	f.capture(t, 1, rows)
	orders := map[string][]int{"name-asc": {1, 2, 4, 3}, "name-desc": {4, 1, 2, 3}, "version-asc": {2, 1, 4, 3}, "version-desc": {4, 1, 2, 3}, "publisher-asc": {1, 2, 4, 3}, "publisher-desc": {4, 1, 2, 3}, "view-asc": {2, 4, 1, 3}, "view-desc": {1, 3, 2, 4}}
	for sort, want := range orders {
		q := softwareQuery()
		q.Sort = sort
		p := f.page(t, q, f.at)
		for i, n := range want {
			if p.Rows[i].RegistrationID != fmt.Sprintf("%064x", n) {
				t.Fatal("sort", sort, i)
			}
		}
	}
	for search, count := range map[string]int{"same 東京": 2, "fIRma": 2, "32": 2, "3": 2, "not present": 0} {
		q := softwareQuery()
		q.Search = search
		p := f.page(t, q, f.at)
		if p.MatchingCount != count {
			t.Fatal("literal search", search, p.MatchingCount, count)
		}
	}
	// Identity is opaque exact native-key/view identity, never a casefolded label.
	if len(f.page(t, softwareQuery(), f.at).Rows) != 4 {
		t.Fatal("duplicate labels removed")
	}
}
func TestWindowsFullSoftwareMaximumRowsAndByteShortPages(t *testing.T) {
	t.Run("32768", func(t *testing.T) {
		f := newFullSoftwareFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		rows := make([]windowsfullsoftware.Row, windowsfullsoftware.MaxRows)
		for i := range rows {
			rows[i] = softwareRow(i+1, nil, nil, nil, "64")
		}
		msgs, e := windowsfullsoftware.Build(f.snap.Approval.DeviceID, f.consent, 1, windowsfullsoftware.Capture{StartedAt: f.at, FinishedAt: f.at, Complete: true, Rows: rows})
		if e != nil {
			t.Fatal(e)
		}
		// Test-only capacity setup: keep real first/final store admission, but
		// batch middle chunks through the production ledger in one transaction.
		// This retains every row, quota and final digest/page check without
		// repeatedly scanning the growing store. The 2051-row retry/restart
		// tests separately exercise end-to-end per-chunk store admission.
		if _, e = f.apply(t, msgs[0], f.at); e != nil {
			t.Fatal(e)
		}
		ctx := WithWindowsFullSoftwareIngressOrigin(context.Background(), f.snap.Binding.Origin)
		e = f.s.transact(ctx, func(tx *transaction) error {
			r, e := softwareledger.LoadRecord(ctx, tx.conn, f.snap.Approval.DeviceID)
			if e != nil {
				return e
			}
			for _, message := range msgs[1 : len(msgs)-1] {
				raw, e := windowsfullsoftware.EncodeMessage(message)
				if e != nil {
					return e
				}
				m, e := windowsfullsoftware.DecodeMessage(raw)
				if e != nil {
					return e
				}
				snap, e := f.s.windowsFullSoftwareAuthority(tx, f.snap.InvitationID, f.cert.CertificateHash(), f.at)
				if e != nil {
					return e
				}
				if m.DeviceID != snap.Approval.DeviceID || m.Consent != r.Consent || r.IngressOrigin != f.snap.Binding.Origin || r.LastAt.After(f.at) {
					return enrollmentstate.ErrProof
				}
				if e = softwareledger.Clock(ctx, tx.conn, f.at); e != nil {
					return e
				}
				extra, e := windowsFullSoftwareOtherBytes(ctx, tx)
				if e != nil {
					return e
				}
				if _, e = softwareledger.Apply(ctx, tx.conn, m, raw, &r, f.at, extra); e != nil {
					return e
				}
				if e = softwareledger.SaveRecord(ctx, tx.conn, m.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r); e != nil {
					return e
				}
				if e = windowsFullSoftwareBudget(ctx, tx); e != nil {
					return e
				}
			}
			tx.beforeCommit = append(tx.beforeCommit, func() error {
				_, e := f.s.windowsFullSoftwareAuthority(tx, f.snap.InvitationID, f.cert.CertificateHash(), f.at)
				return e
			})
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.apply(t, msgs[len(msgs)-1], f.at); e != nil {
			t.Fatal(e)
		}
		p := f.page(t, softwareQuery(), f.at)
		if p.MatchingCount != 32768 || p.Complete.Manifest.RowCount != 32768 || len(p.Rows) != 100 || msgs[0].Manifest.RowsBytes > windowsfullsoftware.MaxSourceBytes {
			t.Fatal("maximum complete generation rejected")
		}
		q := softwareQuery()
		q.Search = "64"
		q.Sort = "view-desc"
		p = f.page(t, q, f.at)
		if p.MatchingCount != 32768 {
			t.Fatal("late rows excluded")
		}
	})
	t.Run("byte-short", func(t *testing.T) {
		f := newFullSoftwareFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		value := strings.Repeat("<", 512)
		rows := make([]windowsfullsoftware.Row, 128)
		for i := range rows {
			rows[i] = softwareRow(i+1, &value, &value, &value, "64")
		}
		f.capture(t, 1, rows)
		q := softwareQuery()
		seen := 0
		for {
			p := f.page(t, q, f.at)
			raw, _ := json.Marshal(p)
			if len(raw) > windowsfullsoftware.MaxPageBytes || len(p.Rows) == 0 || len(p.Rows) >= 100 || p.Offset != seen {
				t.Fatal("page bytes", len(raw), len(p.Rows), p.Offset, seen)
			}
			seen += len(p.Rows)
			if p.NextCursor == "" {
				break
			}
			q.Cursor = p.NextCursor
		}
		if seen != 128 {
			t.Fatal("byte pagination omitted rows")
		}
	})
}
func TestWindowsFullSoftwareMissingRootUsedMarkerAndGrantIsolation(t *testing.T) {
	for _, kind := range []string{"whole-root", "used-marker", "partial-root"} {
		t.Run(kind, func(t *testing.T) {
			f := newFullSoftwareFixture(t, "tls")
			defer f.s.Close()
			f.grant(t)
			switch kind {
			case "whole-root":
				for _, o := range softwareledger.SchemaObjects() {
					if o.Type == "table" {
						if _, e := f.s.db.Exec("DROP TABLE " + o.Name); e != nil {
							t.Fatal(e)
						}
					}
				}
			case "partial-root":
				if _, e := f.s.db.Exec("DROP TABLE wfw_rows"); e != nil {
					t.Fatal(e)
				}
			case "used-marker":
				if _, e := f.s.db.Exec(`UPDATE enrollment_credentials SET body=CAST(json_remove(body,'$.windowsFullSoftwareInitialized') AS BLOB)`); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.s.InitializeWindowsFullSoftware(context.Background()); !errors.Is(e, ErrStorage) {
				t.Fatal("lost used state recreated", e)
			}
			if p, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at); e == nil || !reflect.DeepEqual(p, windowsfullsoftware.Page{}) {
				t.Fatal("lost state disclosed page", e)
			}
		})
	}
	t.Run("service-is-not-software-consent", func(t *testing.T) {
		f := newFullServicesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		if e := f.s.InitializeWindowsFullSoftware(context.Background()); e != nil {
			t.Fatal(e)
		}
		p, e := f.s.WindowsFullSoftwarePage(context.Background(), f.snap.Approval.DeviceID, softwareQuery(), f.at)
		if e != nil || p.Status != "not_configured" || p.GrantID != nil {
			t.Fatal("service grant promoted", e)
		}
	})
}
func additionalSoftwareIdentity(t *testing.T, base fullSoftwareFixture, k int) fullSoftwareFixture {
	t.Helper()
	v := base.f
	v.requestOffset = k * 100
	v.secret = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(k + 32)}, 32))
	v.challenge.InvitationID = id("invite", k)
	v.challenge.ClaimID = id("claim", k)
	ctx := context.Background()
	create := v.createCommand()
	create.Platform = "windows"
	snap, e := base.s.CreateInvitation(ctx, create)
	if e != nil {
		t.Fatal(e)
	}
	snap, e = base.s.Claim(ctx, enrollmentstate.ClaimCommand{Control: v.control(snap, 2), ClaimID: v.challenge.ClaimID}, v.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	snap, e = base.s.Approve(ctx, enrollmentstate.ApproveCommand{Control: v.control(snap, 3), DeviceID: id("agent", k), KeyFingerprint: snap.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	snap, e = base.s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: v.control(snap, 4), IntentID: id("intent", k), SerialHex: fmt.Sprintf("%032x", k), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := base.s.SigningIntent(ctx, snap.InvitationID, snap.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := v.issue(t, intent)
	snap, e = base.s.CommitIssued(ctx, v.control(snap, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	ctl := v.control(snap, 6)
	snap, e = base.s.Activate(ctx, ctl, v.activation(t, cert, ctl))
	if e != nil {
		t.Fatal(e)
	}
	c := base.consent
	c.SenderBinding = windowsfullsoftware.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID)
	return fullSoftwareFixture{v, base.s, base.path, snap, cert, base.at, c}
}
func TestWindowsFullSoftwareAndServicesShareAdmissionAndTransactionCap(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	ctx := context.Background()
	if e := f.s.InitializeWindowsFullServices(ctx); e != nil {
		t.Fatal(e)
	}
	identities := []fullSoftwareFixture{f}
	for k := 2; k <= 5; k++ {
		identities = append(identities, additionalSoftwareIdentity(t, f, k))
	}
	serviceFixtures := make([]fullServicesFixture, len(identities))
	for i, v := range identities {
		v.grant(t)
		sc := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: v.consent.SenderBinding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: v.at}
		serviceFixtures[i] = fullServicesFixture{v.f, v.s, v.path, v.snap, v.cert, v.at, sc}
		serviceFixtures[i].grant(t)
	}
	softwareReservation := func(v fullSoftwareFixture) windowsfullsoftware.Message {
		m := v.messages(t, 1, 129, v.at)[0]
		manifest := *m.Manifest
		manifest.RowsBytes = windowsfullsoftware.MaxSourceBytes
		m.Manifest = &manifest
		m.ManifestSHA256, _ = windowsfullsoftware.ManifestDigest(manifest)
		return m
	}
	serviceReservation := func(v fullServicesFixture) windowsfullservices.Message {
		m := v.messages(t, 1, 129, v.at)[0]
		manifest := *m.Manifest
		manifest.RowsBytes = 11 << 19
		m.Manifest = &manifest
		m.ManifestSHA256, _ = windowsfullservices.ManifestDigest(manifest)
		return m
	}
	// Three 32 MiB software reservations plus a 22 MiB service reservation.
	for _, v := range identities[:3] {
		if _, e := v.apply(t, softwareReservation(v), v.at); e != nil {
			t.Fatal("software reserve", e)
		}
	}
	if _, e := serviceFixtures[3].apply(t, serviceReservation(serviceFixtures[3]), f.at); e != nil {
		t.Fatal("service reserve", e)
	}
	// Neither domain may treat the other's reserved bytes as free global space.
	if _, e := identities[4].apply(t, softwareReservation(identities[4]), f.at); !errors.Is(e, windowsfullsoftware.ErrBudget) {
		t.Fatal("software cross-domain cap", e)
	}
	if _, e := serviceFixtures[4].apply(t, serviceReservation(serviceFixtures[4]), f.at); !errors.Is(e, windowsfullservices.ErrBudget) {
		t.Fatal("service cross-domain cap", e)
	}
	var count int
	f.s.db.QueryRow(`SELECT (SELECT count(*) FROM wfw_generations)+(SELECT count(*) FROM wfs_generations)`).Scan(&count)
	if count != 4 {
		t.Fatal("refused admission staged data", count)
	}
	// Both full transaction validators see the same global overage; no budget recursion.
	e := f.s.transact(ctx, func(tx *transaction) error {
		if _, e := tx.conn.ExecContext(ctx, `UPDATE wfw_generations SET reserved_bytes=reserved_bytes+? WHERE device=?`, 11<<20, f.snap.Approval.DeviceID); e != nil {
			return e
		}
		if e := validateWindowsFullSoftwareState(ctx, tx, f.s.config.Binding.CollectionProfile); !errors.Is(e, windowsfullsoftware.ErrBudget) {
			t.Fatal("software transaction omitted services", e)
		}
		if e := validateWindowsFullServicesState(ctx, tx, f.s.config.Binding.CollectionProfile); !errors.Is(e, windowsfullservices.ErrBudget) {
			t.Fatal("services transaction omitted software", e)
		}
		return nil
	})
	if !errors.Is(e, windowsfullservices.ErrBudget) {
		t.Fatal("commit admitted combined overage", e)
	}
	// Rollback preserves independent floors and original reservations.
	if e = f.s.transact(ctx, func(tx *transaction) error {
		r, e := softwareledger.LoadRecord(ctx, tx.conn, identities[4].snap.Approval.DeviceID)
		if e != nil {
			return e
		}
		sr, e := servicesledger.LoadRecord(ctx, tx.conn, identities[4].snap.Approval.DeviceID)
		if e != nil {
			return e
		}
		if r.Floor != 0 || sr.Floor != 0 {
			t.Fatal("rejected cap consumed a floor")
		}
		return nil
	}); e != nil {
		t.Fatal("quota rollback", e)
	}
}

func TestWindowsFullSoftwareCleanupPreservesFloorsAndOriginalExpiry(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	for seq := uint64(1); seq <= 3; seq++ {
		f.capture(t, seq, []windowsfullsoftware.Row{})
	}
	fourth := f.messages(t, 4, 0, f.at)[0]
	if _, e := f.apply(t, fourth, f.at); !errors.Is(e, windowsfullsoftware.ErrBudget) {
		t.Fatal("generation cap", e)
	}
	if e := f.s.MaintainWindowsFullSoftware(context.Background(), f.at); e != nil {
		t.Fatal(e)
	}
	if _, e := f.apply(t, fourth, f.at); e != nil {
		t.Fatal("maintenance did not reclaim", e)
	}
	if _, e := f.apply(t, f.messages(t, 1, 0, f.at)[0], f.at); !errors.Is(e, windowsfullsoftware.ErrConflict) {
		t.Fatal("cleanup reset floor", e)
	}
	// Cursor deadlines are fixed independently of subsequent requests.
	q := softwareQuery()
	p := f.page(t, q, f.at)
	if p.CursorExpiresAt == nil || !p.CursorExpiresAt.Equal(f.at.Add(15*time.Minute)) {
		t.Fatal("cursor deadline")
	}
}
