package enrollmentstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullprocesses"
	processesledger "localrmm/internal/windowsfullprocessesledger"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
)

func processText(s string) *string { return &s }
func processRow(pid, parent, threads uint32, name *string) windowsfullprocesses.Row {
	quality := "unavailable"
	if name != nil {
		quality = "observed"
	}
	return windowsfullprocesses.Row{PID: pid, ParentPID: parent, Threads: threads, Name: name, NameQuality: quality}
}
func (f fullProcessesFixture) capture(t *testing.T, seq uint64, rows []windowsfullprocesses.Row) []windowsfullprocesses.Message {
	t.Helper()
	messages, e := windowsfullprocesses.Build(f.snap.Approval.DeviceID, f.consent, seq, windowsfullprocesses.Capture{StartedAt: f.at, FinishedAt: f.at, Complete: true, Rows: rows})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		if _, e = f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	return messages
}
func TestWindowsFullProcessesNumericSortsZeroMissingNamesAndLiteralSearch(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	f.capture(t, 1, []windowsfullprocesses.Row{
		processRow(0, 0, 0, nil), processRow(2, 9, 12, processText("Same 東京")), processRow(10, 1, 2, processText("Same 東京")), processRow(4294967295, 1, 12, processText("Zed")),
	})
	orders := map[string][]uint32{
		"pid-asc": {0, 2, 10, 4294967295}, "pid-desc": {4294967295, 10, 2, 0},
		"name-asc": {2, 10, 4294967295, 0}, "name-desc": {4294967295, 2, 10, 0},
		"parentPid-asc": {0, 10, 4294967295, 2}, "parentPid-desc": {2, 10, 4294967295, 0},
		"threads-asc": {0, 10, 2, 4294967295}, "threads-desc": {2, 4294967295, 10, 0},
	}
	for sort, want := range orders {
		q := processesQuery()
		q.Sort = sort
		p := f.page(t, q, f.at)
		got := []uint32{}
		for _, row := range p.Rows {
			got = append(got, row.PID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("numeric ordering", sort, got, want)
		}
	}
	for search, count := range map[string]int{"same 東京": 2, "12": 2, "4294967295": 1, "9": 2, "%": 0, "not present": 0} {
		q := processesQuery()
		q.Search = search
		p := f.page(t, q, f.at)
		if p.MatchingCount != count {
			t.Fatal("literal search", search, p.MatchingCount, count)
		}
	}
}
func TestWindowsFullProcessesMissingUsedStateIsNeverRecreated(t *testing.T) {
	for _, kind := range []string{"whole-root", "partial-root", "used-marker"} {
		t.Run(kind, func(t *testing.T) {
			f := newFullProcessesFixture(t, "tls")
			defer f.s.Close()
			f.grant(t)
			switch kind {
			case "whole-root":
				for _, o := range processesledger.SchemaObjects() {
					if o.Type == "table" {
						if _, e := f.s.db.Exec("DROP TABLE " + o.Name); e != nil {
							t.Fatal(e)
						}
					}
				}
			case "partial-root":
				if _, e := f.s.db.Exec("DROP TABLE wfp_rows"); e != nil {
					t.Fatal(e)
				}
			case "used-marker":
				if _, e := f.s.db.Exec(`UPDATE enrollment_credentials SET body=CAST(json_remove(body,'$.windowsFullProcessesInitialized') AS BLOB)`); e != nil {
					t.Fatal(e)
				}
			}
			if e := f.s.InitializeWindowsFullProcesses(context.Background()); !errors.Is(e, ErrStorage) {
				t.Fatal("lost state reconstructed", e)
			}
			p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at)
			if e == nil || !reflect.DeepEqual(p, windowsfullprocesses.Page{}) {
				t.Fatal("lost state disclosed rows", e)
			}
		})
	}
}
func TestWindowsFullProcessesOtherGrantsDoNotPromoteAndFloorsStayIndependent(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	if e := f.s.InitializeWindowsFullSoftware(context.Background()); e != nil {
		t.Fatal(e)
	}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: f.consent.SenderBinding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	sf := fullSoftwareFixture{f.f, f.s, f.path, f.snap, f.cert, f.at, c}
	sf.grant(t)
	sf.capture(t, 1, []windowsfullsoftware.Row{})
	if p := f.page(t, processesQuery(), f.at); p.Status != "not_configured" || p.GrantID != nil {
		t.Fatal("software grant promoted")
	}
	f.grant(t)
	f.capture(t, 1, []windowsfullprocesses.Row{processRow(0, 0, 0, nil)})
	if p := sf.page(t, softwareQuery(), f.at); p.Complete == nil || p.Complete.Manifest.RowCount != 0 {
		t.Fatal("process generation replaced software")
	}
	if p := f.page(t, processesQuery(), f.at); p.Complete == nil || p.Complete.Manifest.RowCount != 1 || p.Rows[0].PID != 0 {
		t.Fatal("independent process floor or PID zero")
	}
}
func TestWindowsFullProcessesReservationsShareAllThreeDomains(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	ctx := context.Background()
	if e := f.s.InitializeWindowsFullSoftware(ctx); e != nil {
		t.Fatal(e)
	}
	if e := f.s.InitializeWindowsFullServices(ctx); e != nil {
		t.Fatal(e)
	}
	sc := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: f.consent.SenderBinding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	base := fullSoftwareFixture{f.f, f.s, f.path, f.snap, f.cert, f.at, sc}
	identities := []fullSoftwareFixture{base}
	for k := 2; k <= 5; k++ {
		identities = append(identities, additionalSoftwareIdentity(t, base, k))
	}
	processes := []fullProcessesFixture{}
	for _, v := range identities {
		c := f.consent
		c.SenderBinding = v.consent.SenderBinding
		p := fullProcessesFixture{v.f, v.s, v.path, v.snap, v.cert, v.at, c}
		p.grant(t)
		processes = append(processes, p)
	}
	reserveProcess := func(v fullProcessesFixture) windowsfullprocesses.Message {
		m := v.messages(t, 1, 129, v.at)[0]
		manifest := *m.Manifest
		manifest.RowsBytes = windowsfullprocesses.MaxSourceBytes
		m.Manifest = &manifest
		m.ManifestSHA256, _ = windowsfullprocesses.ManifestDigest(manifest)
		return m
	}
	for _, v := range processes[:3] {
		if _, e := v.apply(t, reserveProcess(v), v.at); e != nil {
			t.Fatal("process reservation", e)
		}
	}
	software := identities[3]
	software.grant(t)
	m := software.messages(t, 1, 129, software.at)[0]
	manifest := *m.Manifest
	manifest.RowsBytes = 11 << 19
	m.Manifest = &manifest
	m.ManifestSHA256, _ = windowsfullsoftware.ManifestDigest(manifest)
	if _, e := software.apply(t, m, software.at); e != nil {
		t.Fatal("software reservation", e)
	}
	// Ninety-six MiB of processes plus twenty-two MiB software must bind every domain.
	if _, e := processes[4].apply(t, reserveProcess(processes[4]), f.at); !errors.Is(e, windowsfullprocesses.ErrBudget) {
		t.Fatal("process ignored other domain", e)
	}
	lastSoftware := identities[4]
	lastSoftware.grant(t)
	sm := lastSoftware.messages(t, 1, 129, f.at)[0]
	smf := *sm.Manifest
	smf.RowsBytes = 11 << 19
	sm.Manifest = &smf
	sm.ManifestSHA256, _ = windowsfullsoftware.ManifestDigest(smf)
	if _, e := lastSoftware.apply(t, sm, f.at); !errors.Is(e, windowsfullsoftware.ErrBudget) {
		t.Fatal("software ignored processes", e)
	}
	svc := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: lastSoftware.consent.SenderBinding, GrantID: strings.Repeat("e", 32), Revision: 1, Enabled: true, ChangedAt: f.at}
	service := fullServicesFixture{lastSoftware.f, lastSoftware.s, lastSoftware.path, lastSoftware.snap, lastSoftware.cert, lastSoftware.at, svc}
	service.grant(t)
	vm := service.messages(t, 1, 129, f.at)[0]
	vmf := *vm.Manifest
	vmf.RowsBytes = 11 << 19
	vm.Manifest = &vmf
	vm.ManifestSHA256, _ = windowsfullservices.ManifestDigest(vmf)
	if _, e := service.apply(t, vm, f.at); !errors.Is(e, windowsfullservices.ErrBudget) {
		t.Fatal("services ignored processes", e)
	}
	var count int
	if e := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM wfp_generations)+(SELECT count(*) FROM wfw_generations)+(SELECT count(*) FROM wfs_generations)`).Scan(&count); e != nil || count != 4 {
		t.Fatal("rejected staging leaked", count, e)
	}
	if e := f.s.transact(ctx, func(tx *transaction) error {
		r, e := processesledger.LoadRecord(ctx, tx.conn, processes[4].snap.Approval.DeviceID)
		if e != nil {
			return e
		}
		if r.Floor != 0 {
			t.Fatal("quota failure consumed sequence")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestWindowsFullProcessesFailureBeforeCaptureIsUnavailableNotEmpty(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	at := f.at
	m := windowsfullprocesses.Message{SchemaVersion: windowsfullprocesses.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: 1, AttemptedAt: &at, Reason: "access_denied"}
	first, e := f.apply(t, m, f.at)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := f.apply(t, m, f.at)
	if e != nil || retry != first {
		t.Fatal("failure retry", e)
	}
	if p := f.page(t, processesQuery(), f.at); p.Status != "unavailable" || p.Complete != nil || p.LatestAttempt == nil || p.LatestAttempt.Status != "source_failed" {
		t.Fatal("failed snapshot mislabeled empty")
	}
}

func TestWindowsFullProcessesMaximumRows(t *testing.T) {
	t.Run("32768", func(t *testing.T) {
		f := newFullProcessesFixture(t, "tls")
		defer f.s.Close()
		f.grant(t)
		rows := make([]windowsfullprocesses.Row, windowsfullprocesses.MaxRows)
		for i := range rows {
			rows[i] = processRow(uint32(i), 0, 0, nil)
		}
		msgs, e := windowsfullprocesses.Build(f.snap.Approval.DeviceID, f.consent, 1, windowsfullprocesses.Capture{StartedAt: f.at, FinishedAt: f.at, Complete: true, Rows: rows})
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
		ctx := WithWindowsFullProcessesIngressOrigin(context.Background(), f.snap.Binding.Origin)
		e = f.s.transact(ctx, func(tx *transaction) error {
			r, e := processesledger.LoadRecord(ctx, tx.conn, f.snap.Approval.DeviceID)
			if e != nil {
				return e
			}
			for _, message := range msgs[1 : len(msgs)-1] {
				raw, e := windowsfullprocesses.EncodeMessage(message)
				if e != nil {
					return e
				}
				m, e := windowsfullprocesses.DecodeMessage(raw)
				if e != nil {
					return e
				}
				snap, e := f.s.windowsFullProcessesAuthority(tx, f.snap.InvitationID, f.cert.CertificateHash(), f.at)
				if e != nil {
					return e
				}
				if m.DeviceID != snap.Approval.DeviceID || m.Consent != r.Consent || r.IngressOrigin != f.snap.Binding.Origin || r.LastAt.After(f.at) {
					return enrollmentstate.ErrProof
				}
				if e = processesledger.Clock(ctx, tx.conn, f.at); e != nil {
					return e
				}
				extra, e := windowsFullProcessesOtherBytes(ctx, tx)
				if e != nil {
					return e
				}
				if _, e = processesledger.Apply(ctx, tx.conn, m, raw, &r, f.at, extra); e != nil {
					return e
				}
				if e = processesledger.SaveRecord(ctx, tx.conn, m.DeviceID, f.snap.InvitationID, f.cert.CertificateHash(), r); e != nil {
					return e
				}
				if e = windowsFullProcessesBudget(ctx, tx); e != nil {
					return e
				}
			}
			tx.beforeCommit = append(tx.beforeCommit, func() error {
				_, e := f.s.windowsFullProcessesAuthority(tx, f.snap.InvitationID, f.cert.CertificateHash(), f.at)
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
		p := f.page(t, processesQuery(), f.at)
		if p.MatchingCount != 32768 || p.Complete.Manifest.RowCount != 32768 || len(p.Rows) != 100 || msgs[0].Manifest.RowsBytes > windowsfullprocesses.MaxSourceBytes {
			t.Fatal("maximum complete generation rejected")
		}
		q := processesQuery()
		q.Search = "32767"
		q.Sort = "pid-desc"
		p = f.page(t, q, f.at)
		if p.MatchingCount != 1 || p.Rows[0].PID != 32767 {
			t.Fatal("late rows excluded")
		}
	})
}

func TestWindowsFullProcessesSchemaInitializationPreservesOldCredentialAndGrantBytes(t *testing.T) {
	f := newFullSoftwareFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	f.capture(t, 1, []windowsfullsoftware.Row{})
	var beforeCredential, beforeAuthority []byte
	if e := f.s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snap.InvitationID).Scan(&beforeCredential); e != nil {
		t.Fatal(e)
	}
	if e := f.s.db.QueryRow(`SELECT body FROM wfw_authority WHERE device=?`, f.snap.Approval.DeviceID).Scan(&beforeAuthority); e != nil {
		t.Fatal(e)
	}
	if e := f.s.InitializeWindowsFullProcesses(context.Background()); e != nil {
		t.Fatal(e)
	}
	var afterCredential, afterAuthority []byte
	if e := f.s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snap.InvitationID).Scan(&afterCredential); e != nil {
		t.Fatal(e)
	}
	if e := f.s.db.QueryRow(`SELECT body FROM wfw_authority WHERE device=?`, f.snap.Approval.DeviceID).Scan(&afterAuthority); e != nil {
		t.Fatal(e)
	}
	if string(beforeCredential) != string(afterCredential) || string(beforeAuthority) != string(afterAuthority) {
		t.Fatal("process schema promoted or rewrote old credential/grant bytes")
	}
	p, e := f.s.WindowsFullProcessesPage(context.Background(), f.snap.Approval.DeviceID, processesQuery(), f.at)
	if e != nil || p.Status != "not_configured" || p.GrantID != nil {
		t.Fatal("schema initialization granted process access", e)
	}
}
