package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

func completeIncidentOpen(t *testing.T, s *Store) (windowsservicehealth.Input, WindowsCompleteIncidentTarget) {
	t.Helper()
	ctx := context.Background()
	in := completeStoredInput()
	if _, err := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 0, contactAt); err != nil {
		t.Fatal(err)
	}
	for sec := 0; sec <= 180; sec += 30 {
		now := contactAt.Add(time.Duration(sec) * time.Second)
		if sec == 180 {
			p := &in.Sample.Complete.Source
			p.Sequence++
			p.CapturedAt, p.CaptureFinishedAt, p.ReceivedAt = now, now, now
			p.ExpiresAt = now.Add(windowsfullservices.Retention)
			p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
		}
		if _, err := s.EvaluateWindowsService(ctx, in, now, contactEpoch); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || len(v.CompleteTargets()) != 1 || len(v.Targets()) != 0 {
		t.Fatal("complete episode must remain separate from v1 targets", err)
	}
	for _, target := range v.CompleteTargets() {
		return in, target
	}
	t.Fatal("missing complete target")
	return in, WindowsCompleteIncidentTarget{}
}

func completeIncidentAckRaw(t *testing.T, s *Store, key string) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.QueryRow("SELECT body FROM windows_complete_incident_acknowledgements WHERE key=?", key).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsCompleteIncidentSourceNamespaceDurabilityAndIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "complete-inbox.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	in, target := completeIncidentOpen(t, s)
	before := serviceHealthRaw(t, s, in.DeviceID)
	at := contactAt.Add(240 * time.Second)
	legacyTarget := target.WindowsIncidentTarget
	legacyTarget.Domain = "service"
	legacyAck := WindowsIncidentAcknowledgement{Version: 1, Target: legacyTarget, AcknowledgedAt: at}
	legacyRaw, _ := json.Marshal(legacyAck)
	if _, err = s.db.Exec("INSERT INTO windows_incident_acknowledgements(key,body) VALUES(?,?)", legacyTarget.Key(), legacyRaw); err != nil {
		t.Fatal(err)
	}
	v, err := s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || len(v.Acknowledgements) != 1 || len(v.CompleteAcknowledgements) != 0 || target.Key() == legacyTarget.Key() {
		t.Fatal("old acknowledgement crossed the source namespace", err)
	}
	canonicalTarget, _ := json.Marshal(target)
	wantKey := sha256.Sum256(append([]byte("tracebolt.windows-incident-target.v2\x00"), canonicalTarget...))
	if target.Key() != hex.EncodeToString(wantKey[:]) || !bytes.Contains(canonicalTarget, []byte(`"domain":"service-complete"`)) || bytes.Contains(canonicalTarget, []byte(`"WindowsIncidentTarget"`)) {
		t.Fatal("target is not the flattened canonical v2 namespace")
	}
	ack, err := s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil })
	if err != nil || ack.Version != 2 {
		t.Fatal(err)
	}
	ackRaw := completeIncidentAckRaw(t, s, target.Key())
	again, err := s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return at.Add(60 * 24 * time.Hour) }, func(time.Time) error { return nil })
	if err != nil || again != ack || !bytes.Equal(ackRaw, completeIncidentAckRaw(t, s, target.Key())) || !bytes.Equal(before, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("retained acknowledgement refreshed, aged out or changed source bytes", err)
	}
	var afterLegacy []byte
	if err = s.db.QueryRow("SELECT body FROM windows_incident_acknowledgements WHERE key=?", legacyTarget.Key()).Scan(&afterLegacy); err != nil || !bytes.Equal(legacyRaw, afterLegacy) {
		t.Fatal("complete acknowledgement changed or pruned old v1 metadata", err)
	}
	for _, table := range []string{"health_devices", "health_analyses", "alarm_outbox"} {
		var n int
		if err = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("acknowledgement entered Linux domain", table, err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	v, err = s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || v.CompleteAcknowledgements[target.Key()] != ack || !bytes.Equal(before, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("restart/read modified retained evidence or acknowledgement", err)
	}
}

func TestWindowsCompleteIncidentTargetUsesOpeningGrant(t *testing.T) {
	s := contactStore(t)
	ctx := context.Background()
	in, target := completeIncidentOpen(t, s)
	p := &in.Sample.Complete.Source
	p.GrantID = strings.Repeat("c", 32)
	p.GrantRevision++
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, p.Sequence)
	in.Selection = p
	if _, err := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 1, contactAt.Add(210*time.Second)); err != nil {
		t.Fatal(err)
	}
	v, err := s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || v.CompleteTargets()[target.Key()] != target || v.Services[in.DeviceID].Policy.Source.GrantID == target.Source.GrantID {
		t.Fatal("historical target followed current policy grant", err)
	}
	for _, mutate := range []func(*WindowsCompleteIncidentTarget){
		func(v *WindowsCompleteIncidentTarget) { v.Domain = "service" },
		func(v *WindowsCompleteIncidentTarget) { v.Source.Kind = "windows_services" },
		func(v *WindowsCompleteIncidentTarget) { v.Source.GrantID = strings.Repeat("d", 32) },
		func(v *WindowsCompleteIncidentTarget) { v.Source.GrantRevision++ },
		func(v *WindowsCompleteIncidentTarget) { v.Source.GrantRevision = 0 },
		func(v *WindowsCompleteIncidentTarget) { v.Source.GrantRevision = windowsfullservices.MaxSequence + 1 },
		func(v *WindowsCompleteIncidentTarget) { v.CertificateHash = strings.Repeat("4", 64) },
		func(v *WindowsCompleteIncidentTarget) { v.InvitationID = "invite_" + strings.Repeat("4", 32) },
		func(v *WindowsCompleteIncidentTarget) { v.IncidentID = "wservice_0000000000000002" },
		func(v *WindowsCompleteIncidentTarget) { v.OpenedAt = v.OpenedAt.Add(time.Second) },
	} {
		wrong := target
		mutate(&wrong)
		if _, err = s.AcknowledgeWindowsCompleteIncident(ctx, wrong, func() time.Time { return contactAt.Add(240 * time.Second) }, func(time.Time) error { return nil }); !errors.Is(err, ErrWindowsIncident) {
			t.Fatal("nonretained/source-mismatched target accepted", wrong, err)
		}
	}
	if _, err = s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return contactAt.Add(240 * time.Second) }, func(time.Time) error { return nil }); err != nil {
		t.Fatal("closed retained opening grant lost acknowledgement eligibility", err)
	}
	// A constructed snapshot also cannot admit malformed opening provenance.
	st := v.Services[in.DeviceID]
	st.Incidents[0].OpeningObservation.Source = nil
	v.Services[in.DeviceID] = st
	if len(v.CompleteTargets()) != 0 {
		t.Fatal("missing opening source promoted")
	}
}

func TestWindowsCompleteIncidentCanonicalCorruption(t *testing.T) {
	s := contactStore(t)
	_, target := completeIncidentOpen(t, s)
	ack := WindowsCompleteIncidentAcknowledgement{Version: 2, Target: target, AcknowledgedAt: contactAt.Add(240 * time.Second)}
	raw, _ := json.Marshal(ack)
	if _, err := decodeWindowsCompleteIncidentAcknowledgement(target.Key(), raw); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"whitespace":       append(append([]byte{}, raw...), ' '),
		"unknown-field":    bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"extra":true`), 1),
		"duplicate-field":  bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		"old-version":      bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":1`), 1),
		"old-domain":       bytes.Replace(raw, []byte(`"service-complete"`), []byte(`"service"`), 1),
		"wrong-source":     bytes.Replace(raw, []byte(`"windows_full_services"`), []byte(`"windows_services"`), 1),
		"uppercase-grant":  bytes.Replace(raw, []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("A", 32)), 1),
		"zero-revision":    bytes.Replace(raw, []byte(`"grantRevision":1`), []byte(`"grantRevision":0`), 1),
		"offset-timestamp": bytes.Replace(raw, []byte(`Z"`), []byte(`+00:00"`), 1),
		"oversized":        append(append([]byte{}, raw...), bytes.Repeat([]byte(" "), 2048)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeWindowsCompleteIncidentAcknowledgement(target.Key(), bad); !errors.Is(err, ErrWindowsIncident) {
				t.Fatal("noncanonical acknowledgement accepted", err)
			}
		})
	}
	if _, err := decodeWindowsCompleteIncidentAcknowledgement(strings.Repeat("0", 64), raw); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("mismatched key accepted", err)
	}
	corrupt := append(append([]byte{}, raw...), ' ')
	if _, err := s.db.Exec("INSERT INTO windows_complete_incident_acknowledgements(key,body) VALUES(?,?)", target.Key(), corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WindowsCompleteIncidentSnapshot(context.Background()); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("corrupt metadata returned as empty success", err)
	}
	if _, err := s.AcknowledgeWindowsCompleteIncident(context.Background(), target, func() time.Time { return ack.AcknowledgedAt }, func(time.Time) error { return nil }); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("corrupt metadata overwritten", err)
	}
	if !bytes.Equal(corrupt, completeIncidentAckRaw(t, s, target.Key())) {
		t.Fatal("corrupt metadata repaired")
	}
}

func TestWindowsCompleteIncidentOrphansPruneOnlyOnExplicitAck(t *testing.T) {
	s := contactStore(t)
	_, target := completeIncidentOpen(t, s)
	ctx := context.Background()
	at := contactAt.Add(240 * time.Second)
	orphan := target
	orphan.Source.GrantRevision++
	raw, _ := json.Marshal(WindowsCompleteIncidentAcknowledgement{Version: 2, Target: orphan, AcknowledgedAt: at})
	if _, err := s.db.Exec("INSERT INTO windows_complete_incident_acknowledgements(key,body) VALUES(?,?)", orphan.Key(), raw); err != nil {
		t.Fatal(err)
	}
	v, err := s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || len(v.CompleteAcknowledgements) != 1 || !bytes.Equal(raw, completeIncidentAckRaw(t, s, orphan.Key())) {
		t.Fatal("read pruned orphan", err)
	}
	before := serviceHealthRaw(t, s, target.DeviceID)
	calls := 0
	_, err = s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return at }, func(time.Time) error {
		calls++
		if calls == 2 {
			return ErrWindowsIncident
		}
		return nil
	})
	if !errors.Is(err, ErrWindowsIncident) || !bytes.Equal(raw, completeIncidentAckRaw(t, s, orphan.Key())) {
		t.Fatal("failed final guard committed orphan pruning", err)
	}
	v, err = s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || len(v.CompleteAcknowledgements) != 1 || !bytes.Equal(before, serviceHealthRaw(t, s, target.DeviceID)) {
		t.Fatal("failed final guard committed acknowledgement or source state", err)
	}
	if _, err = s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil }); err != nil {
		t.Fatal(err)
	}
	v, err = s.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil || len(v.CompleteAcknowledgements) != 1 || v.CompleteAcknowledgements[target.Key()].Target != target {
		t.Fatal("explicit acknowledgement did not prune only orphan metadata", err)
	}
}

func TestWindowsCompleteIncidentSQLWaitAndFinalClockGuards(t *testing.T) {
	for _, phase := range []string{"after-sql-wait", "final-expiry", "clock-rollback", "before-stamp-rollback", "idempotent-final-guard"} {
		t.Run(phase, func(t *testing.T) {
			s := contactStore(t)
			_, target := completeIncidentOpen(t, s)
			before := serviceHealthRaw(t, s, target.DeviceID)
			ctx := context.Background()
			at := contactAt.Add(240 * time.Second)
			var expired atomic.Bool
			samples, guards := 0, 0
			clock := func() time.Time {
				samples++
				if phase == "clock-rollback" && samples == 3 || phase == "before-stamp-rollback" && samples == 2 {
					return at.Add(-time.Second)
				}
				if phase == "final-expiry" && samples == 3 {
					return at.Add(time.Second)
				}
				return at
			}
			guard := func(now time.Time) error {
				guards++
				if expired.Load() || !now.Before(at.Add(time.Second)) || phase == "idempotent-final-guard" && guards == 2 {
					return ErrWindowsIncident
				}
				return nil
			}
			wantCount := 0
			var retained []byte
			if phase == "idempotent-final-guard" {
				if _, err := s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return at }, func(time.Time) error { return nil }); err != nil {
					t.Fatal(err)
				}
				wantCount = 1
				retained = completeIncidentAckRaw(t, s, target.Key())
			}
			var err error
			if phase == "after-sql-wait" {
				conn, e := s.db.Conn(ctx)
				if e != nil {
					t.Fatal(e)
				}
				waits := s.db.Stats().WaitCount
				done := make(chan error, 1)
				go func() {
					_, e := s.AcknowledgeWindowsCompleteIncident(ctx, target, clock, guard)
					done <- e
				}()
				deadline := time.Now().Add(5 * time.Second)
				for s.db.Stats().WaitCount == waits && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if s.db.Stats().WaitCount == waits {
					conn.Close()
					t.Fatal("acknowledgement did not wait for SQLite")
				}
				expired.Store(true)
				conn.Close()
				err = <-done
			} else {
				_, err = s.AcknowledgeWindowsCompleteIncident(ctx, target, clock, guard)
			}
			if !errors.Is(err, ErrWindowsIncident) {
				t.Fatal("failed live guard or clock rollback accepted", err)
			}
			v, err := s.WindowsCompleteIncidentSnapshot(ctx)
			if err != nil || len(v.CompleteAcknowledgements) != wantCount || !bytes.Equal(before, serviceHealthRaw(t, s, target.DeviceID)) || wantCount == 1 && !bytes.Equal(retained, completeIncidentAckRaw(t, s, target.Key())) {
				t.Fatal("failed guard changed durable state", err)
			}
		})
	}
}

func TestWindowsCompleteIncidentAcknowledgementBound(t *testing.T) {
	s := contactStore(t)
	_, target := completeIncidentOpen(t, s)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 1; i <= MaxWindowsCompleteInboxIncidents+1; i++ {
		orphan := target
		orphan.IncidentID = fmt.Sprintf("wservice_%016x", i)
		raw, _ := json.Marshal(WindowsCompleteIncidentAcknowledgement{Version: 2, Target: orphan, AcknowledgedAt: contactAt.Add(240 * time.Second)})
		if _, err = tx.ExecContext(ctx, "INSERT INTO windows_complete_incident_acknowledgements(key,body) VALUES(?,?)", orphan.Key(), raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WindowsCompleteIncidentSnapshot(ctx); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("unbounded complete acknowledgement table accepted", err)
	}
	if _, err = s.AcknowledgeWindowsCompleteIncident(ctx, target, func() time.Time { return contactAt.Add(240 * time.Second) }, func(time.Time) error { return nil }); !errors.Is(err, ErrWindowsIncident) {
		t.Fatal("overflow was silently repaired", err)
	}
	if MaxWindowsCompleteInboxIncidents != 2500 || MaxWindowsInboxIncidents != 12500 {
		t.Fatal("complete source created a sixth ledger family")
	}
}
