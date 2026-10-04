package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
)

func systemFixtureSnapshot(t testing.TB, device string, seq uint64, n int, at time.Time) systeminventory.Snapshot {
	t.Helper()
	generation, e := systemwire.GenerationID(device, seq)
	if e != nil {
		t.Fatal(e)
	}
	s := systeminventory.Empty(generation, at, systeminventory.ReasonReadFailed)
	services := make([]systeminventory.Service, n)
	enabled := "enabled"
	for i := range services {
		services[i] = systeminventory.Service{Name: fmt.Sprintf("fixture-%05d.service", i), Enablement: &enabled}
	}
	count := uint64(n)
	s.Services = systeminventory.ServiceSection{Meta: systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}, Items: services}
	socketCount := uint64(2)
	s.Sockets = systeminventory.SocketSection{Meta: systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &socketCount, CountExact: true}, Items: []systeminventory.Socket{
		{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: 8080}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionUnavailable, Reason: systeminventory.ReasonPermissionDenied}},
		{Protocol: "udp", Family: "ipv4", Kind: "bound", Local: systeminventory.Endpoint{Address: "0.0.0.0", Port: 1234}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "bound", Owners: []systeminventory.Owner{}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionUnavailable, Reason: systeminventory.ReasonNoMatch}},
	}}
	if e = systeminventory.Validate(s); e != nil {
		t.Fatal(e)
	}
	return s
}
func systemRaw(t testing.TB, seq uint64, snapshot systeminventory.Snapshot) []byte {
	t.Helper()
	raw, e := systemwire.Encode(seq, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func saveSystemFixture(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, seq uint64, snapshot systeminventory.Snapshot, now time.Time) systemwire.Receipt {
	t.Helper()
	r, e := s.SaveSystemObservation(context.Background(), snap.InvitationID, cert.CertificateHash(), systemRaw(t, seq, snapshot), now)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestSystemObservationExactReplayReopenAndIndependentFloor(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 4, at)
	raw := systemRaw(t, 1, snapshot)
	receipt, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
	if e != nil {
		t.Fatal(e)
	}
	// An exact stale retry returns exactly the original response, not a duplicate
	// bit or refreshed receipt. Whitespace is still part of the exact body digest.
	retry, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
	if e != nil || retry != receipt {
		t.Fatalf("retry changed: %+v %v", retry, e)
	}
	alternate := append([]byte(" \n"), raw...)
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), alternate, at.Add(3*time.Minute)); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("changed exact body accepted", e)
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snap.InvitationID].Replay.Sequence != 0 || len(tx.inventory) != 0 {
			t.Fatal("system write advanced other replay domain")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	retry, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(4*time.Minute))
	if e != nil || retry != receipt {
		t.Fatal("reopened replay changed", e)
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, at.Add(4*time.Minute))
	if e != nil || view.Status != "stale" || view.Latest == nil || view.LastComplete.Services == nil || view.Sequence == nil || *view.Sequence != 1 {
		t.Fatalf("bad view %+v %v", view, e)
	}
	if view.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		t.Fatal("wrong profile")
	}
	rawView, _ := json.Marshal(view)
	if !bytes.Contains(rawView, []byte(`"sequence":"1"`)) {
		t.Fatal("sequence not string")
	}
}

func TestSystemObservationFreshnessAndBinding(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		delta time.Duration
		want  bool
	}{{"future", time.Nanosecond, false}, {"too old", -SystemMaxAge - time.Nanosecond, false}, {"boundary", -SystemMaxAge, true}} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 0, at.Add(tc.delta))
			_, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 1, snapshot), at)
			if (e == nil) != tc.want {
				t.Fatal(e)
			}
		})
	}
	second := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 0, at.Add(-SystemMaxAge))
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, second), at); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("collection time did not advance", e)
	}
	second = systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 0, at)
	wrong := strings.Repeat("1", 64)
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, wrong, systemRaw(t, 2, second), at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("wrong leaf accepted", e)
	}
	// Independent generation derivation is checked against authoritative identity.
	foreign := systemFixtureSnapshot(t, "agent_"+strings.Repeat("f", 32), 2, 0, at)
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, foreign), at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("foreign generation accepted", e)
	}
}

func TestSystemObservationLastCompleteSectionsKeepOriginalAge(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	first := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at)
	saveSystemFixture(t, s, snap, cert, 1, first, at)
	nextAt := at.Add(3 * time.Minute)
	second := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, nextAt)
	failed := systeminventory.Empty(second.GenerationID, nextAt, systeminventory.ReasonPermissionDenied)
	second.Services = failed.Services
	saveSystemFixture(t, s, snap, cert, 2, second, nextAt)
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, nextAt)
	if e != nil {
		t.Fatal(e)
	}
	if view.Status != "fresh" || view.Latest.Services.Coverage != systeminventory.Failed || view.Latest.Services.ObservedCount != nil || view.LastComplete.Services.Status != "stale" || view.LastComplete.Services.Meta.GenerationID != first.GenerationID || !view.LastComplete.Services.Meta.ObservedAt.Equal(at) || view.LastComplete.Sockets.Meta.GenerationID != second.GenerationID {
		t.Fatalf("failed source relabeled old data %+v", view)
	}
	page, e := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "services", GenerationID: first.GenerationID, Limit: 10}, nextAt)
	if e != nil || page.TotalRows != 3 || page.Status != "stale" || len(page.Services) != 3 {
		t.Fatalf("old complete disappeared %+v %v", page, e)
	}
	if _, e = s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "sockets", GenerationID: first.GenerationID, Limit: 10}, nextAt); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("replaced generation silently selected", e)
	}
}

func TestSystemObservationPaginationSearchFiltersAndCursorBinding(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3000, at)
	active := systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}
	failed := systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "failed", SubState: "failed"}
	snapshot.Services.Items[3].Runtime = &active
	snapshot.Services.Items[4].Runtime = &failed
	saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
	req := SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Search: "fixture-02999", Limit: 100, Filter: "all"}
	page, e := s.SystemPage(ctx, snap.Approval.DeviceID, req, at)
	if e != nil || page.Exhausted || page.ReturnedCount != 0 || page.ScannedCount != 2048 || page.NextCursor == "" || page.CursorExpiresAt == nil {
		t.Fatalf("bounded continuation %+v %v", page, e)
	}
	original := page.NextCursor
	req.Cursor = original
	next, e := s.SystemPage(ctx, snap.Approval.DeviceID, req, at.Add(time.Second))
	if e != nil || !next.Exhausted || next.ReturnedCount != 1 || next.Services[0].Name != "fixture-02999.service" {
		t.Fatalf("search prefix lost %+v %v", next, e)
	}
	for _, mutate := range []func(*SystemPageRequest){func(r *SystemPageRequest) { r.Search = "fixture-00001" }, func(r *SystemPageRequest) { r.Limit = 50 }, func(r *SystemPageRequest) { r.Filter = "enabled" }, func(r *SystemPageRequest) { r.Cursor = original[:len(original)-1] + "!" }} {
		bad := req
		mutate(&bad)
		if _, e = s.SystemPage(ctx, snap.Approval.DeviceID, bad, at.Add(time.Second)); !errors.Is(e, ErrSystemCursor) {
			t.Fatal("unbound cursor accepted", e)
		}
	}
	if _, e = s.SystemPage(ctx, snap.Approval.DeviceID, req, at.Add(SystemCursorTTL)); !errors.Is(e, ErrSystemCursorExpired) {
		t.Fatal("expired cursor", e)
	}
	req = SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Limit: 100}
	var all []systeminventory.Service
	for {
		p, e := s.SystemPage(ctx, snap.Approval.DeviceID, req, at)
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, p.Services...)
		if p.Exhausted {
			break
		}
		req.Cursor = p.NextCursor
	}
	if !reflect.DeepEqual(all, snapshot.Services.Items) {
		t.Fatal("page omissions/order/duplicates")
	}
	for _, tc := range []struct {
		section, filter string
		want            int
	}{{"services", "active", 1}, {"services", "failed", 1}, {"sockets", "tcp-listeners", 1}, {"sockets", "udp", 1}, {"sockets", "connections", 0}} {
		req = SystemPageRequest{Section: tc.section, GenerationID: snapshot.GenerationID, Filter: tc.filter, Limit: 100}
		n := 0
		for {
			p, e := s.SystemPage(ctx, snap.Approval.DeviceID, req, at)
			if e != nil {
				t.Fatal(e)
			}
			n += p.ReturnedCount
			if p.Exhausted {
				break
			}
			req.Cursor = p.NextCursor
		}
		if n != tc.want {
			t.Fatalf("filter %s got %d", tc.filter, n)
		}
	}
}

func TestSystemObservationCleanupPreservesFloorReceiptAndAuthority(t *testing.T) {
	f, s, path, snap, cert := systemLongFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 3, at)
	receipt := saveSystemFixture(t, s, snap, cert, 2, snapshot, at)
	raw := systemRaw(t, 2, snapshot)
	now := at.Add(SystemRetention)
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, now)
	if e != nil || view.Status != "expired" || view.Latest != nil || view.LastComplete.Services != nil {
		t.Fatalf("expired data visible %+v %v", view, e)
	}
	if _, e = s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Limit: 100}, now); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("expired page not conflict", e)
	}
	clean, e := s.SystemCleanup(ctx, snap.Approval.DeviceID, now)
	if e != nil || !clean.ClearedLatest || clean.ClearedSections != 2 {
		t.Fatal(clean, e)
	}
	var rows int
	if s.db.QueryRow(`SELECT count(*) FROM enrollment_system_rows`).Scan(&rows) != nil || rows != 0 {
		t.Fatal("cleanup leaked rows")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	again, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, now.Add(time.Second))
	if e != nil || again != receipt {
		t.Fatal("cleanup erased receipt", e)
	}
	lower := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, now)
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 1, lower), now); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("cleanup reset floor", e)
	}
	changed := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, now)
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, changed), now); !errors.Is(e, ErrSystemConflict) {
		t.Fatal("cleanup allowed sequence rebind", e)
	}
	newer := systemFixtureSnapshot(t, snap.Approval.DeviceID, 3, 1, now.Add(time.Second))
	saveSystemFixture(t, s, snap, cert, 3, newer, now.Add(time.Second))
	// Revocation cannot be bypassed even for the last exact frame.
	revoke := control(snap, 7)
	revoke.Now = now.Add(time.Second).Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 3, newer), now.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked exact retry accepted", e)
	}
	view, e = s.SystemView(ctx, snap.Approval.DeviceID, now.Add(2*time.Second))
	if e != nil || view.Status != "revoked" || view.Latest != nil || view.LastComplete.Services != nil {
		t.Fatalf("revocation view %+v %v", view, e)
	}
}

func TestSystemObservationTargetLazyCorruptionIsNotHealthyEmpty(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	ctx := context.Background()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at)
	saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
	if _, e := s.db.Exec(`UPDATE enrollment_system_rows SET body=? WHERE invitation_id=? AND section='services' AND ordinal=1`, []byte(`{"name":"tampered"}`), snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path) // reopen restores metadata, not all endpoint rows
	if _, e := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "services", GenerationID: snapshot.GenerationID, Limit: 100}, at); !errors.Is(e, ErrStorage) {
		t.Fatal("corruption became empty healthy page", e)
	}
	// Unrelated ordinary authority reads remain bounded and do not decode rows.
	if _, e := s.DeviceViews(ctx); e != nil {
		t.Fatal("ordinary authority parsed rows", e)
	}
}

func systemLongFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	ctx := context.Background()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	f.challenge.CollectionProfile = f.config.Binding.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	path := filepath.Join(t.TempDir(), "private", "system.sqlite")
	s := f.open(t, path)
	snap, e := s.CreateInvitation(ctx, f.createCommand())
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: control(snap, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: control(snap, 3), DeviceID: id("agent", 1), KeyFingerprint: snap.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	snap, e = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: control(snap, 4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 3*86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := s.SigningIntent(ctx, snap.InvitationID, snap.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := f.issue(t, intent)
	snap, e = s.CommitIssued(ctx, control(snap, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	c := control(snap, 6)
	snap, e = s.Activate(ctx, c, f.activation(t, cert, c))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, cert
}

func TestSystemObservationCrossHandleAuthorityAndFloor(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	other := f.open(t, path)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	first := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	saveSystemFixture(t, s, snap, cert, 1, first, at)
	// An unrelated, later package clock must never reject an independently fresh
	// system report with an earlier collection/receipt time.
	binding, manifest, chunks := completeGeneration(t, snap.Approval.DeviceID, 9, 1, at.Add(30*time.Second))
	promoteComplete(t, s, snap, cert, binding, manifest, chunks, at.Add(30*time.Second))
	next := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	saveSystemFixture(t, other, snap, cert, 2, next, at.Add(time.Second))
	for _, store := range []*Store{s, other} {
		view, e := store.SystemView(ctx, snap.Approval.DeviceID, at.Add(2*time.Second))
		if e != nil || view.Sequence == nil || *view.Sequence != 2 {
			t.Fatal("second handle cached authority", e)
		}
	}
	revoke := control(snap, 70)
	revoke.Now = at.Add(31 * time.Second).Unix()
	if _, e := other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, next), at.Add(32*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revocation stale cache accepted", e)
	}
	if _, e := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "services", GenerationID: next.GenerationID, Limit: 1}, at.Add(32*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked page served", e)
	}
	clean, e := s.SystemCleanup(ctx, snap.Approval.DeviceID, at.Add(SystemRetention+time.Minute))
	if e != nil || clean.ClearedSections != 2 {
		t.Fatal("revocation stranded expired storage", clean, e)
	}
}

func TestSystemObservationInvalidBodyDoesNotAdvanceAndLegacyCannotWrite(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
	next := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	raw := systemRaw(t, 2, next)
	cases := [][]byte{append([]byte(nil), raw...), []byte(`{"schemaVersion":"tracebolt.agent-system-inventory.v1","sequence":"2","sequence":"3","snapshot":{}}`), bytes.Repeat([]byte(" "), systemwire.MaxBodyBytes+1)}
	cases[0] = bytes.Replace(cases[0], []byte(`"coverage":"complete"`), []byte(`"coverage":"truncated"`), 1)
	for _, raw := range cases {
		if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(time.Second)); e == nil {
			t.Fatal("invalid body accepted")
		}
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, at.Add(time.Second))
	if e != nil || view.Sequence == nil || *view.Sequence != 1 {
		t.Fatal("rejected body advanced floor", e)
	}
	_, legacy, _ := fixtureStore(t)
	if _, e := legacy.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("legacy profile gained system collection", e)
	}
	var tables int
	if legacy.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_system_%'`).Scan(&tables) != nil || tables != 0 {
		t.Fatal("legacy schema changed")
	}
}

func TestSystemObservationMetadataCorruptionAndExactAdmission(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at)
	saveSystemFixture(t, s, snap, cert, 1, snapshot, at)
	var raw []byte
	if s.db.QueryRow(`SELECT body FROM enrollment_system_authority WHERE invitation_id=?`, snap.InvitationID).Scan(&raw) != nil {
		t.Fatal("read")
	}
	var record systemRecord
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("decode")
	}
	record.Latest = nil
	bad, _ := json.Marshal(record)
	if _, e := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, bad, snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(e, ErrStorage) {
		t.Fatal("metadata corruption became unknown", e)
	}
	if _, e := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, raw, snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	// Ingestion checks exact normalized lengths/counts even for a retained failed
	// section that is not being replaced by the incoming complete counterpart.
	if _, e := s.db.Exec(`DELETE FROM enrollment_system_rows WHERE invitation_id=? AND section='services' AND ordinal=1`, snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	next := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	failure := systeminventory.Empty(next.GenerationID, next.CollectedAt, systeminventory.ReasonReadFailed)
	next.Services = failure.Services
	if _, e := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), systemRaw(t, 2, next), next.CollectedAt); !errors.Is(e, ErrStorage) {
		t.Fatal("incorrect persisted count admitted", e)
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, at.Add(time.Second))
	if e != nil || *view.Sequence != 1 || view.LastComplete.Sockets.Meta.GenerationID != snapshot.GenerationID {
		t.Fatal("failed admission partially committed", e)
	}
}

func TestSystemObservationConcurrentExactSequenceConflictIsAtomic(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	other := f.open(t, path)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	a := systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at))
	b := systemRaw(t, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 4, at))
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, store := range []*Store{s, other} {
		raw := a
		if i == 1 {
			raw = b
		}
		go func(store *Store, raw []byte) {
			<-start
			_, e := store.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at)
			results <- e
		}(store, raw)
	}
	close(start)
	success, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			success++
		} else if errors.Is(e, ErrSystemConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success %d conflicts %d", success, conflicts)
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, at)
	if e != nil {
		t.Fatal(e)
	}
	page, e := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "services", GenerationID: view.Latest.GenerationID, Limit: 100}, at)
	if e != nil || !page.Exhausted || (page.TotalRows != 3 && page.TotalRows != 4) || uint64(len(page.Services)) != page.TotalRows {
		t.Fatalf("mixed/partial commit %+v %v", page, e)
	}
}

func TestSystemObservationSectionByteCeilingIsAtomic(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	initial := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 3, at)
	saveSystemFixture(t, s, snap, cert, 1, initial, at)
	oversized := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, at.Add(time.Second))
	row := oversized.Services.Items[0]
	oversized.Services.Items = make([]systeminventory.Service, 7000)
	for i := range oversized.Services.Items {
		row.Name = fmt.Sprintf("fixture-%05d.service", i)
		oversized.Services.Items[i] = row
	}
	count := uint64(len(oversized.Services.Items))
	oversized.Services.Meta.ObservedCount = &count
	section, _ := json.Marshal(oversized.Services)
	if len(section) <= systeminventory.MaxSectionBytes {
		t.Fatal("fixture not over section ceiling")
	}
	raw, e := json.Marshal(systemwire.Frame{SchemaVersion: systemwire.FrameVersion, Sequence: 2, Snapshot: oversized})
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) > systemwire.MaxBodyBytes {
		t.Fatal("fixture exceeded envelope before section ceiling")
	}
	if _, e = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, oversized.CollectedAt); e == nil {
		t.Fatal("oversized section accepted")
	}
	view, e := s.SystemView(ctx, snap.Approval.DeviceID, oversized.CollectedAt)
	if e != nil || view.Sequence == nil || *view.Sequence != 1 || *view.LastComplete.Services.Meta.ObservedCount != 3 {
		t.Fatal("rejection changed retained state", e)
	}
}
