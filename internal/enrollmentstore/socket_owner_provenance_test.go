package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
)

func socketOwnerSourceFixture(at time.Time) systeminventory.SocketOwnerProvenance {
	return systeminventory.SocketOwnerProvenance{SchemaVersion: systeminventory.SocketOwnerSourceVersion, Scope: systeminventory.SocketOwnerSourceScope, GrantEpoch: strings.Repeat("1", 64), PolicyDigest: strings.Repeat("2", 64), AuthorityRevision: strings.Repeat("3", 64), ContextID: strings.Repeat("4", 64), StartedAt: at.Add(time.Second), FinishedAt: at.Add(2 * time.Second)}
}
func socketOwnerSourceRaw(t *testing.T, seq uint64, snapshot systeminventory.Snapshot, source systeminventory.SocketOwnerProvenance) []byte {
	t.Helper()
	raw, err := systemwire.EncodeSocketOwners(seq, snapshot, source, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSocketOwnerProvenanceRetainedIndependentlyAndFallbackClears(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 123456789).UTC()
	first := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	first.DurationMS = 2000
	p := socketOwnerSourceFixture(at)
	raw := socketOwnerSourceRaw(t, 1, first, p)
	receipt, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, p.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	retry, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
	if err != nil || retry != receipt {
		t.Fatal("exact reopened source retry changed", err)
	}
	view, err := s.SystemView(ctx, snap.Approval.DeviceID, at.Add(3*time.Minute))
	if err != nil || view.Latest == nil || !equalSocketOwnerProvenance(view.Latest.SocketOwnerProvenance, &p) || !equalSocketOwnerProvenance(view.LastComplete.Sockets.SocketOwnerProvenance, &p) || view.LastComplete.Services.SocketOwnerProvenance != nil || view.LastComplete.Sockets.Status != "stale" {
		t.Fatal("source/age missing on reopen", err)
	}
	page, err := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "sockets", GenerationID: first.GenerationID, Limit: 1}, at.Add(3*time.Minute))
	if err != nil || page.NextCursor == "" || !equalSocketOwnerProvenance(page.SocketOwnerProvenance, &p) {
		t.Fatal("source page", err)
	}
	page, err = s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "sockets", GenerationID: first.GenerationID, Limit: 1, Cursor: page.NextCursor}, at.Add(3*time.Minute))
	if err != nil || !page.Exhausted || !equalSocketOwnerProvenance(page.SocketOwnerProvenance, &p) {
		t.Fatal("source continuation", err)
	}
	// An ordinary failed attempt carries no source and cannot clear prior rows.
	secondAt := at.Add(4 * time.Minute)
	second := systeminventory.Empty(mustSystemGeneration(t, snap.Approval.DeviceID, 2), secondAt, systeminventory.ReasonTimeout)
	saveSystemFixture(t, s, snap, cert, 2, second, secondAt)
	view, err = s.SystemView(ctx, snap.Approval.DeviceID, secondAt)
	if err != nil || view.Latest.SocketOwnerProvenance != nil || !equalSocketOwnerProvenance(view.LastComplete.Sockets.SocketOwnerProvenance, &p) {
		t.Fatal("failed ordinary attempt adopted or lost source", err)
	}
	// A further failed generation and restart must still retain the original
	// complete source, without borrowing the later batch's clock/duration.
	thirdAt := at.Add(5 * time.Minute)
	third := systeminventory.Empty(mustSystemGeneration(t, snap.Approval.DeviceID, 3), thirdAt, systeminventory.ReasonReadFailed)
	third.DurationMS = 5000
	saveSystemFixture(t, s, snap, cert, 3, third, thirdAt)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	view, err = s.SystemView(ctx, snap.Approval.DeviceID, thirdAt)
	if err != nil || view.Latest.SocketOwnerProvenance != nil || !equalSocketOwnerProvenance(view.LastComplete.Sockets.SocketOwnerProvenance, &p) || !view.LastComplete.Sockets.Meta.ObservedAt.Equal(at) {
		t.Fatal("failed source relabeled retained observation", err)
	}
	// A new ordinary complete generation owns its own rows and clears the marker.
	fourthAt := at.Add(6 * time.Minute)
	fourth := systemFixtureSnapshot(t, snap.Approval.DeviceID, 4, 0, fourthAt)
	saveSystemFixture(t, s, snap, cert, 4, fourth, fourthAt)
	view, err = s.SystemView(ctx, snap.Approval.DeviceID, fourthAt)
	if err != nil || view.Latest.SocketOwnerProvenance != nil || view.LastComplete.Sockets.SocketOwnerProvenance != nil {
		t.Fatal("ordinary complete inherited helper claim", err)
	}
	page, err = s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "sockets", GenerationID: fourth.GenerationID, Limit: 10}, fourthAt)
	if err != nil || page.SocketOwnerProvenance != nil {
		t.Fatal("fallback page inherited source", err)
	}
	if err = s.transact(ctx, func(tx *transaction) error {
		r := tx.system[snap.InvitationID]
		if r.Sockets.SocketOwnerBatchDurationMS != nil || tx.credentials[snap.InvitationID].Replay.Sequence != 0 || len(tx.inventory) != 0 {
			t.Fatal("fallback retained source bounds or changed other floors")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func mustSystemGeneration(t *testing.T, device string, seq uint64) string {
	t.Helper()
	id, err := systemwire.GenerationID(device, seq)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSocketOwnerProvenanceRejectsInvalidWithoutAdvancingFloor(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	base := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	saveSystemFixture(t, s, snap, cert, 1, base, at)
	at = at.Add(time.Second)
	next := systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 1, at)
	next.DurationMS = 2000
	p := socketOwnerSourceFixture(at)
	raw := socketOwnerSourceRaw(t, 2, next, p)
	for name, bad := range map[string][]byte{
		"unknown":         bytes.Replace(raw, []byte(`"contextId":`), []byte(`"privileged":true,"contextId":`), 1),
		"invalid context": bytes.Replace(raw, []byte(p.ContextID), []byte(strings.Repeat("0", 64)), 1),
		"old schema":      bytes.Replace(raw, []byte(systemwire.SocketOwnerFrameVersion), []byte(systemwire.FrameVersion), 1),
		"future schema":   bytes.Replace(raw, []byte(systemwire.SocketOwnerFrameVersion), []byte("tracebolt.agent-system-inventory.v5"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), bad, p.FinishedAt); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
	failed := systeminventory.Empty(next.GenerationID, next.CollectedAt, systeminventory.ReasonReadFailed)
	failed.DurationMS = next.DurationMS
	failedRaw, _ := json.Marshal(systemwire.Frame{SchemaVersion: systemwire.SocketOwnerFrameVersion, Sequence: 2, Snapshot: failed, SocketOwnerProvenance: &p})
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), failedRaw, p.FinishedAt); err == nil {
		t.Fatal("tagged failed source admitted")
	}
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, at); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("future helper completion accepted", err)
	}
	view, err := s.SystemView(ctx, snap.Approval.DeviceID, p.FinishedAt)
	if err != nil || *view.Sequence != 1 || view.Latest.SocketOwnerProvenance != nil {
		t.Fatal("rejected source changed prior state", err)
	}
	if _, err = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, p.FinishedAt); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(p.ContextID), []byte(strings.Repeat("5", 64)), 1)
	if _, err = s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), changed, p.FinishedAt); !errors.Is(err, ErrSystemConflict) {
		t.Fatal("changed marker replay accepted", err)
	}
}

func TestSocketOwnerProvenanceDurableMetadataRejectsCorruptionAndOldReaderLoss(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	first := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	first.DurationMS = 2000
	p := socketOwnerSourceFixture(at)
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), socketOwnerSourceRaw(t, 1, first, p), p.FinishedAt); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_system_authority WHERE invitation_id=?`, snap.InvitationID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*systemRecord){
		"missing retained marker": func(r *systemRecord) {
			r.Sockets.SocketOwnerProvenance = nil
			r.Sockets.SocketOwnerBatchDurationMS = nil
		},
		"changed retained source": func(r *systemRecord) {
			copy := *r.Sockets.SocketOwnerProvenance
			copy.ContextID = strings.Repeat("5", 64)
			r.Sockets.SocketOwnerProvenance = &copy
		},
		"short retained batch":   func(r *systemRecord) { n := int64(1); r.Sockets.SocketOwnerBatchDurationMS = &n },
		"missing retained bound": func(r *systemRecord) { r.Sockets.SocketOwnerBatchDurationMS = nil },
		"service source": func(r *systemRecord) {
			r.Services.SocketOwnerProvenance = &p
			n := int64(2000)
			r.Services.SocketOwnerBatchDurationMS = &n
		},
		"latest source future": func(r *systemRecord) { r.Latest.SocketOwnerProvenance.FinishedAt = at.Add(3 * time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			var record systemRecord
			if json.Unmarshal(original, &record) != nil {
				t.Fatal("fixture")
			}
			change(&record)
			bad, _ := json.Marshal(record)
			if _, err := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, bad, snap.InvitationID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SystemView(ctx, snap.Approval.DeviceID, p.FinishedAt); !errors.Is(err, ErrStorage) {
				t.Fatal("source corruption tolerated", err)
			}
			if _, err := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, original, snap.InvitationID); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Emulate the previous exact-shape reader: ignored new metadata makes its
	// canonical roundtrip differ, so its existing equality guard fails closed.
	type legacyMeta struct {
		SchemaVersion string                      `json:"schemaVersion"`
		GenerationID  string                      `json:"generationId"`
		CollectedAt   time.Time                   `json:"collectedAt"`
		DurationMS    int64                       `json:"durationMs"`
		Scope         string                      `json:"scope"`
		Services      systeminventory.SectionMeta `json:"services"`
		Sockets       systeminventory.SectionMeta `json:"sockets"`
	}
	type legacyComplete struct {
		Sequence     uint64                      `json:"sequence"`
		Meta         systeminventory.SectionMeta `json:"meta"`
		PayloadBytes int                         `json:"payloadBytes"`
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(original, &fields)
	for _, name := range []string{"latest", "sockets"} {
		var canonical []byte
		if name == "latest" {
			var old legacyMeta
			_ = json.Unmarshal(fields[name], &old)
			canonical, _ = json.Marshal(old)
		} else {
			var old legacyComplete
			_ = json.Unmarshal(fields[name], &old)
			canonical, _ = json.Marshal(old)
		}
		if bytes.Equal(canonical, fields[name]) {
			t.Fatal("old reader could silently erase marker")
		}
	}
}

func TestSocketOwnerProvenanceCleanupKeepsFloorAndOriginalIntervals(t *testing.T) {
	_, s, _, snap, cert := systemLongFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	first := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 0, at)
	first.DurationMS = 2000
	p := socketOwnerSourceFixture(at)
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), socketOwnerSourceRaw(t, 1, first, p), p.FinishedAt); err != nil {
		t.Fatal(err)
	}
	later := at.Add(5 * time.Minute)
	second := systeminventory.Empty(mustSystemGeneration(t, snap.Approval.DeviceID, 2), later, systeminventory.ReasonTimeout)
	second.DurationMS = 2000
	raw := systemRaw(t, 2, second)
	receipt, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, later)
	if err != nil {
		t.Fatal(err)
	}
	cleanAt := at.Add(SystemRetention)
	clean, err := s.SystemCleanup(ctx, snap.Approval.DeviceID, cleanAt)
	if err != nil || clean.ClearedSections != 2 || clean.ClearedLatest {
		t.Fatal("independent source retention", clean, err)
	}
	view, err := s.SystemView(ctx, snap.Approval.DeviceID, cleanAt)
	if err != nil || view.LastComplete.Sockets != nil || view.Latest == nil || view.Latest.SocketOwnerProvenance != nil {
		t.Fatal("cleanup relabeled latest source", err)
	}
	cleanAt = later.Add(SystemRetention)
	clean, err = s.SystemCleanup(ctx, snap.Approval.DeviceID, cleanAt)
	if err != nil || !clean.ClearedLatest {
		t.Fatal("source latest expiry", clean, err)
	}
	retry, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, cleanAt)
	if err != nil || retry != receipt {
		t.Fatal("cleanup changed exact floor", err)
	}
	view, err = s.SystemView(ctx, snap.Approval.DeviceID, cleanAt)
	if err != nil || view.Latest != nil || view.LastComplete.Sockets != nil || *view.Sequence != 2 {
		t.Fatal("cleanup revived expired source", err)
	}
}

// Logs only synthetic source/view/page fixtures for strict consumers. No raw
// host telemetry or credential bytes are part of this evidence.
func TestSocketOwnerProvenanceJSONFixtures(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 123456789).UTC()
	snapshot := systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 1, at)
	snapshot.DurationMS = 2000
	name := "fixture-server"
	snapshot.Sockets.Items[0].Owners = []systeminventory.Owner{{PID: 42, ProcessName: &name, NameReason: systeminventory.ReasonNone}}
	snapshot.Sockets.Items[0].Attribution = systeminventory.Attribution{Coverage: systeminventory.AttributionObserved, Reason: systeminventory.ReasonNone}
	p := socketOwnerSourceFixture(at)
	raw := socketOwnerSourceRaw(t, 1, snapshot, p)
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), raw, p.FinishedAt); err != nil {
		t.Fatal(err)
	}
	view, err := s.SystemView(ctx, snap.Approval.DeviceID, p.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.SystemPage(ctx, snap.Approval.DeviceID, SystemPageRequest{Section: "sockets", GenerationID: snapshot.GenerationID, Limit: 100}, p.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	pageDTO := struct {
		SchemaVersion     string    `json:"schemaVersion"`
		DeviceID          string    `json:"deviceId"`
		CollectionProfile string    `json:"collectionProfile"`
		ServerNow         time.Time `json:"serverNow"`
		SystemPageResult
	}{"tracebolt.system-inventory-page.v1", snap.Approval.DeviceID, snap.Binding.CollectionProfile, p.FinishedAt, page}
	viewJSON, _ := json.Marshal(view)
	pageJSON, _ := json.Marshal(pageDTO)
	t.Logf("fixture_frame=%s", raw)
	t.Logf("fixture_view=%s", viewJSON)
	t.Logf("fixture_page=%s", pageJSON)
}
