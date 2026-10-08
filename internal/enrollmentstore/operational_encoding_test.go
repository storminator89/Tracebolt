package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestOperationalSaveReencodesMutationAfterLoad(t *testing.T) {
	_, s, _, identity, cert := operationalFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	raw, _ := operationalFrame(t, 1, at, true)
	if _, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		t.Helper()
		var raw []byte
		if err := s.db.QueryRow(`SELECT body FROM enrollment_operational WHERE invitation_id=?`, identity.InvitationID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := read()
	const changedName = "changed-longer-fixture.service"
	if err := s.transact(ctx, func(tx *transaction) error {
		tx.operational[identity.InvitationID].LastGood.Services.Items[0].Name = changedName
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after := read()
	var saved operationalRecord
	if bytes.Equal(before, after) || len(after) <= len(before) || json.Unmarshal(after, &saved) != nil || saved.LastGood.Services.Items[0].Name != changedName {
		t.Fatal("save reused pre-action encoded bytes")
	}
	// Fresh encoding must not bypass validation of the mutated record.
	if err := s.transact(ctx, func(tx *transaction) error {
		tx.operational[identity.InvitationID].LastGood.Services.Items[0].Name = "invalid/unit.service"
		return nil
	}); !errors.Is(err, ErrStorage) {
		t.Fatal("invalid post-load mutation accepted", err)
	}
	if !bytes.Equal(after, read()) {
		t.Fatal("rejected mutation changed durable record")
	}
	// Each load must reread and reject noncanonical stored bytes.
	if _, err := s.db.Exec(`UPDATE enrollment_operational SET body=? WHERE invitation_id=?`, append(after, ' '), identity.InvitationID); err != nil {
		t.Fatal(err)
	}
	if err := s.transact(ctx, func(*transaction) error { return nil }); !errors.Is(err, ErrStorage) {
		t.Fatal("noncanonical stored bytes accepted", err)
	}
}

func TestOperationalSaveChecksQuotaAfterRetainedOnlyMutation(t *testing.T) {
	_, s, _, identity, cert := operationalFixture(t)
	ctx := context.Background()
	samples := budgetOperationalSamples(t)
	for i, sample := range samples {
		raw := budgetOperationalFrame(t, uint64(i+1), budgetDeviceSample(sample, 1, uint64(i+1)))
		if _, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, sample.CollectedAt); err != nil {
			t.Fatal(err)
		}
	}
	var before []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_operational WHERE invitation_id=?`, identity.InvitationID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if budgetJSONSize(t, samples[5])+len(before) != OperationalDeviceQuota {
		t.Fatal("fixture did not reach exact quota")
	}
	err := s.transact(ctx, func(tx *transaction) error {
		record := tx.operational[identity.InvitationID]
		// One additional decimal digit is valid metadata but exceeds the exact
		// logical quota. The accepted frame remains unchanged during this action.
		value := uint64(10)
		record.LastGood.Network.Items[0].RXBytes = &value
		if validateLastGood(record.LastGood, samples[5].CollectedAt) != nil || budgetJSONSize(t, record) != len(before)+1 {
			t.Fatal("retained-only mutation must be valid and exactly one byte larger")
		}
		tx.operational[identity.InvitationID] = record
		return nil
	})
	if !errors.Is(err, ErrStorage) {
		t.Fatal("save used pre-mutation quota bytes", err)
	}
	var after []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_operational WHERE invitation_id=?`, identity.InvitationID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("quota rejection changed durable retained bytes")
	}
}
