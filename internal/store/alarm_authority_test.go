package store

import (
	"context"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/operatorauth"
	"strings"
	"testing"
	"time"
)

func TestAlarmTestAuthorityPersistsAcrossRestartAndCannotRetag(t *testing.T) {
	s, path := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	actor := "operator_00000000000000000000000000000001"
	ctx := operatorauth.WithApprovalEpoch(context.Background(), 7)
	request := strings.Repeat("a", 32)
	result, err := s.EnqueueAlarmTest(ctx, alarmBinding, request, actor, alarmEpoch)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []struct {
		actor string
		epoch uint64
	}{{actor, 8}, {"operator_00000000000000000000000000000002", 7}} {
		if _, err := s.EnqueueAlarmTest(operatorauth.WithApprovalEpoch(context.Background(), other.epoch), alarmBinding, request, other.actor, alarmEpoch); err == nil {
			t.Fatal("old test request retagged")
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.ConfigureAlarms(context.Background(), &alarmBinding, alarmEpoch); err != nil {
		t.Fatal(err)
	}
	attempt, err := reopened.ClaimAlarm(context.Background(), alarmBinding, alarmEpoch)
	if err != nil || attempt == nil || attempt.Payload.EventID != result.EventID || !attempt.OperatorTest || attempt.TestActor != actor || attempt.AuthorityEpoch != 7 {
		t.Fatal("original test receipt lost on restart", err)
	}
	if err = reopened.CompleteAlarm(context.Background(), alarmBinding, *attempt, alarmdelivery.Result{Outcome: alarmdelivery.Failed, Code: "operator_authority_revoked"}, alarmEpoch); err != nil {
		t.Fatal(err)
	}
	status, err := reopened.LatestAlarmTest(context.Background(), alarmBinding)
	if err != nil || status.State != "failed" {
		t.Fatal("denied test not terminal", err)
	}
	if again, err := reopened.ClaimAlarm(context.Background(), alarmBinding, alarmEpoch.Add(time.Minute)); err != nil || again != nil {
		t.Fatal("denied test retried", err)
	}
}

func TestAlarmLegacyTestReceiptRemainsUnbound(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	result, err := s.EnqueueAlarmTest(context.Background(), alarmBinding, strings.Repeat("a", 32), "shared-administrator", alarmEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`DELETE FROM alarm_test_authority WHERE event_id=?`, result.EventID); err != nil {
		t.Fatal(err)
	}
	attempt, err := s.ClaimAlarm(context.Background(), alarmBinding, alarmEpoch)
	if err != nil || attempt == nil || !attempt.OperatorTest || attempt.AuthorityEpoch != 0 || attempt.TestActor != "" {
		t.Fatal("legacy receipt silently promoted", err)
	}
}

func TestAlarmTestReceiptCascadePreservesBound(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	result, err := s.EnqueueAlarmTest(context.Background(), alarmBinding, strings.Repeat("a", 32), "shared-administrator", alarmEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`DELETE FROM alarm_outbox WHERE id=?`, result.EventID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM alarm_test_authority`).Scan(&count); err != nil || count != 0 {
		t.Fatal("test metadata outlived bounded outbox", err)
	}
}
