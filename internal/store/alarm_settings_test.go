package store

import (
	"context"
	"fmt"
	"localrmm/internal/alarmdelivery"
	"strings"
	"testing"
	"time"
)

func TestAlarmSyntheticTestOutboxDedupLimitsAndNoHealth(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	ctx := context.Background()
	id := strings.Repeat("a", 32)
	test, e := s.EnqueueAlarmTest(ctx, alarmBinding, id, "shared-administrator", alarmEpoch)
	if e != nil || test.State != "queued" {
		t.Fatal(test, e)
	}
	again, e := s.EnqueueAlarmTest(ctx, alarmBinding, id, "shared-administrator", alarmEpoch.Add(time.Hour))
	if e != nil || *again != *test {
		t.Fatal("test repeated")
	}
	if _, e = s.EnqueueAlarmTest(ctx, alarmBinding, strings.Repeat("b", 32), "shared-administrator", alarmEpoch.Add(time.Minute)); e != alarmdelivery.ErrTestLimited {
		t.Fatal("outstanding test limit", e)
	}
	a, e := s.ClaimAlarm(ctx, alarmBinding, alarmEpoch)
	if e != nil || a == nil || !alarmdelivery.IsTestPayload(a.Payload) {
		t.Fatal("fixed synthetic job needs no health record", a, e)
	}
	if e = s.CompleteAlarm(ctx, alarmBinding, *a, alarmdelivery.Result{Outcome: alarmdelivery.Accepted, Code: "provider_accepted"}, alarmEpoch); e != nil {
		t.Fatal(e)
	}
	got, e := s.LatestAlarmTest(ctx, alarmBinding)
	if e != nil || got.State != "provider_accepted" {
		t.Fatal(got, e)
	}
	if _, e = s.EnqueueAlarmTest(ctx, alarmBinding, strings.Repeat("b", 32), "shared-administrator", alarmEpoch.Add(time.Second)); e != alarmdelivery.ErrTestLimited {
		t.Fatal("minute limit", e)
	}
	other := alarmBinding
	other.Generation = "two"
	if e = s.ConfigureAlarms(ctx, &other, alarmEpoch); e != nil {
		t.Fatal(e)
	}
	if _, e = s.EnqueueAlarmTest(ctx, other, strings.Repeat("b", 32), "shared-administrator", alarmEpoch.Add(time.Second)); e != alarmdelivery.ErrTestLimited {
		t.Fatal("destination change bypassed minute limit", e)
	}
	if _, e = s.EnqueueAlarmTest(ctx, other, strings.Repeat("b", 32), "shared-administrator", alarmEpoch.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	st, _ := s.AlarmStatus(ctx)
	if st.ProviderAccepted != 1 || st.Queued != 1 {
		t.Fatal("test not visible in aggregate", st)
	}
}
func TestAlarmSyntheticTestRestartDisableAndUncertainty(t *testing.T) {
	for _, op := range []string{"disable", "replace", "restart", "uncertain", "retry"} {
		t.Run(op, func(t *testing.T) {
			s, _ := alarmStore(t)
			configureAlarm(t, s, &alarmBinding)
			ctx := context.Background()
			if _, e := s.EnqueueAlarmTest(ctx, alarmBinding, strings.Repeat("a", 32), "shared-administrator", alarmEpoch); e != nil {
				t.Fatal(e)
			}
			switch op {
			case "disable":
				configureAlarm(t, s, nil)
			case "replace":
				other := alarmBinding
				other.Generation = "two"
				configureAlarm(t, s, &other)
			case "restart":
				if a := alarmClaim(t, s, 0); a == nil {
					t.Fatal("claim")
				}
				configureAlarm(t, s, &alarmBinding)
			case "uncertain":
				a := alarmClaim(t, s, 0)
				alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Uncertain, Code: "provider_uncertain"}, 0)
			case "retry":
				a := alarmClaim(t, s, 0)
				alarmComplete(t, s, a, alarmdelivery.Result{Outcome: alarmdelivery.Retryable, Code: "dns_failed"}, 0)
				if a = alarmClaim(t, s, 59); a != nil {
					t.Fatal("retry before due")
				}
				a = alarmClaim(t, s, 60)
				if a == nil || a.Number != 2 {
					t.Fatal("bounded definite retry lost")
				}
				return
			}
			if a := alarmClaim(t, s, 120); a != nil {
				t.Fatal("suppressed or uncertain test replayed")
			}
			v, e := s.LatestAlarmTest(ctx, alarmBinding)
			want := "suppressed"
			if op == "restart" || op == "uncertain" {
				want = "uncertain"
			}
			if e != nil || v.State != want {
				t.Fatal(v, e)
			}
		})
	}
}
func TestAlarmSettingsAuditBoundedAndRedacted(t *testing.T) {
	s, _ := alarmStore(t)
	ctx := context.Background()
	for i := 0; i < 210; i++ {
		if e := s.ConfigureAlarmsAudited(ctx, &alarmBinding, alarmdelivery.SettingsAudit{Revision: fmt.Sprintf("%032x", i), Actor: "shared-administrator", Action: "replace", At: alarmEpoch.Add(time.Duration(i) * time.Second)}, alarmEpoch.Add(time.Duration(i)*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := s.db.QueryRow(`SELECT count(*) FROM alarm_config_audit`).Scan(&count); e != nil || count != 200 {
		t.Fatal(count, e)
	}
	for _, actor := range []string{"", "https://receiver.example.test/secret", "operator_00000000000000000000000000000000"} {
		if e := s.ConfigureAlarmsAudited(ctx, &alarmBinding, alarmdelivery.SettingsAudit{Revision: strings.Repeat("f", 32), Actor: actor, Action: "replace", At: alarmEpoch}, alarmEpoch); e == nil {
			t.Fatal("untrusted audit actor")
		}
	}
	if e := s.ConfigureAlarmsAudited(ctx, &alarmBinding, alarmdelivery.SettingsAudit{Revision: strings.Repeat("f", 32), Actor: "shared-administrator", Action: "https://receiver.example.test/secret", At: alarmEpoch}, alarmEpoch); e == nil {
		t.Fatal("arbitrary audit action")
	}
	var actor, action string
	if e := s.db.QueryRow(`SELECT actor,action FROM alarm_config_audit LIMIT 1`).Scan(&actor, &action); e != nil || actor != "shared-administrator" || action != "replace" {
		t.Fatal(actor, action, e)
	}
}
func TestAlarmSyntheticTestRejectsMalformedQueuePayload(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	ctx := context.Background()
	test, e := s.EnqueueAlarmTest(ctx, alarmBinding, strings.Repeat("a", 32), "shared-administrator", alarmEpoch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`UPDATE alarm_outbox SET body=json_set(body,'$.deviceId',?) WHERE id=?`, "real-device", test.EventID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ClaimAlarm(ctx, alarmBinding, alarmEpoch); e != alarmdelivery.ErrInvalid {
		t.Fatal("test path accepted arbitrary payload", e)
	}
}
func TestAlarmSyntheticTestCapacityDoesNotDisplaceHealth(t *testing.T) {
	s, _ := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	ctx := context.Background()
	for i := 0; i < alarmdelivery.MaxRecords; i++ {
		id := fmt.Sprintf("fixture-%d", i)
		if _, e := s.db.Exec(`INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,?,?,?,'opened','{}','failed',?,?)`, id, alarmBinding.Key(), id, id, "root-filesystem", alarmEpoch.UnixMilli(), alarmEpoch.UnixMilli()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.EnqueueAlarmTest(ctx, alarmBinding, strings.Repeat("a", 32), "shared-administrator", alarmEpoch); e != alarmdelivery.ErrTestLimited {
		t.Fatal("capacity ignored", e)
	}
	st, _ := s.AlarmStatus(ctx)
	if st.Dropped != 0 || st.Failed != alarmdelivery.MaxRecords || st.Queued != 0 {
		t.Fatal("test displaced health or counted as health delivery gap", st)
	}
}

func TestAlarmSettingsAuditRestartReconciliationIsIdempotent(t *testing.T) {
	s, _ := alarmStore(t)
	ctx := context.Background()
	a := alarmdelivery.SettingsAudit{Revision: strings.Repeat("e", 32), Actor: "shared-administrator", Action: "disable", At: alarmEpoch}
	for i := 0; i < 3; i++ {
		if e := s.ConfigureAlarmsAudited(ctx, nil, a, alarmEpoch.Add(time.Duration(i)*time.Hour)); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := s.db.QueryRow(`SELECT count(*) FROM alarm_config_audit WHERE revision=?`, a.Revision).Scan(&count); e != nil || count != 1 {
		t.Fatal("restart duplicated audit", count, e)
	}
	var at int64
	if e := s.db.QueryRow(`SELECT at FROM alarm_config_audit WHERE revision=?`, a.Revision).Scan(&at); e != nil || at != alarmEpoch.UnixMilli() {
		t.Fatal("approval timestamp changed on restart")
	}
	a.Action = "enable"
	if e := s.ConfigureAlarmsAudited(ctx, &alarmBinding, a, alarmEpoch); e != alarmdelivery.ErrInvalid {
		t.Fatal("conflicting same-revision audit accepted")
	}
	st, _ := s.AlarmStatus(ctx)
	if st.Enabled {
		t.Fatal("failed audit did not roll back configuration")
	}
}
