package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

func completeNotificationTarget(in windowsservicehealth.Input, healthRevision uint64) WindowsCompleteNotificationTarget {
	return WindowsCompleteNotificationTarget{WindowsMaintenanceTarget: WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: "service-complete"}, Source: in.Sample.Complete.Source.Binding(), HealthPolicyRevision: healthRevision}
}
func completeNotificationConfigure(t *testing.T, s *Store, name string) windowsservicehealth.Input {
	t.Helper()
	in := completeStoredInput()
	in.Sample.Complete.Rows[0].Name = name
	if _, e := s.ConfigureWindowsService(context.Background(), in, true, []string{name}, 0, contactAt); e != nil {
		t.Fatal(e)
	}
	return in
}
func completeNotificationEnable(t *testing.T, s *Store, in windowsservicehealth.Input) WindowsCompleteNotificationPolicy {
	t.Helper()
	p, e := s.ChangeWindowsCompleteNotificationPolicy(context.Background(), completeNotificationTarget(in, 1), 0, true, alarmBinding.Key(), in, func() time.Time { return contactAt }, notificationGuard)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func completeNotificationGeneration(in *windowsservicehealth.Input, sequence uint64, at time.Time, state string) {
	p := &in.Sample.Complete.Source
	p.Sequence = sequence
	p.CapturedAt = at
	p.CaptureFinishedAt = at
	p.ReceivedAt = at
	p.ExpiresAt = at.Add(windowsfullservices.Retention)
	p.GenerationID, _ = windowsfullservices.GenerationID(in.DeviceID, p.GrantID, sequence)
	in.Sample.Complete.Rows[0].State = &state
	selected := *p
	in.Selection = &selected
}
func completeNotificationOpen(t *testing.T, s *Store, in *windowsservicehealth.Input) {
	t.Helper()
	for sec := 0; sec <= 180; sec += 30 {
		at := contactAt.Add(time.Duration(sec) * time.Second)
		if sec == 180 {
			completeNotificationGeneration(in, 2, at, "stopped")
		}
		if _, e := s.EvaluateWindowsService(context.Background(), *in, at, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
}
func completeNotificationRecover(t *testing.T, s *Store, in *windowsservicehealth.Input) {
	t.Helper()
	for _, sec := range []int{210, 240, 270} {
		at := contactAt.Add(time.Duration(sec) * time.Second)
		if sec != 240 {
			completeNotificationGeneration(in, uint64(sec/60), at, "running")
		}
		if _, e := s.EvaluateWindowsService(context.Background(), *in, at, contactEpoch); e != nil {
			t.Fatal(e)
		}
	}
}
func completeNotificationCandidate(t *testing.T, s *Store, at time.Time) WindowsNotificationCandidate {
	t.Helper()
	c, e := s.NextWindowsNotification(context.Background(), alarmBinding, at)
	if e != nil || c == nil || c.CompleteTarget == nil {
		t.Fatal("missing complete candidate", c, e)
	}
	return *c
}
func completeNotificationClaim(t *testing.T, s *Store, in windowsservicehealth.Input, at time.Time) *alarmdelivery.Attempt {
	t.Helper()
	c := completeNotificationCandidate(t, s, at)
	a, e := s.ClaimWindowsCompleteNotification(context.Background(), alarmBinding, c, in, contactAt, func() time.Time { return at }, notificationGuard)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func completeNotificationFixture(t *testing.T) (*Store, windowsservicehealth.Input, WindowsCompleteNotificationPolicy) {
	t.Helper()
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	in := completeNotificationConfigure(t, s, "FixtureService")
	p := completeNotificationEnable(t, s, in)
	completeNotificationOpen(t, s, &in)
	return s, in, p
}
func completeNotificationRow(t *testing.T, s *Store, id string) (string, int, string) {
	t.Helper()
	var state, code string
	var attempts int
	if e := s.db.QueryRow(`SELECT state,attempts,code FROM windows_notification_outbox WHERE id=?`, id).Scan(&state, &attempts, &code); e != nil {
		t.Fatal(e)
	}
	return state, attempts, code
}

func TestWindowsCompleteNotificationsPolicyIsolationAndNoBackfill(t *testing.T) {
	ctx := context.Background()
	s := contactStore(t)
	configureAlarm(t, s, &alarmBinding)
	in := completeNotificationConfigure(t, s, "FixtureService")
	notificationEnable(t, s, "service")
	completeNotificationOpen(t, s, &in)
	if c := notificationCounts(t, s); c.Queued != 0 {
		t.Fatal("v1 source approval promoted", c)
	}
	raw := serviceHealthRaw(t, s, in.DeviceID)
	target := completeNotificationTarget(in, 1)
	at := contactAt.Add(181 * time.Second)
	p, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, target, 0, true, alarmBinding.Key(), in, func() time.Time { return at }, notificationGuard)
	if e != nil || p.Revision != 1 || !bytes.Equal(raw, serviceHealthRaw(t, s, in.DeviceID)) {
		t.Fatal("policy edited history", e)
	}
	completeNotificationRecover(t, s, &in)
	if c := notificationCounts(t, s); c.Queued != 0 {
		t.Fatal("enable backfilled recovery", c)
	}
	snapshot, e := s.WindowsNotifications(ctx)
	if e != nil || len(snapshot.Policies) != 1 || len(snapshot.CompletePolicies) != 1 {
		t.Fatal(e, snapshot)
	}
	if _, e = s.db.Exec(`PRAGMA query_only=ON`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WindowsNotifications(ctx); e != nil {
		t.Fatal("read writes", e)
	}
}

func TestWindowsCompleteNotificationsAcceptedRecoveryAndMaintenance(t *testing.T) {
	for _, mode := range []string{"accepted", "uncertain", "in-flight", "maintenance-open", "maintenance-claim", "maintenance-in-flight-accepted", "maintenance-in-flight-retry", "health-policy", "notification-policy", "destination", "recovery-unknown", "recovery-unevaluated", "recovery-stale-evaluation", "recovery-final-source"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s := contactStore(t)
			configureAlarm(t, s, &alarmBinding)
			in := completeNotificationConfigure(t, s, "FixtureService")
			p := completeNotificationEnable(t, s, in)
			maintenance := WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: "service"}
			start := func(at time.Time) {
				t.Helper()
				if _, e := s.ChangeWindowsMaintenance(ctx, maintenance, 0, at.Add(time.Hour), "planned-work", 0, func() time.Time { return at }, func(time.Time, time.Time) error { return nil }); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "maintenance-open" {
				start(contactAt)
			}
			completeNotificationOpen(t, s, &in)
			if mode == "maintenance-open" {
				if c := notificationCounts(t, s); c.Suppressed != 1 || c.Queued != 0 {
					t.Fatal(c)
				}
				return
			}
			at := contactAt.Add(180 * time.Second)
			candidate := completeNotificationCandidate(t, s, at)
			if mode == "maintenance-claim" {
				start(at)
				state, _, _ := completeNotificationRow(t, s, candidate.ID)
				if state != "suppressed" {
					t.Fatal(state)
				}
				return
			}
			a := completeNotificationClaim(t, s, in, at)
			if a == nil || a.Payload.SchemaVersion != WindowsCompleteNotificationSchema || a.Payload.Rule != "windows-service-complete" || a.Payload.Target != "FixtureService" {
				t.Fatal(a)
			}
			if mode == "maintenance-in-flight-accepted" || mode == "maintenance-in-flight-retry" {
				start(at.Add(time.Second))
				outcome := alarmdelivery.Accepted
				if mode == "maintenance-in-flight-retry" {
					outcome = alarmdelivery.Retryable
				}
				notificationComplete(t, s, a, outcome, at.Add(2*time.Second))
				state, _, _ := completeNotificationRow(t, s, candidate.ID)
				want := "provider_accepted"
				if outcome == alarmdelivery.Retryable {
					want = "suppressed"
				}
				if state != want {
					t.Fatal(state)
				}
				return
			}
			if mode != "in-flight" {
				outcome := alarmdelivery.Accepted
				if mode == "uncertain" {
					outcome = alarmdelivery.Uncertain
				}
				notificationComplete(t, s, a, outcome, at)
			}
			if mode == "health-policy" {
				in.Selection = nil
				if _, e := s.ConfigureWindowsService(ctx, in, false, []string{}, 1, at.Add(time.Second)); e != nil {
					t.Fatal(e)
				}
				if c := notificationCounts(t, s); c.Queued != 0 {
					t.Fatal("policy closure recovered", c)
				}
				return
			}
			if mode == "notification-policy" {
				if _, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, p.Target, 1, false, "", windowsservicehealth.Input{}, func() time.Time { return at.Add(time.Second) }, notificationGuard); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "destination" {
				b := alarmBinding
				b.Generation = "changed"
				configureAlarm(t, s, &b)
			}
			completeNotificationRecover(t, s, &in)
			if mode == "uncertain" || mode == "notification-policy" || mode == "destination" {
				if c := notificationCounts(t, s); c.Queued != 0 {
					t.Fatal("unpaired recovery", c)
				}
				return
			}
			at = contactAt.Add(270 * time.Second)
			if strings.HasPrefix(mode, "recovery-") {
				if mode == "recovery-unknown" || mode == "recovery-unevaluated" {
					completeNotificationGeneration(&in, 5, at, "running")
				}
				if mode == "recovery-unknown" {
					in.Sample.Complete.Rows[0].State = nil
					in.Sample.Complete.Rows[0].StateQuality = "unavailable"
				}
				if mode == "recovery-stale-evaluation" {
					at = at.Add(121 * time.Second)
				}
				c := completeNotificationCandidate(t, s, at)
				calls := 0
				a, e := s.ClaimWindowsCompleteNotification(ctx, alarmBinding, c, in, contactAt, func() time.Time {
					calls++
					if mode == "recovery-final-source" && calls >= 3 {
						return at.Add(301 * time.Second)
					}
					return at
				}, notificationGuard)
				if a != nil || mode == "recovery-final-source" && e == nil || mode != "recovery-final-source" && e != nil {
					t.Fatal("unknown or expired source dispatched recovery", a, e)
				}
				state, n, _ := completeNotificationRow(t, s, c.ID)
				if state != "queued" || n != 0 {
					t.Fatal(state, n)
				}
				return
			}
			if mode == "in-flight" {
				if got := completeNotificationClaim(t, s, in, at); got != nil {
					t.Fatal("recovery overtook in-flight opening")
				}
				notificationComplete(t, s, a, alarmdelivery.Accepted, at)
			}
			recovered := completeNotificationClaim(t, s, in, at.Add(2*time.Second))
			if recovered == nil || recovered.Payload.Transition != "recovered" || recovered.Payload.Reason != "running" {
				t.Fatal(recovered)
			}
			notificationComplete(t, s, recovered, alarmdelivery.Accepted, at.Add(2*time.Second))
			var count int
			if e := s.db.QueryRow(`SELECT count(*) FROM alarm_outbox`).Scan(&count); e != nil || count != 0 {
				t.Fatal("complete notification entered Linux outbox", e, count)
			}
		})
	}
}

func TestWindowsCompleteNotificationsClaimGuardsAndUnknown(t *testing.T) {
	t.Run("actual-sql-wait", func(t *testing.T) {
		s, in, _ := completeNotificationFixture(t)
		ctx := context.Background()
		at := contactAt.Add(180 * time.Second)
		c := completeNotificationCandidate(t, s, at)
		conn, e := s.db.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		waits := s.db.Stats().WaitCount
		var shifted atomic.Bool
		done := make(chan error, 1)
		go func() {
			a, e := s.ClaimWindowsCompleteNotification(ctx, alarmBinding, c, in, contactAt, func() time.Time {
				if shifted.Load() {
					return at.Add(time.Second)
				}
				return at
			}, notificationGuard)
			if e == nil && a == nil {
				e = errors.New("missing claim")
			}
			done <- e
		}()
		until := time.Now().Add(5 * time.Second)
		for s.db.Stats().WaitCount == waits && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if s.db.Stats().WaitCount == waits {
			conn.Close()
			t.Fatal("did not reach SQL wait")
		}
		shifted.Store(true)
		conn.Close()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		var last int64
		if e := s.db.QueryRow(`SELECT last_attempt FROM windows_notification_outbox WHERE id=?`, c.ID).Scan(&last); e != nil || last != at.Add(time.Second).UnixMilli() {
			t.Fatal("claim borrowed pre-wait clock", last, e)
		}
	})
	for _, mode := range []string{"unknown", "new-generation", "wrong-grant", "wrong-identity", "final-source", "after-guard-source", "final-authority", "final-policy", "legacy-claim", "defer-expiry"} {
		t.Run(mode, func(t *testing.T) {
			s, in, _ := completeNotificationFixture(t)
			ctx := context.Background()
			at := contactAt.Add(180 * time.Second)
			c := completeNotificationCandidate(t, s, at)
			if mode == "defer-expiry" {
				if e := s.DeferWindowsNotification(ctx, c.ID, at.Add(alarmdelivery.MaxQueueAge)); e != nil {
					t.Fatal(e)
				}
				state, n, code := completeNotificationRow(t, s, c.ID)
				if state != "suppressed" || n != 0 || code != "queue_expired" {
					t.Fatal(state, n, code)
				}
				return
			}
			if mode == "legacy-claim" {
				if _, e := s.ClaimWindowsNotification(ctx, alarmBinding, c, capacityInput(1, 180, 95), contactAt, func() time.Time { return at }, notificationGuard); e == nil {
					t.Fatal("v1 claim admitted complete source")
				}
				return
			}
			if mode == "unknown" {
				in.Sample.Complete = nil
			}
			if mode == "new-generation" {
				completeNotificationGeneration(&in, 3, at, "stopped")
			}
			if mode == "wrong-grant" {
				in.Sample.Complete.Source.GrantID = strings.Repeat("c", 32)
				completeNotificationGeneration(&in, 3, at, "stopped")
			}
			if mode == "wrong-identity" {
				in.CertificateHash = strings.Repeat("f", 64)
			}
			calls := 0
			clock := func() time.Time {
				calls++
				if mode == "final-source" && calls >= 3 || mode == "after-guard-source" && calls >= 4 {
					return at.Add(301 * time.Second)
				}
				return at
			}
			guards := 0
			guard := func(time.Time) error {
				guards++
				if mode == "final-authority" && guards == 3 {
					return errors.New("revoked")
				}
				if mode == "final-policy" && guards == 3 {
					return errors.New("health policy changed")
				}
				return nil
			}
			a, e := s.ClaimWindowsCompleteNotification(ctx, alarmBinding, c, in, contactAt, clock, guard)
			if mode == "unknown" || mode == "new-generation" || mode == "wrong-grant" {
				if e != nil || a != nil {
					t.Fatal(a, e)
				}
			} else if e == nil || a != nil {
				t.Fatal("unsafe final claim", a, e)
			}
			state, n, _ := completeNotificationRow(t, s, c.ID)
			if state != "queued" || n != 0 {
				t.Fatal("rejected claim consumed attempt", state, n)
			}
			var sent int64
			if e := s.db.QueryRow(`SELECT last_send FROM alarm_settings WHERE id=1`).Scan(&sent); e != nil || sent != 0 {
				t.Fatal("rejected claim changed shared spacing", sent, e)
			}
		})
	}
}

func TestWindowsCompleteNotificationsRetainedPolicyBoundsAndStrictQueue(t *testing.T) {
	ctx := context.Background()
	t.Run("policy-final-source-expiry", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		in := completeNotificationConfigure(t, s, "FixtureService")
		raw := serviceHealthRaw(t, s, in.DeviceID)
		calls := 0
		clock := func() time.Time {
			calls++
			if calls >= 3 {
				return contactAt.Add(301 * time.Second)
			}
			return contactAt
		}
		if _, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, completeNotificationTarget(in, 1), 0, true, alarmBinding.Key(), in, clock, notificationGuard); e == nil {
			t.Fatal("post-write source expiry committed")
		}
		snapshot, e := s.WindowsNotifications(ctx)
		if e != nil || len(snapshot.CompletePolicies) != 0 || !bytes.Equal(raw, serviceHealthRaw(t, s, in.DeviceID)) {
			t.Fatal("failed policy write changed durable state", e)
		}
	})
	t.Run("health-revision-replacement", func(t *testing.T) {
		s, in, p := completeNotificationFixture(t)
		at := contactAt.Add(181 * time.Second)
		in.Selection = nil
		if _, e := s.ConfigureWindowsService(ctx, in, false, []string{"FixtureService"}, 1, at); e != nil {
			t.Fatal(e)
		}
		target := p.Target
		target.HealthPolicyRevision = 2
		if _, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, target, 0, true, alarmBinding.Key(), in, func() time.Time { return at }, notificationGuard); e == nil {
			t.Fatal("health revision bypassed retained notification revision")
		}
		if _, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, p.Target, 1, false, "", windowsservicehealth.Input{}, func() time.Time { return at }, notificationGuard); e != nil {
			t.Fatal("could not disable without fresh source", e)
		}
		in.Selection = &in.Sample.Complete.Source
		if _, e := s.ConfigureWindowsService(ctx, in, true, []string{"FixtureService"}, 2, at); e != nil {
			t.Fatal(e)
		}
		target.HealthPolicyRevision = 3
		next, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, target, 2, true, alarmBinding.Key(), in, func() time.Time { return at }, notificationGuard)
		if e != nil || next.Revision != 3 || next.Target.Key() == p.Target.Key() || next.Target.IdentityKey() != p.Target.IdentityKey() {
			t.Fatal(next, e)
		}
		snapshot, e := s.WindowsNotifications(ctx)
		if e != nil || len(snapshot.CompletePolicies) != 1 {
			t.Fatal(snapshot, e)
		}
	})
	t.Run("retained-identity-bound", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		in := completeNotificationConfigure(t, s, "FixtureService")
		p := WindowsCompleteNotificationPolicy{Version: 2, Target: completeNotificationTarget(in, 1), Revision: 1, Binding: alarmBinding.Key(), ChangedAt: contactAt}
		for i := 0; i < 25; i++ {
			copy := p
			copy.Target.CertificateHash = fmt.Sprintf("%064x", i+100)
			raw, _ := json.Marshal(copy)
			if _, e := s.db.Exec(`INSERT INTO windows_complete_notification_policies(id,body) VALUES(?,?)`, copy.Target.IdentityKey(), raw); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := s.ChangeWindowsCompleteNotificationPolicy(ctx, p.Target, 0, true, p.Binding, in, func() time.Time { return contactAt }, notificationGuard); !errors.Is(e, ErrLimit) {
			t.Fatal("retained identities evicted", e)
		}
		snapshot, e := s.WindowsNotifications(ctx)
		if e != nil || len(snapshot.CompletePolicies) != 25 {
			t.Fatal(e)
		}
	})
	for _, mode := range []string{"unknown-field", "wrong-version", "legacy-envelope", "policy-revision", "wrong-rule"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _ := completeNotificationFixture(t)
			at := contactAt.Add(180 * time.Second)
			c := completeNotificationCandidate(t, s, at)
			var raw, body []byte
			if e := s.db.QueryRow(`SELECT target,body FROM windows_notification_outbox WHERE id=?`, c.ID).Scan(&raw, &body); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			case "wrong-version":
				raw = bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":1`), 1)
			case "legacy-envelope":
				raw, _ = json.Marshal(c.Target)
			case "policy-revision":
				raw = bytes.Replace(raw, []byte(`"healthPolicyRevision":1`), []byte(`"healthPolicyRevision":0`), 1)
			case "wrong-rule":
				body = bytes.Replace(body, []byte(`windows-service-complete`), []byte(`windows-service`), 1)
			}
			if _, e := s.db.Exec(`UPDATE windows_notification_outbox SET target=?,body=? WHERE id=?`, raw, body, c.ID); e != nil {
				t.Fatal(e)
			}
			if _, e := s.NextWindowsNotification(ctx, alarmBinding, at); e == nil {
				t.Fatal("malformed queue accepted")
			}
		})
	}
}

func TestWindowsCompleteNotificationsCapacityPruningAndRestart(t *testing.T) {
	ctx := context.Background()
	t.Run("unrelated-complete-seen-corruption", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		notificationEnable(t, s, "disk")
		if _, e := s.db.Exec(`INSERT INTO windows_complete_incident_acknowledgements(key,body) VALUES(?,?)`, strings.Repeat("a", 64), []byte(`{"invalid":"synthetic-seen-metadata"}`)); e != nil {
			t.Fatal(e)
		}
		state := capacityOpen(t, s)
		if len(state.Incidents) != 1 || notificationCounts(t, s).Queued != 1 {
			t.Fatal("unrelated complete seen metadata blocked a legacy source transition")
		}
	})
	t.Run("native-name-payload-bound", func(t *testing.T) {
		for _, name := range []string{strings.Repeat("&", 256), strings.Repeat("\\\"", 128), strings.Repeat("界", 256), strings.Repeat("\u2028", 256)} {
			s := contactStore(t)
			configureAlarm(t, s, &alarmBinding)
			in := completeNotificationConfigure(t, s, name)
			completeNotificationEnable(t, s, in)
			completeNotificationOpen(t, s, &in)
			at := contactAt.Add(180 * time.Second)
			c := completeNotificationCandidate(t, s, at)
			var body []byte
			if e := s.db.QueryRow(`SELECT body FROM windows_notification_outbox WHERE id=?`, c.ID).Scan(&body); e != nil {
				t.Fatal(e)
			}
			if len(body) > alarmdelivery.MaxPayloadBytes || c.Subject != name || bytes.Contains(body, []byte(in.CertificateHash)) || bytes.Contains(body, []byte(in.Sample.Complete.Source.GrantID)) {
				t.Fatal("payload bound or private provenance", len(body))
			}
			a := completeNotificationClaim(t, s, in, at)
			if a == nil || a.Payload.Target != name {
				t.Fatal("native name lost", a)
			}
			// Maximum JSON escaping (six bytes per native UTF-16 unit) and
			// nanosecond UTC timestamps fit the unchanged transport budget.
			worst := a.Payload
			worst.ObservedAt = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
			worst.TransitionAt = worst.ObservedAt
			encoded, err := json.Marshal(worst)
			if err != nil || len(encoded) > alarmdelivery.MaxPayloadBytes {
				t.Fatal("worst-case Go JSON payload exceeds transport bound", len(encoded), err)
			}
			if name == strings.Repeat("&", 256) {
				t.Logf("maximum escaped native name with nanosecond UTC timestamps: %d bytes (limit %d)", len(encoded), alarmdelivery.MaxPayloadBytes)
			}
		}
	})
	t.Run("pending-bound", func(t *testing.T) {
		s := contactStore(t)
		configureAlarm(t, s, &alarmBinding)
		in := completeNotificationConfigure(t, s, "FixtureService")
		completeNotificationEnable(t, s, in)
		for n := 0; n < alarmdelivery.MaxPending; n++ {
			if _, e := s.db.Exec(`INSERT INTO windows_notification_outbox(id,binding,target_key,policy_key,revision,device,domain,target,body,transition,state,created,due) VALUES(?,?,?,?,1,?,'disk','{}','{}','opened','queued',?,?)`, fmt.Sprintf("fixture-%d", n), alarmBinding.Key(), fmt.Sprintf("target-%d", n), "fixture", in.DeviceID, contactAt.UnixMilli(), contactAt.UnixMilli()); e != nil {
				t.Fatal(e)
			}
		}
		completeNotificationOpen(t, s, &in)
		if c := notificationCounts(t, s); c.Queued != 500 || c.Dropped != 1 {
			t.Fatal(c)
		}
		state, e := s.WindowsServiceState(ctx, in.DeviceID)
		if e != nil || len(state.Incidents) != 1 {
			t.Fatal("capacity blocked source", e)
		}
	})
	t.Run("accepted-retained-opening", func(t *testing.T) {
		s, in, _ := completeNotificationFixture(t)
		at := contactAt.Add(180 * time.Second)
		a := completeNotificationClaim(t, s, in, at)
		notificationComplete(t, s, a, alarmdelivery.Accepted, at)
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = pruneWindowsNotifications(ctx, tx, at.Add(31*24*time.Hour)); e != nil {
			t.Fatal(e)
		}
		var n int
		if e = tx.QueryRow(`SELECT count(*) FROM windows_notification_outbox WHERE id=?`, a.Payload.EventID).Scan(&n); e != nil || n != 1 {
			t.Fatal("pruned accepted complete dependency", e, n)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("restart-in-flight", func(t *testing.T) {
		s, in, _ := completeNotificationFixture(t)
		at := contactAt.Add(180 * time.Second)
		a := completeNotificationClaim(t, s, in, at)
		if e := s.ConfigureAlarms(ctx, &alarmBinding, at.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		state, n, code := completeNotificationRow(t, s, a.Payload.EventID)
		if state != "uncertain" || n != 1 || code != "restart_in_flight" {
			t.Fatal(state, n, code)
		}
		completeNotificationRecover(t, s, &in)
		if c := notificationCounts(t, s); c.Queued != 0 {
			t.Fatal("restart uncertainty paired recovery", c)
		}
	})
}
