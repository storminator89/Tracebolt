package api

import (
	"context"
	"testing"
	"time"
)

type capacityBoundaryClock struct {
	*fixtureWindowsCapacitySource
	calls      int
	transition func(int) time.Time
}

func (f *capacityBoundaryClock) Now() time.Time { f.calls++; return f.transition(f.calls) }

func TestWindowsCapacityFinalClockCannotReleaseExpiredHistory(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	openCapacityFixture(t, m, f)
	o.login(t)
	start := f.now
	expiry := start.Add(time.Second)
	f.inputs[0].AuthorityUntil = expiry
	clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
	clock.transition = func(n int) time.Time {
		if n >= 4 {
			return expiry
		}
		return start
	}
	m.source = clock
	r, v := o.call(t, "GET", "/api/devices/"+f.inputs[0].DeviceID+"/windows-capacity", nil, "", nil)
	if r.StatusCode == 200 {
		t.Fatalf("released %d incidents at expired serverNow=%v, expiry=%v, Now calls=%d", len(v["incidents"].([]any)), v["serverNow"], v["certificateExpiresAt"], clock.calls)
	}
}

func TestWindowsCapacityPolicyFinalAuthorityMustRejectBeforeWrite(t *testing.T) {
	for _, mode := range []string{"revoked", "missing", "expiry", "clock-rollback", "changed-binding"} {
		t.Run(mode, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installCapacityFixture(t, o)
			_, v := o.login(t)
			id := f.inputs[0].DeviceID
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "revoked":
					f.inputs[0].Authorized = false
				case "missing":
					f.inputs = nil
				case "expiry":
					f.now = f.inputs[0].AuthorityUntil
				case "clock-rollback":
					f.now = f.now.Add(-time.Second)
				case "changed-binding":
					f.inputs[0].InvitationID = "invite_11111111111111111111111111111111"
				}
			}
			r, _ := o.call(t, "POST", "/api/devices/"+id+"/windows-capacity/policy", map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, v["csrfToken"].(string), nil)
			if r.StatusCode == 200 {
				t.Fatal("lost authority policy succeeded")
			}
			states, err := o.app.store.WindowsCapacityStates(context.Background())
			if err != nil || len(states) != 0 {
				t.Fatal("rejected policy persisted", err)
			}
		})
	}
}

func TestWindowsCapacityOffDoesNotReadEnrollment(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	if err := m.evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.reads != 0 {
		t.Fatal("default-off monitor competed for enrollment reads", f.reads)
	}
}
