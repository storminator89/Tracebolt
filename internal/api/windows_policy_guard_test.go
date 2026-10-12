package api

import (
	"context"
	"testing"
	"time"
)

func TestWindowsPercentagePolicyTransactionClockRejectsBeforeCommit(t *testing.T) {
	for _, metric := range []string{"disk", "cpu", "memory"} {
		for _, rejectAt := range []int{5, 6} {
			t.Run(metric+string(rune('0'+rejectAt)), func(t *testing.T) {
				o := newOperatorFixture(t, time.Hour)
				m, f := installCapacityFixture(t, o)
				_, login := o.login(t)
				start := f.now
				expiry := start.Add(time.Second)
				f.inputs[0].AuthorityUntil = expiry
				clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
				clock.transition = func(n int) time.Time {
					if n >= rejectAt {
						return expiry
					}
					return start
				}
				m.source = clock
				path := "/api/devices/" + f.inputs[0].DeviceID + "/windows-capacity/policy"
				if metric != "disk" {
					path = "/api/devices/" + f.inputs[0].DeviceID + "/windows-resource/" + metric + "/policy"
				}
				r, _ := o.call(t, "POST", path, map[string]any{"enabled": true, "thresholdPercent": 90, "expectedRevision": 0}, login["csrfToken"].(string), nil)
				if r.StatusCode == 200 {
					t.Fatal("expired transaction accepted")
				}
				disks, err := o.app.store.WindowsCapacityStates(context.Background())
				if err != nil || len(disks) != 0 {
					t.Fatal("expired disk write committed")
				}
				resources, err := o.app.store.WindowsResourceStates(context.Background())
				if err != nil || len(resources) != 0 {
					t.Fatal("expired resource write committed")
				}
			})
		}
	}
}
