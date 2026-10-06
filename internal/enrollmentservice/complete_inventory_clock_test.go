package enrollmentservice

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"reflect"
	"testing"
	"time"
)

func TestCompleteInventoryServicePropagatesTrustedClock(t *testing.T) {
	for _, boundary := range []string{"transaction", "after_commit"} {
		for _, horizon := range []string{"fresh", "certificate"} {
			t.Run(boundary+"/"+horizon, func(t *testing.T) {
				f, active := systemInventoryClockFixture(t)
				at := f.now
				checked := at.Add(time.Second)
				if horizon == "certificate" {
					checked = time.Unix(active.Intent.NotAfter, 0).UTC()
				}
				calls := 0
				f.service.now = func() time.Time {
					calls++
					if boundary == "after_commit" && calls == 1 {
						return at
					}
					return checked
				}
				ctx := enrollmentstore.WithSystemViewClock(context.Background(), func() time.Time { return at })
				view, err := f.service.CompleteInventoryView(ctx, active.Approval.DeviceID, at)
				if horizon == "certificate" {
					if !errors.Is(err, enrollmentstate.ErrExpired) || !reflect.DeepEqual(view, enrollmentstore.InventoryStatus{}) {
						t.Fatal("expired identity escaped service clock", err)
					}
					return
				}
				if err != nil || calls < 2 || !view.ServerNow.Equal(checked) || view.DeviceID != active.Approval.DeviceID || view.Complete != nil || view.Transfer != nil {
					t.Fatal("service clock not used", err)
				}
			})
		}
	}
}
