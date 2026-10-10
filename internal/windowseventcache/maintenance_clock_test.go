package windowseventcache

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventrequest"
	"testing"
	"time"
)

// Any legacy per-device storage call fails the regression, including the
// invalidation path rather than only the all-valid steady state.
type maintenanceBatchOnlyStore struct {
	*fakeStore
	statuses map[string]enrollmentstore.WindowsEventStatus
	calls    int
	live     int
	after    func()
}

func (s *maintenanceBatchOnlyStore) MaintainWindowsEventAuthorities(_ context.Context, live map[string]windowseventrequest.Identity, _ time.Time) (map[string]enrollmentstore.WindowsEventStatus, error) {
	s.calls++
	s.live = len(live)
	if s.after != nil {
		s.after()
	}
	return s.statuses, nil
}
func (*maintenanceBatchOnlyStore) WindowsEventContentStatus(context.Context, string, time.Time) (enrollmentstore.WindowsEventStatus, error) {
	panic("per-device maintenance reload")
}
func (*maintenanceBatchOnlyStore) CancelWindowsEventRequest(context.Context, string, windowseventrequest.Identity, time.Time) error {
	panic("per-device maintenance cancellation")
}
func (*maintenanceBatchOnlyStore) MaintainWindowsEventContent(context.Context, time.Time, bool) error {
	panic("extra maintenance transaction")
}
func (*maintenanceBatchOnlyStore) CancelUnownedWindowsEventRequests(context.Context, map[string]windowseventrequest.Identity, time.Time) error {
	panic("extra orphan transaction")
}

func TestMaintenanceBatchesCapacityAndRechecksEveryPostStoreBoundary(t *testing.T) {
	for _, kind := range []string{"live", "session", "capability", "certificate", "request", "header", "grant", "missing", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			c, s, _, r, now, _ := cacheFixture(t)
			if _, err := c.Accept(context.Background(), r.Claim.DeviceID, r.Claim.CertificateHash, r, *now); err != nil {
				t.Fatal(err)
			}
			original := c.entries[r.Claim.DeviceID]
			c.entries = make(map[string]*entry)
			*now = now.Add(4 * time.Minute)
			boundary := now.Add(time.Nanosecond)
			batch := &maintenanceBatchOnlyStore{fakeStore: s, statuses: make(map[string]enrollmentstore.WindowsEventStatus)}
			for i := 0; i < MaxDevices; i++ {
				id := fmt.Sprintf("agent_%032x", i+1)
				e := *original
				e.raw = append([]byte(nil), original.raw...)
				record := s.record
				record.Description.DeviceID = id
				cap := s.cap
				cap.DeviceID = id
				status := enrollmentstore.WindowsEventStatus{DeviceID: id, LocalStatus: "enabled", AuthorityUntil: s.authority, Request: &record, Capability: &cap}
				switch kind {
				case "session":
					e.owner.ExpiresAt = boundary
				case "capability":
					cap.CollectedAt = boundary.Add(-5 * time.Minute)
				case "certificate":
					status.AuthorityUntil = boundary
				case "request":
					record.Description.ExpiresAt = boundary
				case "header":
					record.Description.HeaderCollectedAt = boundary.Add(-windowseventrequest.MaxHeaderAge)
				case "grant":
					cap.Consent.GrantID = "replacement"
				}
				c.entries[id] = &e
				if kind != "missing" {
					batch.statuses[id] = status
				}
			}
			c.store = batch
			batch.after = func() {
				*now = boundary
				if kind == "rollback" {
					*now = boundary.Add(-2 * time.Nanosecond)
				}
			}
			err := c.Maintain(context.Background(), *now)
			if kind == "rollback" {
				if !errors.Is(err, ErrClock) {
					t.Fatal("clock rollback accepted", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if batch.calls != 1 || batch.live != MaxDevices {
				t.Fatal("maintenance did not use one bounded snapshot", batch.calls, batch.live)
			}
			expected := 0
			if kind == "live" || kind == "capability" {
				expected = MaxDevices
			}
			if len(c.entries) != expected {
				t.Fatalf("retained %d entries, want %d", len(c.entries), expected)
			}
			for _, e := range c.entries {
				if kind == "live" && len(e.raw) == 0 || kind == "capability" && len(e.raw) != 0 {
					t.Fatal("incorrect post-store content lifetime")
				}
			}
		})
	}
}

func TestMaintenanceResamplesAndRetriesOwnerLostDuringBatch(t *testing.T) {
	c, s, _, result, now, _ := cacheFixture(t)
	*now = now.Add(4 * time.Minute)
	end := now.Add(time.Nanosecond)
	c.entries[result.Claim.DeviceID].owner.ExpiresAt = end
	s.afterStatus = func() { *now = end }
	if err := c.Maintain(context.Background(), *now); err != nil {
		t.Fatal(err)
	}
	if len(c.entries) != 0 || s.record.State != windowseventrequest.Claimed {
		t.Fatal("slow batch retained expired owner or made a second storage call")
	}
	if d, err := c.Peek(context.Background(), result.Claim.DeviceID, result.Claim.CertificateHash, *now); err != nil || d != nil {
		t.Fatal("lost owner could still poll", err)
	}
	if err := c.Maintain(context.Background(), *now); err != nil {
		t.Fatal(err)
	}
	if s.record.State != windowseventrequest.Canceled || s.orphans != 1 {
		t.Fatal("next batch did not cancel orphan")
	}
}
