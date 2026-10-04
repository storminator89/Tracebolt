package journalcache

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalrequest"
)

func TestJournalCacheTransientAuthorityReadPreservesOriginalContent(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"inventory_busy", enrollmentstore.ErrInventoryBusy}, {"store_busy", enrollmentstore.ErrBusy},
		{"canceled", context.Canceled}, {"deadline", context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, status, q := journalClockFixture(t)
			id, at := status.Description.DeviceID, status.Description.CreatedAt
			original := c.entries[id]
			raw := append([]byte(nil), original.raw...)
			timer, receipt, expiry := original.timer, *original.receipt, original.expiry
			read := c.readStatus
			c.readStatus = func(context.Context, string, time.Time) (journalrequest.Status, error) {
				return journalrequest.Status{}, tc.err
			}
			got, local, err := c.Status(context.Background(), id, at)
			if !errors.Is(err, tc.err) || !reflect.DeepEqual(got, journalrequest.Status{}) || local != "unknown" {
				t.Fatal("transient read released status")
			}
			page, err := c.Page(context.Background(), id, q, at)
			if !errors.Is(err, tc.err) || !reflect.DeepEqual(page, Page{}) {
				t.Fatal("transient read released page")
			}
			retained := c.entries[id]
			if retained != original || retained == nil || retained.timer != timer || *retained.receipt != receipt || !retained.expiry.Equal(expiry) || !reflect.DeepEqual(retained.raw, raw) {
				t.Fatal("temporary authority failure destroyed or refreshed accepted content")
			}
			c.readStatus = read
			page, err = c.Page(context.Background(), id, q, at.Add(time.Minute))
			if err != nil || len(page.Rows) != 1 || !page.ExpiresAt.Equal(expiry) || page.SnapshotDigest != q.SnapshotDigest {
				t.Fatal("fresh authorized read did not recover original content")
			}
		})
	}
}

func TestJournalCacheTransientReadCrossingExpiryErasesOriginalBytes(t *testing.T) {
	c, clock, status, _ := journalClockFixture(t)
	id, at := status.Description.DeviceID, status.Description.CreatedAt
	raw := c.entries[id].raw
	c.readStatus = func(context.Context, string, time.Time) (journalrequest.Status, error) {
		clock.Store(status.Description.ExpiresAt.UnixNano())
		return journalrequest.Status{}, enrollmentstore.ErrInventoryBusy
	}
	got, local, err := c.Status(context.Background(), id, at)
	if !errors.Is(err, enrollmentstore.ErrInventoryBusy) || !reflect.DeepEqual(got, journalrequest.Status{}) || local != "unknown" {
		t.Fatal("expired busy read released metadata")
	}
	if c.entries[id] != nil {
		t.Fatal("busy read retained expired entry")
	}
	for _, b := range raw {
		if b != 0 {
			t.Fatal("expired bytes not cleared")
		}
	}
}

func TestJournalCacheTransientReadThenAuthorityDenialErasesContent(t *testing.T) {
	for _, denied := range []error{enrollmentstate.ErrProof, enrollmentstate.ErrState, enrollmentstate.ErrExpired, enrollmentstore.ErrStorage, errors.New("unrecognized"), errors.Join(enrollmentstore.ErrInventoryBusy, enrollmentstore.ErrStorage)} {
		c, _, status, q := journalClockFixture(t)
		id, at := status.Description.DeviceID, status.Description.CreatedAt
		raw := c.entries[id].raw
		c.readStatus = func(context.Context, string, time.Time) (journalrequest.Status, error) {
			return journalrequest.Status{}, enrollmentstore.ErrInventoryBusy
		}
		_, _, _ = c.Status(context.Background(), id, at)
		c.readStatus = func(context.Context, string, time.Time) (journalrequest.Status, error) {
			return journalrequest.Status{}, denied
		}
		got, err := c.Page(context.Background(), id, q, at)
		if !errors.Is(err, denied) || !reflect.DeepEqual(got, Page{}) || c.entries[id] != nil {
			t.Fatal("denied authority retained or released content")
		}
		for _, b := range raw {
			if b != 0 {
				t.Fatal("denied authority bytes not cleared")
			}
		}
	}
}
