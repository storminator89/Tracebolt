package api

import (
	"context"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"time"
)

type windowsNotificationAuthoritySource interface {
	WithWindowsNotificationAuthority(context.Context, windowscontact.Input, func(func(time.Time) error) error) error
}

// WindowsNotificationQueue reuses the configured, serialized alarm worker and
// HTTPS transport while retaining separate Windows admission and durable state.
// It never passes Windows episodes into Store.ClaimAlarm or Linux HealthInputs.
type WindowsNotificationQueue struct {
	*store.Store
	source windowsCapacitySource
	since  time.Time
}

func NewWindowsNotificationQueue(db *store.Store, source windowsCapacitySource) *WindowsNotificationQueue {
	q := &WindowsNotificationQueue{Store: db, source: source}
	if source != nil {
		q.since = source.Now().UTC()
	}
	return q
}
func (q *WindowsNotificationQueue) ClaimAlarm(ctx context.Context, b alarmdelivery.Binding, now time.Time) (*alarmdelivery.Attempt, error) {
	attempt, e := q.Store.ClaimAlarm(ctx, b, now)
	if e != nil || attempt != nil || q.source == nil {
		return attempt, e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := q.source.Now().UTC()
	c, e := q.Store.NextWindowsNotification(ctx, b, started)
	if e != nil || c == nil {
		return nil, e
	}
	inputs, e := q.source.WindowsCapacityInputs(ctx, started)
	if e != nil {
		return nil, e
	}
	authority, e := windowsCapacityAuthority(inputs, started)
	if e != nil {
		return nil, e
	}
	in, ok := authority[c.Target.DeviceID]
	if !ok || !in.Authorized || in.InvitationID != c.Target.InvitationID || in.CertificateHash != c.Target.CertificateHash {
		return nil, q.Store.SuppressWindowsNotification(ctx, c.ID, started)
	}
	lease, ok := q.source.(windowsNotificationAuthoritySource)
	if !ok {
		return nil, store.ErrWindowsNotificationConflict
	}
	e = lease.WithWindowsNotificationAuthority(ctx, in.Input, func(authorityGuard func(time.Time) error) error {
		var err error
		sample := started
		attempt, err = q.Store.ClaimWindowsNotification(ctx, b, *c, in, q.since, q.source.Now, func(at time.Time) error {
			if at.Before(sample) || !contactReadTime(started, at) || !at.Before(in.AuthorityUntil) || ctx.Err() != nil {
				return store.ErrWindowsNotificationConflict
			}
			sample = at
			return authorityGuard(at)
		})
		return err
	})
	return attempt, e
}
func (q *WindowsNotificationQueue) CompleteAlarm(ctx context.Context, b alarmdelivery.Binding, a alarmdelivery.Attempt, r alarmdelivery.Result, now time.Time) error {
	if a.Payload.SchemaVersion == store.WindowsNotificationSchema {
		return q.Store.CompleteWindowsNotification(ctx, b, a, r, now)
	}
	return q.Store.CompleteAlarm(ctx, b, a, r, now)
}
