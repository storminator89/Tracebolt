package store

import (
	"context"
	"database/sql"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/managerstatus"
)

// ManagerStatus reports storage admission, not successful mutation durability
// or the availability of every independently fenced application feature.
func (s *Store) ManagerStatus(ctx context.Context) managerstatus.ProbeResult {
	if s == nil {
		return managerstatus.ProbeResult{State: managerstatus.Unavailable}
	}
	return managerstatus.SQLiteProbe(ctx, s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
		// Resolve expected real columns even when the tables are empty. Avoid
		// scanning unbounded application content on an operational status request.
		for _, q := range []string{"SELECT id,body FROM devices LIMIT 1", "SELECT id,body FROM cases LIMIT 1"} {
			rows, err := c.QueryContext(ctx, q)
			if err != nil {
				return managerstatus.ProbeResult{}, err
			}
			err = rows.Close()
			if err != nil {
				return managerstatus.ProbeResult{}, err
			}
		}
		queue, err := managerStatusQueue(ctx, c, false)
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		windowsQueue, err := managerStatusQueue(ctx, c, true)
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		var cancellation, unconfirmed int
		if err = c.QueryRowContext(ctx, `SELECT coalesce(sum(state IN ('cancel_pending','capture_unconfirmed')),0),coalesce(sum(state='capture_unconfirmed'),0) FROM journal_ai_attempts`).Scan(&cancellation, &unconfirmed); err != nil {
			return managerstatus.ProbeResult{}, err
		}
		return managerstatus.ProbeResult{State: managerstatus.OK, AlarmQueue: queue, WindowsQueue: windowsQueue, Fences: &managerstatus.FenceMetrics{JournalCancellationPending: cancellation > 0, JournalCaptureUnconfirmed: unconfirmed > 0}}, nil
	})
}

func managerStatusQueue(ctx context.Context, c *sql.Conn, windows bool) (*managerstatus.QueueMetrics, error) {
	q := &managerstatus.QueueMetrics{PendingLimit: alarmdelivery.MaxPending, RecordLimit: alarmdelivery.MaxRecords}
	query := `SELECT count(*),coalesce(sum(state='queued'),0),coalesce(sum(state='in_flight'),0),coalesce(sum(state='provider_accepted'),0),coalesce(sum(state='failed'),0),coalesce(sum(state='uncertain'),0),coalesce(sum(state='suppressed'),0),(SELECT coalesce(sum(dropped),0) FROM alarm_settings) FROM alarm_outbox`
	if windows {
		query = `SELECT count(*),coalesce(sum(state='queued'),0),coalesce(sum(state='in_flight'),0),coalesce(sum(state='provider_accepted'),0),coalesce(sum(state='failed'),0),coalesce(sum(state='uncertain'),0),coalesce(sum(state='suppressed'),0),(SELECT coalesce(sum(dropped),0) FROM windows_notification_counters) FROM windows_notification_outbox`
	}
	err := c.QueryRowContext(ctx, query).Scan(&q.Records, &q.Queued, &q.InFlight, &q.ProviderAccepted, &q.Failed, &q.Uncertain, &q.Suppressed, &q.Dropped)
	return q, err
}
