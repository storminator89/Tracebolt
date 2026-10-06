package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/enrollmentcrypto"
	"time"
)

func validAlarmActor(s string) bool {
	return s == "shared-administrator" || enrollmentcrypto.ValidID(s, "operator_")
}
func validAlarmAudit(a alarmdelivery.SettingsAudit) bool {
	id, e := hex.DecodeString(a.Revision)
	return e == nil && len(id) == 16 && hex.EncodeToString(id) == a.Revision && validAlarmActor(a.Actor) && !a.At.IsZero() && (a.Action == "replace" || a.Action == "enable" || a.Action == "disable" || a.Action == "test")
}
func insertAlarmAudit(ctx context.Context, tx *sql.Tx, a alarmdelivery.SettingsAudit) error {
	if !validAlarmAudit(a) {
		return alarmdelivery.ErrInvalid
	}
	if _, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO alarm_config_audit(revision,actor,action,at) VALUES(?,?,?,?)`, a.Revision, a.Actor, a.Action, a.At.UnixMilli()); e != nil {
		return e
	}
	var actor, action string
	var at int64
	if e := tx.QueryRowContext(ctx, `SELECT actor,action,at FROM alarm_config_audit WHERE revision=?`, a.Revision).Scan(&actor, &action, &at); e != nil {
		return e
	}
	if actor != a.Actor || action != a.Action || at != a.At.UnixMilli() {
		return alarmdelivery.ErrInvalid
	}
	_, e := tx.ExecContext(ctx, `DELETE FROM alarm_config_audit WHERE id NOT IN (SELECT id FROM alarm_config_audit ORDER BY id DESC LIMIT 200)`)
	return e
}

// EnqueueAlarmTest records an explicitly approved fixed synthetic test in the
// existing durable outbox. Repeating its request ID only reads the same record.
// The persisted global minute limit cannot be reset by changing destinations.
func (s *Store) EnqueueAlarmTest(ctx context.Context, b alarmdelivery.Binding, requestID, actor string, now time.Time) (*alarmdelivery.TestStatus, error) {
	rawID, e := hex.DecodeString(requestID)
	if e != nil || len(rawID) != 16 || hex.EncodeToString(rawID) != requestID || !b.Valid() || !validAlarmActor(actor) || now.IsZero() {
		return nil, alarmdelivery.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var active string
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&active, &enabled); e != nil {
		return nil, e
	}
	if active != b.Key() || enabled != 1 {
		return nil, alarmdelivery.ErrSettingsUnavailable
	}
	sum := sha256.Sum256([]byte(b.Key() + "\x00alarm-test\x00" + requestID))
	id := hex.EncodeToString(sum[:])
	var existing alarmdelivery.TestStatus
	var created int64
	e = tx.QueryRowContext(ctx, `SELECT id,state,created FROM alarm_outbox WHERE id=? AND binding=? AND rule=?`, id, b.Key(), alarmdelivery.TestRule).Scan(&existing.EventID, &existing.State, &created)
	if e == nil {
		existing.CreatedAt = time.UnixMilli(created).UTC()
		return &existing, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	var outstanding int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM alarm_outbox WHERE rule=? AND state IN ('queued','in_flight')`, alarmdelivery.TestRule).Scan(&outstanding); e != nil {
		return nil, e
	}
	if outstanding > 0 {
		return nil, alarmdelivery.ErrTestLimited
	}
	var latest sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT max(created) FROM alarm_outbox WHERE rule=?`, alarmdelivery.TestRule).Scan(&latest); e != nil {
		return nil, e
	}
	if latest.Valid && now.UnixMilli() < latest.Int64+time.Minute.Milliseconds() {
		return nil, alarmdelivery.ErrTestLimited
	}
	// Test-only terminal pruning never removes accepted opening dependencies.
	if _, e = tx.ExecContext(ctx, `DELETE FROM alarm_outbox WHERE rule=? AND state NOT IN ('queued','in_flight') AND created<?`, alarmdelivery.TestRule, now.Add(-30*24*time.Hour).UnixMilli()); e != nil {
		return nil, e
	}
	var count, pending int
	if e = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(state IN ('queued','in_flight')),0) FROM alarm_outbox`).Scan(&count, &pending); e != nil {
		return nil, e
	}
	if count >= alarmdelivery.MaxRecords || pending >= alarmdelivery.MaxPending {
		return nil, alarmdelivery.ErrTestLimited
	}
	p := alarmdelivery.NewTestPayload(id, now.UTC())
	body, e := json.Marshal(p)
	if e != nil || len(body) > alarmdelivery.MaxPayloadBytes {
		return nil, alarmdelivery.ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,?, ?,?,'opened',?,'queued',?,?)`, id, b.Key(), "synthetic", id, alarmdelivery.TestRule, body, now.UnixMilli(), now.UnixMilli()); e != nil {
		return nil, e
	}
	if e = insertAlarmAudit(ctx, tx, alarmdelivery.SettingsAudit{Revision: id[:32], Actor: actor, Action: "test", At: now}); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &alarmdelivery.TestStatus{EventID: id, State: "queued", CreatedAt: now.UTC()}, nil
}
func (s *Store) LatestAlarmTest(ctx context.Context, b alarmdelivery.Binding) (*alarmdelivery.TestStatus, error) {
	if !b.Valid() {
		return nil, alarmdelivery.ErrInvalid
	}
	var out alarmdelivery.TestStatus
	var ms int64
	e := s.db.QueryRowContext(ctx, `SELECT id,state,created FROM alarm_outbox WHERE binding=? AND rule=? ORDER BY created DESC,id DESC LIMIT 1`, b.Key(), alarmdelivery.TestRule).Scan(&out.EventID, &out.State, &ms)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	out.CreatedAt = time.UnixMilli(ms).UTC()
	return &out, nil
}
