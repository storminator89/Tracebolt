package enrollmentstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"math"
	"strconv"
	"time"
)

// Resource history retains only already accepted basic utilization observations.
// Each minute contains its last authentic sample, never an average or backfill.
const ResourceHistoryRetention = 24 * time.Hour
const ResourceHistoryLimit = 1441
const resourceHistorySchema = `CREATE TABLE enrollment_resource_history(invitation_id TEXT NOT NULL REFERENCES enrollment_credentials(invitation_id), bucket INTEGER NOT NULL CHECK(bucket>0), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024), PRIMARY KEY(invitation_id,bucket)) STRICT`
const resourceHistoryIndex = `CREATE INDEX enrollment_resource_history_age ON enrollment_resource_history(bucket)`

type ResourceMetric struct {
	Value       *float64  `json:"value"`
	Quality     string    `json:"quality"`
	CollectedAt time.Time `json:"collectedAt"`
}
type ResourcePoint struct {
	Sequence    string         `json:"sequence"`
	CollectedAt time.Time      `json:"collectedAt"`
	ReceivedAt  time.Time      `json:"receivedAt"`
	CPU         ResourceMetric `json:"cpu"`
	Memory      ResourceMetric `json:"memory"`
	Disk        ResourceMetric `json:"disk"`
}
type ResourceHistoryView struct {
	SchemaVersion       string          `json:"schemaVersion"`
	DeviceID            string          `json:"deviceId"`
	ServerNow           time.Time       `json:"serverNow"`
	WindowStart         time.Time       `json:"windowStart"`
	Status              string          `json:"status"`
	ResolutionSeconds   int             `json:"resolutionSeconds"`
	GapAfterSeconds     int             `json:"gapAfterSeconds"`
	Points              []ResourcePoint `json:"points"`
	certificateNotAfter int64
}

func EmptyResourceHistory(id string, now time.Time, status string) ResourceHistoryView {
	now = now.UTC()
	return ResourceHistoryView{SchemaVersion: "tracebolt.resource-history.v1", DeviceID: id, ServerNow: now, WindowStart: now.Add(-ResourceHistoryRetention), Status: status, ResolutionSeconds: 60, GapAfterSeconds: 120, Points: []ResourcePoint{}}
}
func resourceHistoryObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_resource_history", SQL: resourceHistorySchema}, {Type: "index", Name: "enrollment_resource_history_age", SQL: resourceHistoryIndex}}
}
func resourceHistoryPresent(ctx context.Context, conn *sql.Conn) (bool, error) {
	var n int
	if conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name IN ('enrollment_resource_history','enrollment_resource_history_age')`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if n != 2 {
		return false, ErrStorage
	}
	return true, nil
}
func resourceMetric(m model.Metric) ResourceMetric {
	return ResourceMetric{Value: m.Value, Quality: m.Quality, CollectedAt: m.CollectedAt.UTC()}
}
func validResourcePoint(p ResourcePoint) bool {
	n, e := strconv.ParseUint(p.Sequence, 10, 64)
	if e != nil || n == 0 || n > enrollmentstate.MaxRevision || strconv.FormatUint(n, 10) != p.Sequence || !validStoreTime(p.CollectedAt) || !validStoreTime(p.ReceivedAt) || p.CollectedAt.Sub(p.ReceivedAt) > lanstore.AllowedClockSkew || p.ReceivedAt.Sub(p.CollectedAt) > lanstore.SampleMaxAge {
		return false
	}
	for _, m := range []ResourceMetric{p.CPU, p.Memory, p.Disk} {
		if !validStoreTime(m.CollectedAt) || m.CollectedAt.After(p.CollectedAt) || p.CollectedAt.Sub(m.CollectedAt) > lanstore.SampleMaxAge+lanstore.AllowedClockSkew {
			return false
		}
		switch m.Quality {
		case "healthy":
			if m.Value == nil {
				return false
			}
		case "unknown", "denied", "stale":
		default:
			return false
		}
		if m.Value != nil && (math.IsNaN(*m.Value) || math.IsInf(*m.Value, 0) || *m.Value < 0 || *m.Value > 100) {
			return false
		}
		if m.Quality != "healthy" && m.Quality != "stale" && m.Value != nil {
			return false
		}
	}
	return true
}
func retainResourcePoint(ctx context.Context, t *transaction, invitation string, sequence uint64, device model.Device, received time.Time) error {
	enabled, e := resourceHistoryPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	if !enabled {
		for _, o := range resourceHistoryObjects() {
			if _, e = t.conn.ExecContext(ctx, o.SQL); e != nil {
				return ErrStorage
			}
		}
	}
	p := ResourcePoint{Sequence: strconv.FormatUint(sequence, 10), CollectedAt: device.LastSeen.UTC(), ReceivedAt: received.UTC(), CPU: resourceMetric(device.CPU), Memory: resourceMetric(device.Memory), Disk: resourceMetric(device.Disk)}
	if !validResourcePoint(p) {
		return ErrStorage
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 1024 {
		return ErrStorage
	}
	// Delete by collection time. Retries never enter this function, so they cannot
	// add points, move a timestamp, or extend retention.
	if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_resource_history WHERE invitation_id=? AND bucket<?`, invitation, received.Add(-ResourceHistoryRetention).Unix()/60); e != nil {
		return ErrStorage
	}
	if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_resource_history(invitation_id,bucket,body) VALUES(?,?,?) ON CONFLICT(invitation_id,bucket) DO UPDATE SET body=excluded.body`, invitation, p.CollectedAt.Unix()/60, raw); e != nil {
		return ErrStorage
	}
	var count int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_resource_history WHERE invitation_id=?`, invitation).Scan(&count) != nil || count > ResourceHistoryLimit+1 {
		return ErrStorage
	}
	return nil
}

// Physical expiry uses the existing bounded manager maintenance transaction.
// Responses independently enforce the exact 24-hour collection-time cutoff.
func pruneResourceHistory(ctx context.Context, t *transaction, now time.Time) error {
	enabled, e := resourceHistoryPresent(ctx, t.conn)
	if e != nil || !enabled {
		return e
	}
	_, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_resource_history WHERE rowid IN (SELECT rowid FROM enrollment_resource_history WHERE bucket<? ORDER BY bucket LIMIT 256)`, now.Add(-ResourceHistoryRetention).Unix()/60)
	if e != nil {
		return ErrStorage
	}
	return nil
}

// RecheckAt prevents time spent waiting/encoding from extending history or a
// certificate. It cannot refresh any collection time or revive expired data.
func (v ResourceHistoryView) RecheckAt(now time.Time) (ResourceHistoryView, error) {
	if !validStoreTime(now) || !validStoreTime(v.ServerNow) {
		return ResourceHistoryView{}, ErrStorage
	}
	now = now.UTC()
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now
	v.WindowStart = now.Add(-ResourceHistoryRetention)
	if v.certificateNotAfter > 0 && now.Unix() >= v.certificateNotAfter && v.Status != "revoked" {
		v.Status = "expired"
		v.Points = []ResourcePoint{}
		return v, nil
	}
	out := make([]ResourcePoint, 0, len(v.Points))
	for _, p := range v.Points {
		if !p.CollectedAt.Before(v.WindowStart) && !p.CollectedAt.After(now) && !p.ReceivedAt.After(now) {
			out = append(out, p)
		}
	}
	v.Points = out
	if v.Status == "available" && len(out) == 0 {
		v.Status = "awaiting"
	}
	return v, nil
}

// ValidateAt checks whether an already encoded view can still be emitted.
// It never re-encodes, refreshes timestamps, or silently removes expired points.
func (v ResourceHistoryView) ValidateAt(now time.Time) error {
	current, err := v.RecheckAt(now)
	if err != nil {
		return err
	}
	if current.Status != v.Status || len(current.Points) != len(v.Points) {
		return enrollmentstate.ErrExpired
	}
	return nil
}

func (s *Store) ResourceHistory(ctx context.Context, device string, now time.Time) (ResourceHistoryView, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") || !validStoreTime(now) {
		return ResourceHistoryView{}, enrollmentstate.ErrInvalid
	}
	if completeProfile(s.config.Binding.CollectionProfile) {
		release, e := s.systemReadAdmission(ctx)
		if e != nil {
			return ResourceHistoryView{}, e
		}
		defer release()
	}
	now, e := systemViewNow(ctx, now)
	if e != nil {
		return ResourceHistoryView{}, e
	}
	out := EmptyResourceHistory(device, now, "awaiting")
	e = s.transact(ctx, func(t *transaction) error {
		var snap enrollmentstate.Snapshot
		found := false
		for _, candidate := range t.engine.Snapshots() {
			if candidate.Approval.DeviceID == device {
				snap = candidate
				found = true
				break
			}
		}
		if !found {
			return enrollmentstate.ErrNotFound
		}
		current, e := systemViewNow(ctx, now)
		if e != nil {
			return e
		}
		out = EmptyResourceHistory(device, current, "awaiting")
		out.certificateNotAfter = snap.Intent.NotAfter
		if current.Unix() < snap.UpdatedAt || current.Unix() < snap.Intent.NotBefore {
			return enrollmentstate.ErrInvalid
		}
		if snap.State == enrollmentstate.Revoked || snap.State == enrollmentstate.Canceled || snap.State == enrollmentstate.Rejected {
			out.Status = "revoked"
			return nil
		}
		if snap.State == enrollmentstate.Expired || snap.Intent.NotAfter > 0 && current.Unix() >= snap.Intent.NotAfter {
			out.Status = "expired"
			return nil
		}
		if snap.State != enrollmentstate.Activated {
			return nil
		}
		c, ok := t.credentials[snap.InvitationID]
		if !ok {
			return ErrStorage
		}
		if current.Before(c.Replay.ReceivedAt) {
			return enrollmentstate.ErrInvalid
		}
		enabled, e := resourceHistoryPresent(ctx, t.conn)
		if e != nil || !enabled {
			return e
		}
		if e = pruneResourceHistory(ctx, t, current); e != nil {
			return e
		}
		rows, e := t.conn.QueryContext(ctx, `SELECT bucket,body FROM enrollment_resource_history WHERE invitation_id=? AND bucket>=? ORDER BY bucket LIMIT 1442`, snap.InvitationID, out.WindowStart.Unix()/60)
		if e != nil {
			return ErrStorage
		}
		defer rows.Close()
		var previous uint64
		var last time.Time
		for rows.Next() {
			var bucket int64
			var raw []byte
			var p ResourcePoint
			if rows.Scan(&bucket, &raw) != nil || len(raw) > 1024 || json.Unmarshal(raw, &p) != nil || !validResourcePoint(p) {
				return ErrStorage
			}
			canonical, _ := json.Marshal(p)
			seq, _ := strconv.ParseUint(p.Sequence, 10, 64)
			if !bytes.Equal(canonical, raw) || bucket != p.CollectedAt.Unix()/60 || seq <= previous || seq > c.Replay.Sequence || !last.IsZero() && !p.CollectedAt.After(last) || p.CollectedAt.After(c.Replay.CollectedAt) || p.ReceivedAt.After(c.Replay.ReceivedAt) || p.ReceivedAt.Unix() < snap.Activation.At || p.ReceivedAt.Unix() >= snap.Intent.NotAfter {
				return ErrStorage
			}
			previous = seq
			last = p.CollectedAt
			if !p.CollectedAt.Before(out.WindowStart) && !p.CollectedAt.After(out.ServerNow) {
				out.Points = append(out.Points, p)
			}
			if len(out.Points) > ResourceHistoryLimit {
				return ErrStorage
			}
		}
		if rows.Err() != nil {
			return ErrStorage
		}
		if len(out.Points) > 0 {
			out.Status = "available"
		}
		return nil
	})
	if e != nil {
		return ResourceHistoryView{}, e
	}
	current, e := systemViewNow(ctx, out.ServerNow)
	if e != nil {
		return ResourceHistoryView{}, e
	}
	return out.RecheckAt(current)
}
