package overviewledger

import (
	"context"
	"database/sql"
	"errors"
	"localrmm/internal/overviewgeneration"
	"strings"
	"time"
)

// SchemaObject is an exact SQLite schema allowlist entry. It does not authorize
// adoption or migration; the authority owner still selects its fresh profile.
type SchemaObject struct{ Type, Name, SQL string }

func SchemaObjects() []SchemaObject {
	out := make([]SchemaObject, 0, len(schema))
	for _, q := range schema {
		p := strings.SplitN(q, " ", 4)
		name := strings.SplitN(p[2], "(", 2)[0]
		out = append(out, SchemaObject{strings.ToLower(p[1]), name, q})
	}
	return out
}

// Check verifies the exact persisted logical limit binding without reading rows.
func (l *Ledger) Check(ctx context.Context, tx Transaction) error { return l.check(ctx, tx) }

// GenerationStatus is bounded metadata, never proof of complete rows by itself.
// State is pending, complete, retired, expired, or failed. An expired complete
// inventory retains its original manifest and completion timestamps.
type GenerationStatus struct {
	Manifest                          overviewgeneration.Manifest
	State                             string
	StartedAt, ExpiresAt, CompletedAt time.Time
	AcceptedChunks                    uint32
	AcceptedRows                      uint64
}

func (l *Ledger) GenerationStatus(ctx context.Context, tx Transaction, device, id string, now time.Time) (GenerationStatus, error) {
	if e := l.check(ctx, tx); e != nil {
		return GenerationStatus{}, e
	}
	if !validDevice(device) || !validGeneration(id) || !validTime(now) {
		return GenerationStatus{}, ErrInvalid
	}
	g, e := loadGeneration(ctx, tx, device, id)
	if e != nil {
		return GenerationStatus{}, e
	}
	if now.Before(g.started) || now.Before(g.completed) || g.manifest.CollectedAt.After(now) {
		return GenerationStatus{}, ErrExpired
	}
	if g.state != "garbage" {
		if e = checkReceiptClock(ctx, tx, g, now); e != nil {
			return GenerationStatus{}, e
		}
	}
	expires := g.expires
	if g.state == "current" || g.state == "retired" {
		expires = g.manifest.CollectedAt.Add(ObservationTTL)
	}
	state := g.state
	switch state {
	case "staging":
		state = "pending"
		if !now.Before(g.expires) {
			state = "expired"
		}
	case "current":
		state = "complete"
		if !now.Before(g.manifest.CollectedAt.Add(ObservationTTL)) {
			state = "expired"
		}
	case "retired":
		if !now.Before(g.manifest.CollectedAt.Add(ObservationTTL)) {
			state = "expired"
		}
	case "garbage":
		state = "failed"
	}
	return GenerationStatus{g.manifest, state, g.started, expires, g.completed, uint32(g.nextChunk), uint64(g.nextRow)}, nil
}

// CurrentStatus reads only the current pointer and its bounded metadata.
func (l *Ledger) CurrentStatus(ctx context.Context, tx Transaction, device string, now time.Time) (GenerationStatus, error) {
	if e := l.check(ctx, tx); e != nil {
		return GenerationStatus{}, e
	}
	if !validDevice(device) || !validTime(now) {
		return GenerationStatus{}, ErrInvalid
	}
	var id string
	e := tx.QueryRowContext(ctx, `SELECT current_generation FROM co_devices WHERE device=?`, device).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) || e == nil && id == "" {
		return GenerationStatus{}, ErrNotFound
	}
	if e != nil {
		return GenerationStatus{}, ErrStorage
	}
	return l.GenerationStatus(ctx, tx, device, id, now)
}
