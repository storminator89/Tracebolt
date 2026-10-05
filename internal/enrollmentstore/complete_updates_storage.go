package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/updategeneration"
	"strings"
	"time"
)

const completeUpdatesMetaSchema = `CREATE TABLE enrollment_complete_updates_meta(id INTEGER PRIMARY KEY CHECK(id=1),cursor_key BLOB NOT NULL CHECK(length(cursor_key)=32)) STRICT`
const completeUpdatesAuthoritySchema = `CREATE TABLE enrollment_complete_updates_authority(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=12288)) STRICT`
const completeUpdatesGenerationsSchema = `CREATE TABLE enrollment_complete_updates_generations(device TEXT NOT NULL,generation TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=4096),state TEXT NOT NULL CHECK(state IN ('staging','current','retired','garbage')),started_at TEXT NOT NULL,expires_at TEXT NOT NULL,completed_at TEXT NOT NULL,retired_at TEXT NOT NULL,declared_rows INTEGER NOT NULL CHECK(declared_rows>=0 AND declared_rows<=16384),declared_chunks INTEGER NOT NULL CHECK(declared_chunks>=0 AND declared_chunks<=1024),next_row INTEGER NOT NULL CHECK(next_row>=0 AND next_row<=declared_rows),next_chunk INTEGER NOT NULL CHECK(next_chunk>=0 AND next_chunk<=declared_chunks),row_bytes INTEGER NOT NULL CHECK(row_bytes>=0 AND row_bytes<=33554432),wire_bytes INTEGER NOT NULL CHECK(wire_bytes>0 AND wire_bytes<=50331648),stored_bytes INTEGER NOT NULL CHECK(stored_bytes>0 AND stored_bytes<=50331648),live_rows INTEGER NOT NULL CHECK(live_rows>=0 AND live_rows<=next_row),live_chunks INTEGER NOT NULL CHECK(live_chunks>=0 AND live_chunks<=next_chunk),last_hash TEXT NOT NULL,last_name TEXT NOT NULL,last_arch TEXT NOT NULL,PRIMARY KEY(device,generation)) STRICT`
const completeUpdatesChunksSchema = `CREATE TABLE enrollment_complete_updates_chunks(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<1024),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=65536),received_at TEXT NOT NULL,PRIMARY KEY(device,generation,ordinal),FOREIGN KEY(device,generation) REFERENCES enrollment_complete_updates_generations(device,generation) ON DELETE CASCADE) STRICT`
const completeUpdatesRowsSchema = `CREATE TABLE enrollment_complete_updates_rows(device TEXT NOT NULL,generation TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<16384),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=2048),body_hash TEXT NOT NULL CHECK(length(body_hash)=64),PRIMARY KEY(device,generation,ordinal),FOREIGN KEY(device,generation) REFERENCES enrollment_complete_updates_generations(device,generation) ON DELETE CASCADE) STRICT`

func completeUpdatesSchemaObjects() []inventoryledger.SchemaObject {
	var out []inventoryledger.SchemaObject
	for _, q := range []string{completeUpdatesMetaSchema, completeUpdatesAuthoritySchema, completeUpdatesGenerationsSchema, completeUpdatesChunksSchema, completeUpdatesRowsSchema} {
		name := strings.SplitN(strings.SplitN(q, " ", 4)[2], "(", 2)[0]
		out = append(out, inventoryledger.SchemaObject{Type: "table", Name: name, SQL: q})
	}
	return out
}
func completeUpdatesSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_complete_updates\_%' ESCAPE '\'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if n != len(completeUpdatesSchemaObjects()) {
		return false, ErrStorage
	}
	return true, nil
}
func (s *Store) InitializeCompleteUpdates(ctx context.Context) error {
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		if !completeProfile(s.config.Binding.CollectionProfile) {
			return enrollmentstate.ErrProof
		}
		if t.completeUpdatesEnabled {
			return nil
		}
		for _, o := range completeUpdatesSchemaObjects() {
			if _, e = t.conn.ExecContext(ctx, o.SQL); e != nil {
				return ErrStorage
			}
		}
		var key [32]byte
		if _, e = rand.Read(key[:]); e != nil {
			return ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_complete_updates_meta VALUES(1,?)`, key[:]); e != nil {
			return ErrStorage
		}
		if e = validateSchema(ctx, t.conn, s.config.Binding.CollectionProfile); e != nil {
			return e
		}
		return s.loadCompleteUpdates(ctx, t)
	})
}
func completeUpdatesStamp(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339Nano)
}
func completeUpdatesTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	at, e := time.Parse(time.RFC3339Nano, raw)
	if e != nil || !validStoreTime(at) || at.Location() != time.UTC || completeUpdatesStamp(at) != raw {
		return time.Time{}, ErrStorage
	}
	return at, nil
}

type completeUpdatesGeneration struct {
	Device                                                                     string
	Binding                                                                    InventoryBinding
	Manifest                                                                   updategeneration.Manifest
	State                                                                      string
	Started, Expires, Completed, Retired                                       time.Time
	NextRow, NextChunk, RowBytes, WireBytes, StoredBytes, LiveRows, LiveChunks int64
	LastHash, LastName, LastArch                                               string
}

const completeUpdatesGenerationColumns = `device,generation,sequence,manifest_hash,manifest,state,started_at,expires_at,completed_at,retired_at,declared_rows,declared_chunks,next_row,next_chunk,row_bytes,wire_bytes,stored_bytes,live_rows,live_chunks,last_hash,last_name,last_arch`

type completeUpdatesScanner interface{ Scan(...any) error }

func scanCompleteUpdatesGeneration(row completeUpdatesScanner) (completeUpdatesGeneration, error) {
	var g completeUpdatesGeneration
	var raw []byte
	var start, expiry, completed, retired string
	var nr, nc int64
	e := row.Scan(&g.Device, &g.Binding.GenerationID, &g.Binding.Sequence, &g.Binding.ManifestHash, &raw, &g.State, &start, &expiry, &completed, &retired, &nr, &nc, &g.NextRow, &g.NextChunk, &g.RowBytes, &g.WireBytes, &g.StoredBytes, &g.LiveRows, &g.LiveChunks, &g.LastHash, &g.LastName, &g.LastArch)
	if errors.Is(e, sql.ErrNoRows) {
		return g, inventoryledger.ErrNotFound
	}
	if e != nil {
		return g, ErrStorage
	}
	g.Manifest, e = updategeneration.DecodeManifest(raw)
	if e != nil {
		return g, ErrStorage
	}
	canonical, _ := json.Marshal(g.Manifest)
	if !bytes.Equal(canonical, raw) || !validCompleteUpdatesManifest(g.Binding, g.Manifest) || nr != int64(g.Manifest.CandidateCount) || nc != int64(g.Manifest.ChunkCount) {
		return g, ErrStorage
	}
	want, e := inventorywire.CachedUpdatesGenerationID(g.Device, g.Binding.Sequence)
	if e != nil || want != g.Binding.GenerationID {
		return g, ErrStorage
	}
	if g.Started, e = completeUpdatesTime(start); e != nil {
		return g, e
	}
	if g.Expires, e = completeUpdatesTime(expiry); e != nil {
		return g, e
	}
	if g.Completed, e = completeUpdatesTime(completed); e != nil {
		return g, e
	}
	if g.Retired, e = completeUpdatesTime(retired); e != nil {
		return g, e
	}
	if g.Started.IsZero() || !g.Expires.Equal(g.Started.Add(inventoryledger.StagingTTL)) || g.Manifest.CollectedAt.After(g.Started) || g.NextRow < 0 || g.NextRow > nr || g.NextChunk < 0 || g.NextChunk > nc || g.RowBytes < 0 || g.RowBytes > int64(g.Manifest.CanonicalRowBytes) || g.WireBytes < int64(len(raw)) || g.WireBytes > updategeneration.MaxCanonicalWireBytes || g.StoredBytes < int64(len(raw)) || g.StoredBytes > inventoryLimits().GenerationBytes || g.LiveRows < 0 || g.LiveRows > g.NextRow || g.LiveChunks < 0 || g.LiveChunks > g.NextChunk {
		return g, ErrStorage
	}
	if g.NextChunk == 0 && (g.NextRow != 0 || g.RowBytes != 0 || g.LastHash != "" || g.LastName != "" || g.LastArch != "") {
		return g, ErrStorage
	}
	if g.NextChunk > 0 && (g.NextRow == 0 || len(g.LastHash) != 64 || g.LastName == "" || g.LastArch == "") {
		return g, ErrStorage
	}
	switch g.State {
	case "staging":
		if !g.Completed.IsZero() || !g.Retired.IsZero() {
			return g, ErrStorage
		}
	case "current", "retired":
		if g.Completed.IsZero() || g.Completed.Before(g.Started) || !g.Completed.Before(g.Expires) || !g.Completed.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) || g.NextRow != nr || g.NextChunk != nc || g.RowBytes != int64(g.Manifest.CanonicalRowBytes) {
			return g, ErrStorage
		}
		if g.State == "current" && !g.Retired.IsZero() || g.State == "retired" && (g.Retired.IsZero() || g.Retired.Before(g.Completed)) {
			return g, ErrStorage
		}
	case "garbage":
	default:
		return g, ErrStorage
	}
	if g.State != "garbage" && (g.LiveRows != g.NextRow || g.LiveChunks != g.NextChunk) {
		return g, ErrStorage
	}
	return g, nil
}
func loadCompleteUpdatesGeneration(ctx context.Context, t *transaction, device, generation string) (completeUpdatesGeneration, error) {
	return scanCompleteUpdatesGeneration(t.conn.QueryRowContext(ctx, `SELECT `+completeUpdatesGenerationColumns+` FROM enrollment_complete_updates_generations WHERE device=? AND generation=?`, device, generation))
}

// Restore only a bounded authority/header set. No chunk or candidate payload is
// read by routine authentication, lifecycle changes or other inventory domains.
func (s *Store) loadCompleteUpdates(ctx context.Context, t *transaction) error {
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	present, e := completeUpdatesSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	t.completeUpdatesEnabled = present
	if !present {
		return nil
	}
	var key []byte
	if t.conn.QueryRowContext(ctx, `SELECT cursor_key FROM enrollment_complete_updates_meta WHERE id=1`).Scan(&key) != nil || len(key) != 32 {
		return ErrStorage
	}
	copy(t.completeUpdatesKey[:], key)
	if t.completeUpdatesKey == (completeUpdatesCursorKey{}) {
		return ErrStorage
	}
	var n int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_complete_updates_authority`).Scan(&n) != nil || n > s.config.RecordLimit {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id FROM enrollment_complete_updates_authority ORDER BY invitation_id`)
	if e != nil {
		return ErrStorage
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return ErrStorage
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	known := map[string]completeUpdatesRecord{}
	for _, id := range ids {
		r, e := readCompleteUpdatesRecord(ctx, t, id)
		if e != nil {
			return e
		}
		snap, e := t.engine.Get(id)
		if e != nil {
			return ErrStorage
		}
		known[snap.Approval.DeviceID] = r
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_complete_updates_generations`).Scan(&n) != nil || int64(n) > inventoryLimits().GlobalGenerations {
		return ErrStorage
	}
	rows, e = t.conn.QueryContext(ctx, `SELECT `+completeUpdatesGenerationColumns+` FROM enrollment_complete_updates_generations ORDER BY device,generation`)
	if e != nil {
		return ErrStorage
	}
	seenCurrent, seenLatest := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		g, e := scanCompleteUpdatesGeneration(rows)
		r, ok := known[g.Device]
		if e != nil || !ok || g.Binding.Sequence > r.Binding.Sequence {
			rows.Close()
			return ErrStorage
		}
		if g.Binding == r.Binding {
			seenLatest[g.Device] = true
			if r.Manifest == nil || g.Started != r.StartedAt || r.State == "complete" && g.State != "current" && (g.State != "garbage" || r.MaintenanceAt == nil || r.MaintenanceAt.Before(g.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL))) || r.State == "aborted" && g.State != "garbage" || r.State == "pending" && g.State != "staging" && g.State != "garbage" {
				rows.Close()
				return ErrStorage
			}
		}
		if g.State == "staging" && g.Binding != r.Binding {
			rows.Close()
			return ErrStorage
		}
		if g.State == "current" {
			if seenCurrent[g.Device] || r.Complete == nil || g.Binding != r.Complete.Binding || g.Started != r.Complete.StartedAt || g.Completed != r.Complete.CompletedAt {
				rows.Close()
				return ErrStorage
			}
			seenCurrent[g.Device] = true
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	for device, r := range known {
		if r.Complete != nil && !seenCurrent[device] && r.LastAt.Before(r.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)) && (r.MaintenanceAt == nil || r.MaintenanceAt.Before(r.Complete.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL))) {
			return ErrStorage
		}
		latestExpiry := r.StartedAt.Add(inventoryledger.StagingTTL)
		if r.Manifest != nil {
			retentionExpiry := r.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL)
			if r.State == "complete" || retentionExpiry.Before(latestExpiry) {
				latestExpiry = retentionExpiry
			}
		}
		if r.Manifest != nil && !seenLatest[device] && r.State != "aborted" && r.LastAt.Before(latestExpiry) && (r.MaintenanceAt == nil || r.MaintenanceAt.Before(latestExpiry)) {
			return ErrStorage
		}
	}
	return completeUpdatesBudgets(ctx, t, true)
}
func completeUpdatesBudgets(ctx context.Context, t *transaction, stored bool) error {
	if !t.completeUpdatesEnabled {
		return nil
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT device,sum(declared_rows),sum(declared_chunks),sum(stored_bytes),count(*) FROM enrollment_complete_updates_generations GROUP BY device`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	var totalR, totalC, totalB, totalG int64
	l := inventoryLimits()
	for rows.Next() {
		var device string
		var nr, nc, nb, ng int64
		if rows.Scan(&device, &nr, &nc, &nb, &ng) != nil {
			return ErrStorage
		}
		if nr > l.DeviceRows || nc > l.DeviceChunks || nb > l.DeviceBytes || ng > l.DeviceGenerations {
			if stored {
				return ErrStorage
			}
			return inventoryledger.ErrQuota
		}
		totalR += nr
		totalC += nc
		totalB += nb
		totalG += ng
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	if totalR > l.GlobalRows || totalC > l.GlobalChunks || totalB > l.GlobalBytes || totalG > l.GlobalGenerations {
		if stored {
			return ErrStorage
		}
		return inventoryledger.ErrQuota
	}
	return nil
}

// Recheck the small records after lifecycle mutations in this same transaction.
// A termination timestamp cannot precede an accepted update-domain receipt.
func validateCompleteUpdatesRecords(ctx context.Context, t *transaction) error {
	if !t.completeUpdatesEnabled {
		return nil
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id,body FROM enrollment_complete_updates_authority ORDER BY invitation_id`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		var r completeUpdatesRecord
		if rows.Scan(&id, &raw) != nil || len(raw) == 0 || len(raw) > 12288 || json.Unmarshal(raw, &r) != nil {
			return ErrStorage
		}
		snap, e := t.engine.Get(id)
		canonical, _ := json.Marshal(r)
		if e != nil || !bytes.Equal(raw, canonical) || !validCompleteUpdatesRecord(snap, r) {
			return ErrStorage
		}
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	return nil
}
