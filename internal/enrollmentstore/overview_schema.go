package enrollmentstore

import (
	"context"
	"database/sql"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"strings"
)

func validOverviewSection(s string) bool          { return s == "processes" || s == "volumes" }
func overviewRecordKey(id, section string) string { return id + ":" + section }
func overviewDevice(id, section string) string    { return id + ":" + section }

func overviewSchemaObjects() []inventoryledger.SchemaObject {
	out := []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_overview_meta", SQL: overviewMetaSchema}, {Type: "table", Name: "enrollment_overview_authority", SQL: overviewAuthoritySchema}, {Type: "table", Name: "enrollment_overview_generations", SQL: overviewGenerationsSchema}}
	for _, o := range overviewledger.SchemaObjects() {
		out = append(out, inventoryledger.SchemaObject{Type: o.Type, Name: o.Name, SQL: o.SQL})
	}
	return out
}
func overviewSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'co\_%' ESCAPE '\' OR name LIKE 'enrollment_overview\_%' ESCAPE '\'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if n != len(overviewSchemaObjects()) {
		return false, ErrStorage
	}
	return true, nil
}

// InitializeOverview explicitly installs only the checked optional extension in
// an existing protected current-v3 database. It neither resets nor migrates any
// existing table, binding, credential, floor or pending package byte. This does
// not grant endpoint collection consent. The exact legacy schema and authority
// are checked before the addition, inside the same BEGIN IMMEDIATE transaction.
func (s *Store) InitializeOverview(ctx context.Context) error {
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		if !completeProfile(s.config.Binding.CollectionProfile) {
			return enrollmentstate.ErrProof
		}
		if t.overviewEnabled {
			return nil
		}
		if e := initializeOverview(ctx, t.conn); e != nil {
			return e
		}
		if e := validateSchema(ctx, t.conn, s.config.Binding.CollectionProfile); e != nil {
			return e
		}
		return s.loadOverview(ctx, t)
	})
}

// Validate only small normalized ownership/count/accounting metadata. Ordinary
// authority transactions never read complete row/chunk sets or every checkpoint.
func validateOverviewBudgets(ctx context.Context, t *transaction) error {
	limits := overviewLimits()
	var n, bindings, orphans int64
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_generations`).Scan(&n) != nil || n > limits.GlobalGenerations || t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_overview_generations`).Scan(&bindings) != nil || bindings != n {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_generations g LEFT JOIN enrollment_overview_generations b ON g.device=b.device AND g.generation=b.generation LEFT JOIN co_devices d ON g.device=d.device WHERE b.generation IS NULL OR d.device IS NULL`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT scope,held_rows,held_chunks,stored_bytes,generations FROM co_budget ORDER BY scope`)
	if e != nil {
		return ErrStorage
	}
	type budget struct {
		scope                            string
		rows, chunks, bytes, generations int64
	}
	all := []budget{}
	for rows.Next() {
		var b budget
		if rows.Scan(&b.scope, &b.rows, &b.chunks, &b.bytes, &b.generations) != nil {
			rows.Close()
			return ErrStorage
		}
		all = append(all, b)
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	var deviceCount int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_devices`).Scan(&deviceCount) != nil {
		return ErrStorage
	}
	if len(all) < 1 || len(all) > 51 || all[0].scope != "" || len(all) != deviceCount+1 {
		return ErrStorage
	}
	for _, b := range all {
		var actual budget
		q := `SELECT coalesce(sum(declared_rows),0),coalesce(sum(declared_chunks),0),coalesce(sum(stored_bytes),0),count(*) FROM co_generations`
		args := []any{}
		if b.scope != "" {
			q += ` WHERE device=?`
			args = append(args, b.scope)
		}
		if t.conn.QueryRowContext(ctx, q, args...).Scan(&actual.rows, &actual.chunks, &actual.bytes, &actual.generations) != nil || actual.rows != b.rows || actual.chunks != b.chunks || actual.bytes != b.bytes || actual.generations != b.generations {
			return ErrStorage
		}
		maxRows, maxChunks, maxBytes, maxGen := limits.DeviceRows, limits.DeviceChunks, limits.DeviceBytes, limits.DeviceGenerations
		if b.scope == "" {
			maxRows, maxChunks, maxBytes, maxGen = limits.GlobalRows, limits.GlobalChunks, limits.GlobalBytes, limits.GlobalGenerations
		}
		if b.rows < 0 || b.chunks < 0 || b.bytes < 0 || b.generations < 0 || b.rows > maxRows || b.chunks > maxChunks || b.bytes > maxBytes || b.generations > maxGen {
			return ErrStorage
		}
	}
	known := map[string]overviewRecord{}
	for key, r := range t.overview {
		id, section, _ := strings.Cut(key, ":")
		snap, e := t.engine.Get(id)
		if e != nil {
			return ErrStorage
		}
		known[overviewDevice(snap.Approval.DeviceID, section)] = r
	}
	for _, b := range all {
		if b.scope != "" {
			if _, ok := known[b.scope]; !ok {
				return ErrStorage
			}
		}
	}
	devices, e := t.conn.QueryContext(ctx, `SELECT device,current_generation,staging_generation FROM co_devices`)
	if e != nil {
		return ErrStorage
	}
	for devices.Next() {
		var device, current, staged string
		if devices.Scan(&device, &current, &staged) != nil {
			devices.Close()
			return ErrStorage
		}
		r, ok := known[device]
		if !ok || staged != "" && (r.State != "pending" || staged != r.Binding.GenerationID) || r.State == "complete" && current != r.Binding.GenerationID {
			devices.Close()
			return ErrStorage
		}
	}
	if devices.Err() != nil {
		devices.Close()
		return ErrStorage
	}
	if devices.Close() != nil {
		return ErrStorage
	}
	bindingsRows, e := t.conn.QueryContext(ctx, `SELECT device,generation,sequence,manifest_hash FROM enrollment_overview_generations`)
	if e != nil {
		return ErrStorage
	}
	for bindingsRows.Next() {
		var device, generation, hash string
		var seq uint64
		if bindingsRows.Scan(&device, &generation, &seq, &hash) != nil {
			bindingsRows.Close()
			return ErrStorage
		}
		r, ok := known[device]
		public, section, parsed := strings.Cut(device, ":")
		want, e := overviewwire.GenerationID(public, section, seq)
		if !ok || !parsed || e != nil || want != generation || seq > r.Binding.Sequence || !(OverviewBinding{Section: section, Sequence: seq, GenerationID: generation, ManifestHash: hash}).valid() {
			bindingsRows.Close()
			return ErrStorage
		}
	}
	if bindingsRows.Err() != nil {
		bindingsRows.Close()
		return ErrStorage
	}
	if bindingsRows.Close() != nil {
		return ErrStorage
	}
	// Pointers must refer to retained generations in the same fixed namespace.
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_devices d LEFT JOIN co_generations c ON d.device=c.device AND d.current_generation=c.generation LEFT JOIN co_generations s ON d.device=s.device AND d.staging_generation=s.generation WHERE (d.current_generation<>'' AND (c.state IS NULL OR c.state<>'current')) OR (d.staging_generation<>'' AND (s.state IS NULL OR s.state<>'staging'))`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM co_generations g JOIN co_devices d ON g.device=d.device WHERE (g.state='current' AND d.current_generation<>g.generation) OR (g.state='staging' AND d.staging_generation<>g.generation)`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	return nil
}

// All complete-inventory domains share one global logical rejection ceiling.
// This check runs before COMMIT for package, overview, system and authority calls,
// so interleaving domains cannot each spend the global allowance independently.
// The existing DB/WAL/SHM physical bounds apply to this same database unchanged.
func sharedInventoryBudget(ctx context.Context, t *transaction) error {
	if !t.overviewEnabled {
		return nil
	}
	var rows, chunks, stored, generations, systemBytes int64
	q := `SELECT sum(held_rows),sum(held_chunks),sum(stored_bytes),sum(generations) FROM (SELECT * FROM fi_budget WHERE scope='' UNION ALL SELECT * FROM co_budget WHERE scope='')`
	if t.conn.QueryRowContext(ctx, q).Scan(&rows, &chunks, &stored, &generations) != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(payload_bytes) FROM enrollment_system_sections),0)+coalesce((SELECT sum(length(body)) FROM enrollment_system_authority),0)`).Scan(&systemBytes) != nil {
		return ErrStorage
	}
	l := inventoryLimits()
	if rows > l.GlobalRows || chunks > l.GlobalChunks || stored+systemBytes > l.GlobalBytes || generations > l.GlobalGenerations {
		return inventoryledger.ErrQuota
	}
	byDevice, e := t.conn.QueryContext(ctx, `SELECT substr(scope,1,38),sum(held_rows),sum(held_chunks),sum(stored_bytes) FROM (SELECT * FROM fi_budget WHERE scope<>'' UNION ALL SELECT * FROM co_budget WHERE scope<>'') GROUP BY substr(scope,1,38)`)
	if e != nil {
		return ErrStorage
	}
	defer byDevice.Close()
	for byDevice.Next() {
		var device string
		var rows, chunks, bytes int64
		if byDevice.Scan(&device, &rows, &chunks, &bytes) != nil {
			return ErrStorage
		}
		if rows > l.DeviceRows || chunks > l.DeviceChunks || bytes > l.DeviceBytes {
			return inventoryledger.ErrQuota
		}
	}
	if byDevice.Err() != nil {
		return ErrStorage
	}
	return nil
}
