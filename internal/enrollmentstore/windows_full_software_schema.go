package enrollmentstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
)

func windowsFullSoftwareSchemaPresent(ctx context.Context, c *sql.Conn, profile string) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'wfw\_%' ESCAPE '\'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if profile != enrollmentcrypto.CollectionProfileWindowsInventory || n != len(ledger.SchemaObjects()) {
		return false, ErrStorage
	}
	var version, count int
	var key []byte
	var last string
	if c.QueryRowContext(ctx, `SELECT count(*) FROM wfw_meta`).Scan(&count) != nil || count != 1 || c.QueryRowContext(ctx, `SELECT version,cursor_key,last_time FROM wfw_meta WHERE id=1`).Scan(&version, &key, &last) != nil || version != 1 || len(key) != 32 {
		return false, ErrStorage
	}
	if last != "" {
		if _, e := windowsEventTime(last); e != nil {
			return false, e
		}
	}
	return true, nil
}
func (s *Store) InitializeWindowsFullSoftware(ctx context.Context) error {
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil || present {
			return e
		}
		if e = ledger.Initialize(ctx, t.conn); e != nil {
			return e
		}
		return validateSchema(ctx, t.conn, s.config.Binding.CollectionProfile)
	})
}

// The immutable credential-used bit makes a missing used authority/floor a hard
// storage error even if all optional extension tables have been removed.
func validateWindowsFullSoftwareState(ctx context.Context, t *transaction, profile string) error {
	used := map[string]string{}
	ids := map[string]string{}
	for id, c := range t.credentials {
		if !c.WindowsFullSoftwareInitialized {
			continue
		}
		snap, e := t.engine.Get(id)
		if e != nil || profile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" || snap.Activation.At == 0 {
			return ErrStorage
		}
		used[snap.Approval.DeviceID] = snap.Issuance.CertificateHash
		ids[snap.Approval.DeviceID] = id
	}
	present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, profile)
	if e != nil {
		return e
	}
	if !present {
		if len(used) > 0 {
			return ErrStorage
		}
		return nil
	}
	rr, e := t.conn.QueryContext(ctx, `SELECT device,invitation,certificate FROM wfw_authority ORDER BY device`)
	if e != nil {
		return ErrStorage
	}
	devices := []string{}
	for rr.Next() {
		var device, invite, cert string
		if rr.Scan(&device, &invite, &cert) != nil || used[device] != cert || ids[device] != invite || cert == "" {
			rr.Close()
			return ErrStorage
		}
		devices = append(devices, device)
	}
	if rr.Err() != nil {
		rr.Close()
		return ErrStorage
	}
	if rr.Close() != nil || len(devices) != len(used) || len(devices) > 25 {
		return ErrStorage
	}
	known := map[string]ledger.Record{}
	for _, device := range devices {
		r, e := ledger.LoadRecord(ctx, t.conn, device)
		if e != nil {
			return ErrStorage
		}
		snap, _ := t.engine.Get(ids[device])
		expected := windowsfullsoftware.SenderBinding(snap.Binding.Profile, r.IngressOrigin, snap.Issuance.CertificateHash, device)
		m, e := windowsfullsoftware.DecodeMessage(r.ScopeRaw)
		if e != nil || !validWindowsFullSoftwareOrigin(r.IngressOrigin, snap.Binding.Profile) || m.Operation != "scope" || m.DeviceID != device || m.Consent != r.Consent || r.Consent.SenderBinding != expected || r.Consent.ChangedAt.Unix() < snap.Activation.At || r.LastAt.Unix() < snap.Activation.At {
			return ErrStorage
		}
		receiptRaw, _ := json.Marshal(r.ScopeReceipt)
		if _, e = windowsfullsoftware.DecodeReceipt(receiptRaw, r.ScopeRaw); e != nil {
			return ErrStorage
		}
		if r.Latest != nil && (r.Latest.Sequence != r.Floor || !windowsfullsoftware.ValidTime(r.Latest.AttemptedAt)) {
			return ErrStorage
		}
		if r.FailureReceipt != nil {
			fm, e := windowsfullsoftware.DecodeMessage(r.FailureRaw)
			fr, _ := json.Marshal(r.FailureReceipt)
			if e != nil || fm.Sequence != r.Floor || fm.Consent != r.Consent || fm.Operation != "failure" {
				return ErrStorage
			}
			if _, e = windowsfullsoftware.DecodeReceipt(fr, r.FailureRaw); e != nil {
				return ErrStorage
			}
		}
		if !r.Consent.Enabled && (r.Current != "" || r.Pending != "") {
			return ErrStorage
		}
		known[device] = r
	}
	rr, e = t.conn.QueryContext(ctx, `SELECT device,generation,state,declared_rows,declared_chunks,next_row,next_chunk,(SELECT count(*) FROM wfw_rows r WHERE r.device=g.device AND r.generation=g.generation),(SELECT count(*) FROM wfw_chunks c WHERE c.device=g.device AND c.generation=g.generation) FROM wfw_generations g`)
	if e != nil {
		return ErrStorage
	}
	count := 0
	for rr.Next() {
		var device, generation, state string
		var declaredRows, declaredChunks, nextRow, nextChunk, rows, chunks int
		if rr.Scan(&device, &generation, &state, &declaredRows, &declaredChunks, &nextRow, &nextChunk, &rows, &chunks) != nil {
			rr.Close()
			return ErrStorage
		}
		r, ok := known[device]
		if !ok || state == "current" && (r.Current != generation || nextRow != declaredRows || nextChunk != declaredChunks) || state == "staging" && r.Pending != generation || state != "garbage" && (rows != nextRow || chunks != nextChunk) {
			rr.Close()
			return ErrStorage
		}
		count++
	}
	if rr.Err() != nil {
		rr.Close()
		return ErrStorage
	}
	if rr.Close() != nil || count > ledger.MaxGlobalGenerations {
		return ErrStorage
	}
	for device, r := range known {
		for _, id := range []string{r.Current, r.Pending} {
			if id == "" {
				continue
			}
			g, e := ledger.LoadGeneration(ctx, t.conn, device, id)
			if e != nil || g.Manifest.Sequence > r.Floor || g.Manifest.GrantID != r.Consent.GrantID || g.Manifest.GrantRevision != r.Consent.Revision {
				return ErrStorage
			}
		}
	}
	var orphans int
	if t.conn.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM wfw_rows r LEFT JOIN wfw_generations g ON r.device=g.device AND r.generation=g.generation WHERE g.generation IS NULL)+(SELECT count(*) FROM wfw_chunks c LEFT JOIN wfw_generations g ON c.device=g.device AND c.generation=g.generation WHERE g.generation IS NULL)`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	return windowsFullSoftwareBudget(ctx, t)
}
func windowsFullSoftwareOtherBytes(ctx context.Context, t *transaction) (int64, error) {
	var extra int64
	// Base authority/credentials/telemetry share the same global logical byte cap.
	if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(length(ledger)) FROM enrollment_state),0)+coalesce((SELECT sum(length(body)) FROM enrollment_credentials),0)+coalesce((SELECT sum(length(body)) FROM wfw_authority),0)`).Scan(&extra) != nil {
		return 0, ErrStorage
	}
	present, e := windowsEventSchemaPresent(ctx, t.conn, enrollmentcrypto.CollectionProfileWindowsInventory)
	if e != nil {
		return 0, e
	}
	if present {
		var n int64
		if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(length(capability)) FROM enrollment_windows_event_authority),0)+coalesce((SELECT sum(length(body)) FROM enrollment_windows_event_requests),0)`).Scan(&n) != nil {
			return 0, ErrStorage
		}
		extra += n
	}
	present, e = resourceHistoryPresent(ctx, t.conn)
	if e != nil {
		return 0, e
	}
	if present {
		var n int64
		if t.conn.QueryRowContext(ctx, `SELECT coalesce(sum(length(body)),0) FROM enrollment_resource_history`).Scan(&n) != nil {
			return 0, ErrStorage
		}
		extra += n
	}
	// The global byte ceiling is shared across all complete Windows domains.
	// Count reservations and authority bytes without recursive budget checks.
	present, e = windowsFullServicesSchemaPresent(ctx, t.conn, enrollmentcrypto.CollectionProfileWindowsInventory)
	if e != nil {
		return 0, e
	}
	if present {
		var n int64
		if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(length(body)) FROM wfs_authority),0)+coalesce((SELECT sum(reserved_bytes) FROM wfs_generations),0)`).Scan(&n) != nil {
			return 0, ErrStorage
		}
		extra += n
	}
	present, e = windowsFullProcessesSchemaPresent(ctx, t.conn, enrollmentcrypto.CollectionProfileWindowsInventory)
	if e != nil {
		return 0, e
	}
	if present {
		var n int64
		if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(length(body)) FROM wfp_authority),0)+coalesce((SELECT sum(reserved_bytes) FROM wfp_generations),0)`).Scan(&n) != nil {
			return 0, ErrStorage
		}
		extra += n
	}
	present, e = windowsNetworkContextSchemaPresent(ctx, t.conn, enrollmentcrypto.CollectionProfileWindowsInventory)
	if e != nil {
		return 0, e
	}
	if present {
		var n int64
		if t.conn.QueryRowContext(ctx, `SELECT coalesce((SELECT sum(length(body)) FROM wnc_authority),0)+coalesce((SELECT sum(reserved_bytes) FROM wnc_generations),0)`).Scan(&n) != nil {
			return 0, ErrStorage
		}
		extra += n
	}
	return extra, nil
}
func readWindowsFullSoftwareRecord(ctx context.Context, t *transaction, device string) (ledger.Record, error) {
	r, e := ledger.LoadRecord(ctx, t.conn, device)
	if errors.Is(e, ledger.ErrNotFound) {
		return ledger.Record{}, nil
	}
	return r, e
}

func windowsFullSoftwareSchemaObjects() []inventoryledger.SchemaObject { return ledger.SchemaObjects() }

func windowsFullSoftwareBudget(ctx context.Context, t *transaction) error {
	extra, e := windowsFullSoftwareOtherBytes(ctx, t)
	if e != nil {
		return e
	}
	return ledger.Budgets(ctx, t.conn, extra)
}
