package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/journalrequest"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
)

const (
	SystemDeviceQuota   = 2 << 20
	SystemGlobalQuota   = 50 << 20
	SystemRetention     = 24 * time.Hour
	SystemMaxAge        = 2 * time.Minute
	systemMetadataLimit = 16 << 10
	systemRowLimit      = 8192
)

var (
	ErrSystemConflict      = errors.New("system_inventory_conflict")
	ErrSystemCursor        = errors.New("system_inventory_cursor_invalid")
	ErrSystemCursorExpired = errors.New("system_inventory_cursor_expired")
	ErrSystemCapacity      = errors.New("system_inventory_capacity")
)

const systemAuthoritySchema = `CREATE TABLE enrollment_system_authority(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384)) STRICT`
const systemSectionsSchema = `CREATE TABLE enrollment_system_sections(invitation_id TEXT NOT NULL REFERENCES enrollment_system_authority(invitation_id),section TEXT NOT NULL CHECK(section IN ('services','sockets')),generation TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>0),meta BLOB NOT NULL CHECK(length(meta)>0 AND length(meta)<=4096),row_count INTEGER NOT NULL CHECK(row_count>=0 AND row_count<=16384),payload_bytes INTEGER NOT NULL CHECK(payload_bytes>0 AND payload_bytes<=524288),PRIMARY KEY(invitation_id,section)) STRICT`
const systemRowsSchema = `CREATE TABLE enrollment_system_rows(invitation_id TEXT NOT NULL,section TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<16384),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=8192),PRIMARY KEY(invitation_id,section,ordinal),FOREIGN KEY(invitation_id,section) REFERENCES enrollment_system_sections(invitation_id,section) ON DELETE CASCADE) STRICT`

func systemSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_system_authority", SQL: systemAuthoritySchema}, {Type: "table", Name: "enrollment_system_sections", SQL: systemSectionsSchema}, {Type: "table", Name: "enrollment_system_rows", SQL: systemRowsSchema}}
}
func initializeSystemObservations(ctx context.Context, c *sql.Conn) error {
	for _, o := range systemSchemaObjects() {
		if _, e := c.ExecContext(ctx, o.SQL); e != nil {
			return ErrStorage
		}
	}
	return nil
}

// Only small typed metadata is restored on ordinary authority transactions.
// The latest complete section and its last-complete cache are one normalized
// row set. Failed latest attempts have no rows and cannot erase that set.
type systemSnapshotMeta struct {
	SchemaVersion string                      `json:"schemaVersion"`
	GenerationID  string                      `json:"generationId"`
	CollectedAt   time.Time                   `json:"collectedAt"`
	DurationMS    int64                       `json:"durationMs"`
	Scope         string                      `json:"scope"`
	Services      systeminventory.SectionMeta `json:"services"`
	Sockets       systeminventory.SectionMeta `json:"sockets"`
}
type systemComplete struct {
	Sequence     uint64                      `json:"sequence"`
	Meta         systeminventory.SectionMeta `json:"meta"`
	PayloadBytes int                         `json:"payloadBytes"`
}
type systemRecord struct {
	Receipt          systemwire.Receipt      `json:"receipt"`
	Latest           *systemSnapshotMeta     `json:"latest"`
	Services         *systemComplete         `json:"services"`
	Sockets          *systemComplete         `json:"sockets"`
	MaintenanceAt    *time.Time              `json:"maintenanceAt"`
	EndpointIdentity *endpointIdentityRecord `json:"endpointIdentity,omitempty"`
	JournalRequest   *journalrequest.Record  `json:"journalRequest,omitempty"`
}

type endpointIdentityRecord struct {
	Receipt  systemwire.Receipt         `json:"receipt"`
	Snapshot *endpointidentity.Snapshot `json:"snapshot"`
}

func snapshotMetadata(s systeminventory.Snapshot) *systemSnapshotMeta {
	return &systemSnapshotMeta{s.SchemaVersion, s.GenerationID, s.CollectedAt, s.DurationMS, s.Scope, s.Services.Meta, s.Sockets.Meta}
}
func (r systemRecord) section(name string) *systemComplete {
	if name == "services" {
		return r.Services
	}
	return r.Sockets
}
func (r *systemRecord) setSection(name string, c *systemComplete) {
	if name == "services" {
		r.Services = c
	} else {
		r.Sockets = c
	}
}
func sectionRowLimit(name string) int {
	if name == "services" {
		return systeminventory.MaxServiceRows
	}
	return systeminventory.MaxSocketRows
}
func validSystemMeta(m systeminventory.SectionMeta) bool {
	n := 0
	if m.ObservedCount != nil {
		if *m.ObservedCount > uint64(systeminventory.MaxSocketRows) {
			return false
		}
		n = int(*m.ObservedCount)
	}
	return validStoreTime(m.ObservedAt) && systeminventory.ValidateSectionMeta(m, n) == nil
}
func validSystemRecord(snap enrollmentstate.Snapshot, r systemRecord) bool {
	p := r.Receipt
	expected, e := systemwire.GenerationID(snap.Approval.DeviceID, p.Sequence)
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 || snap.Issuance.CertificateHash == "" || e != nil || p.SchemaVersion != systemwire.ReceiptVersion || p.DeviceID != snap.Approval.DeviceID || p.GenerationID != expected || !enrollmentcrypto.ValidHash(p.BodyHash) || !validStoreTime(p.CollectedAt) || !validStoreTime(p.ReceivedAt) || p.CollectedAt.Location() != time.UTC || p.ReceivedAt.Location() != time.UTC || p.CollectedAt.After(p.ReceivedAt) || p.ReceivedAt.Sub(p.CollectedAt) > SystemMaxAge || p.ReceivedAt.Unix() < snap.Activation.At || p.ReceivedAt.Unix() >= snap.Intent.NotAfter {
		return false
	}
	if snap.Termination.At != 0 && p.ReceivedAt.Unix() > snap.Termination.At {
		return false
	}
	if r.MaintenanceAt != nil && (!validStoreTime(*r.MaintenanceAt) || r.MaintenanceAt.Location() != time.UTC || r.MaintenanceAt.Before(p.ReceivedAt)) {
		return false
	}
	if r.Latest == nil && (r.MaintenanceAt == nil || r.MaintenanceAt.Before(p.CollectedAt.Add(SystemRetention)) || r.Services != nil || r.Sockets != nil) {
		return false
	}
	if r.Latest != nil {
		m := r.Latest
		if m.SchemaVersion != systeminventory.SchemaVersion || m.Scope != systeminventory.SnapshotScope || m.GenerationID != p.GenerationID || !m.CollectedAt.Equal(p.CollectedAt) || m.DurationMS < 0 || m.DurationMS > systeminventory.MaxSafeInteger {
			return false
		}
		for _, item := range []struct {
			name string
			meta systeminventory.SectionMeta
		}{{"services", m.Services}, {"sockets", m.Sockets}} {
			if !validSystemMeta(item.meta) || item.meta.GenerationID != m.GenerationID || !item.meta.ObservedAt.Equal(m.CollectedAt) || item.meta.ObservedCount != nil && *item.meta.ObservedCount > uint64(sectionRowLimit(item.name)) {
				return false
			}
			if item.meta.Coverage == systeminventory.Complete {
				c := r.section(item.name)
				if c == nil || c.Sequence != p.Sequence || !equalSystemMeta(c.Meta, item.meta) {
					return false
				}
			}
		}
	}
	for _, name := range []string{"services", "sockets"} {
		c := r.section(name)
		if c == nil {
			continue
		}
		expected, e := systemwire.GenerationID(snap.Approval.DeviceID, c.Sequence)
		if e != nil || c.Sequence > p.Sequence || c.Meta.GenerationID != expected || !validSystemMeta(c.Meta) || c.Meta.Coverage != systeminventory.Complete || c.Meta.ObservedAt.After(p.CollectedAt) || *c.Meta.ObservedCount > uint64(sectionRowLimit(name)) || c.PayloadBytes <= 0 || c.PayloadBytes > systeminventory.MaxSectionBytes {
			return false
		}
	}
	if r.EndpointIdentity != nil {
		identity := r.EndpointIdentity
		p := identity.Receipt
		expected, e := systemwire.GenerationID(snap.Approval.DeviceID, p.Sequence)
		if e != nil || p.SchemaVersion != systemwire.ReceiptVersion || p.DeviceID != snap.Approval.DeviceID || p.GenerationID != expected || !enrollmentcrypto.ValidHash(p.BodyHash) || !validStoreTime(p.CollectedAt) || !validStoreTime(p.ReceivedAt) || p.CollectedAt.Location() != time.UTC || p.ReceivedAt.Location() != time.UTC || p.CollectedAt.After(p.ReceivedAt) || p.ReceivedAt.Sub(p.CollectedAt) > SystemMaxAge || p.Sequence > r.Receipt.Sequence || p.CollectedAt.After(r.Receipt.CollectedAt) || p.ReceivedAt.After(r.Receipt.ReceivedAt) || p.ReceivedAt.Unix() < snap.Activation.At || p.ReceivedAt.Unix() >= snap.Intent.NotAfter {
			return false
		}
		if p.Sequence == r.Receipt.Sequence && p != r.Receipt {
			return false
		}
		if identity.Snapshot != nil {
			if endpointidentity.Validate(*identity.Snapshot) != nil || identity.Snapshot.GenerationID != p.GenerationID || !identity.Snapshot.CollectedAt.Equal(p.CollectedAt) {
				return false
			}
		} else if (r.MaintenanceAt == nil || r.MaintenanceAt.Before(p.CollectedAt.Add(SystemRetention))) && r.Receipt.ReceivedAt.Before(p.CollectedAt.Add(SystemRetention)) {
			return false
		}
	}
	if r.JournalRequest != nil && !validJournalRecord(snap, *r.JournalRequest) {
		return false
	}
	return true
}
func equalSystemMeta(a, b systeminventory.SectionMeta) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (s *Store) loadSystemMetadata(ctx context.Context, t *transaction) error {
	t.system = map[string]systemRecord{}
	if !completeProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	var n, max int
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_system_authority`).Scan(&n, &max) != nil || n > s.config.RecordLimit || max > systemMetadataLimit {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id,body FROM enrollment_system_authority ORDER BY invitation_id`)
	if e != nil {
		return ErrStorage
	}
	for rows.Next() {
		var id string
		var raw []byte
		var r systemRecord
		if rows.Scan(&id, &raw) != nil || len(raw) == 0 || len(raw) > systemMetadataLimit || json.Unmarshal(raw, &r) != nil {
			rows.Close()
			return ErrStorage
		}
		canon, _ := json.Marshal(r)
		snap, e := t.engine.Get(id)
		if e != nil || !bytes.Equal(raw, canon) || !validSystemRecord(snap, r) {
			rows.Close()
			return ErrStorage
		}
		t.system[id] = r
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_system_sections`).Scan(&n) != nil || n > 2*s.config.RecordLimit {
		return ErrStorage
	}
	rows, e = t.conn.QueryContext(ctx, `SELECT invitation_id,section,generation,sequence,meta,row_count,payload_bytes FROM enrollment_system_sections ORDER BY invitation_id,section`)
	if e != nil {
		return ErrStorage
	}
	seen := map[string]bool{}
	total := 0
	for _, r := range t.system {
		b, _ := json.Marshal(r)
		total += len(b)
	}
	for rows.Next() {
		var id, name, generation string
		var seq uint64
		var raw []byte
		var count, payload int
		if rows.Scan(&id, &name, &generation, &seq, &raw, &count, &payload) != nil {
			rows.Close()
			return ErrStorage
		}
		r, ok := t.system[id]
		c := r.section(name)
		if !ok || (name != "services" && name != "sockets") || c == nil {
			rows.Close()
			return ErrStorage
		}
		meta, _ := json.Marshal(c.Meta)
		if generation != c.Meta.GenerationID || seq != c.Sequence || !bytes.Equal(meta, raw) || count != int(*c.Meta.ObservedCount) || payload != c.PayloadBytes {
			rows.Close()
			return ErrStorage
		}
		seen[id+"/"+name] = true
		total += payload
	}
	if rows.Err() != nil {
		rows.Close()
		return ErrStorage
	}
	if rows.Close() != nil {
		return ErrStorage
	}
	if total > SystemGlobalQuota {
		return ErrStorage
	}
	for id, r := range t.system {
		b, _ := json.Marshal(r)
		n := len(b)
		for _, name := range []string{"services", "sockets"} {
			c := r.section(name)
			if (c != nil) != seen[id+"/"+name] {
				return ErrStorage
			}
			if c != nil {
				n += c.PayloadBytes
			}
		}
		if n > SystemDeviceQuota {
			return ErrStorage
		}
	}
	return nil
}

// No package replay/clock state is consulted here. The fresh ledger and exact
// leaf binding are checked in the same BEGIN IMMEDIATE transaction as the save.
func (s *Store) systemAuthority(t *transaction, id, hash string, now time.Time) (enrollmentstate.Snapshot, error) {
	zero := enrollmentstate.Snapshot{}
	if !enrollmentcrypto.ValidID(id, "invite_") || !enrollmentcrypto.ValidHash(hash) || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	snap, e := t.engine.Get(id)
	if e != nil {
		return zero, e
	}
	if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" {
		return zero, enrollmentstate.ErrProof
	}
	if snap.State != enrollmentstate.Activated {
		return zero, enrollmentstate.ErrState
	}
	if snap.Issuance.CertificateHash != hash {
		return zero, enrollmentstate.ErrProof
	}
	if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore {
		return zero, enrollmentstate.ErrInvalid
	}
	if now.Unix() >= snap.Intent.NotAfter {
		return zero, enrollmentstate.ErrExpired
	}
	c, ok := t.credentials[id]
	if !ok {
		return zero, ErrStorage
	}
	intent, e := t.engine.TrustedRecordedIntent(id)
	if e != nil {
		return zero, ErrStorage
	}
	if _, e = enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, now); e != nil {
		return zero, enrollmentstate.ErrProof
	}
	if r, ok := t.system[id]; ok && (now.Before(r.Receipt.ReceivedAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt)) {
		return zero, enrollmentstate.ErrInvalid
	}
	return snap, nil
}

func (s *Store) SaveSystemObservation(ctx context.Context, id, hash string, raw []byte, receivedAt time.Time) (systemwire.Receipt, error) {
	zero := systemwire.Receipt{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if len(raw) == 0 || len(raw) > systemwire.MaxBodyBytes || !validStoreTime(receivedAt) {
		return zero, enrollmentstate.ErrInvalid
	}
	raw = bytes.Clone(raw)
	frame, e := systemwire.Decode(raw)
	if e != nil {
		return zero, e
	}
	receivedAt = receivedAt.UTC()
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var out systemwire.Receipt
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := s.systemAuthority(t, id, hash, receivedAt)
		if e != nil {
			return e
		}
		expected, e := systemwire.GenerationID(snap.Approval.DeviceID, frame.Sequence)
		if e != nil || frame.Snapshot.GenerationID != expected {
			return enrollmentstate.ErrProof
		}
		old, exists := t.system[id]
		if exists && frame.Sequence <= old.Receipt.Sequence {
			if frame.Sequence != old.Receipt.Sequence || digest != old.Receipt.BodyHash {
				return ErrSystemConflict
			}
			out = old.Receipt
			return nil
		}
		at := frame.Snapshot.CollectedAt
		if at.After(receivedAt) || receivedAt.Sub(at) > SystemMaxAge {
			return enrollmentstate.ErrInvalid
		}
		if exists && !at.After(old.Receipt.CollectedAt) {
			return ErrSystemConflict
		}
		out = systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: snap.Approval.DeviceID, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: at, ReceivedAt: receivedAt, BodyHash: digest}
		record := old
		record.Receipt = out
		record.MaintenanceAt = nil
		record.Latest = snapshotMetadata(frame.Snapshot)
		if frame.EndpointIdentity != nil {
			record.EndpointIdentity = &endpointIdentityRecord{Receipt: out, Snapshot: frame.EndpointIdentity}
		}
		// Ordinary v1 reports never refresh a prior endpoint snapshot or receipt.
		// Insert the authority parent first; all subsequent failure paths roll back.
		if !exists {
			placeholder, _ := json.Marshal(record)
			if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_system_authority VALUES(?,?)`, id, placeholder); e != nil {
				return ErrStorage
			}
		}
		for _, name := range []string{"services", "sockets"} {
			var meta systeminventory.SectionMeta
			var items [][]byte
			var sectionBytes []byte
			if name == "services" {
				meta = frame.Snapshot.Services.Meta
				sectionBytes, e = json.Marshal(frame.Snapshot.Services)
				for _, row := range frame.Snapshot.Services.Items {
					b, err := json.Marshal(row)
					if err != nil {
						return ErrStorage
					}
					items = append(items, b)
				}
			} else {
				meta = frame.Snapshot.Sockets.Meta
				sectionBytes, e = json.Marshal(frame.Snapshot.Sockets)
				for _, row := range frame.Snapshot.Sockets.Items {
					b, err := json.Marshal(row)
					if err != nil {
						return ErrStorage
					}
					items = append(items, b)
				}
			}
			if e != nil {
				return ErrStorage
			}
			if meta.Coverage != systeminventory.Complete {
				continue
			}
			if len(sectionBytes) > systeminventory.MaxSectionBytes {
				return ErrSystemCapacity
			}
			if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_system_sections WHERE invitation_id=? AND section=?`, id, name); e != nil {
				return ErrStorage
			}
			m, _ := json.Marshal(meta)
			if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_system_sections VALUES(?,?,?,?,?,?,?)`, id, name, meta.GenerationID, frame.Sequence, m, len(items), len(sectionBytes)); e != nil {
				return ErrStorage
			}
			statement, e := t.conn.PrepareContext(ctx, `INSERT INTO enrollment_system_rows VALUES(?,?,?,?)`)
			if e != nil {
				return ErrStorage
			}
			for i, b := range items {
				if len(b) == 0 || len(b) > systemRowLimit {
					statement.Close()
					return ErrSystemCapacity
				}
				if _, e = statement.ExecContext(ctx, id, name, i, b); e != nil {
					statement.Close()
					return ErrStorage
				}
			}
			if statement.Close() != nil {
				return ErrStorage
			}
			record.setSection(name, &systemComplete{Sequence: frame.Sequence, Meta: meta, PayloadBytes: len(sectionBytes)})
		}
		b, e := json.Marshal(record)
		if e != nil || len(b) > systemMetadataLimit || !validSystemRecord(snap, record) {
			return ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, b, id); e != nil {
			return ErrStorage
		}
		t.system[id] = record
		return s.checkSystemAdmission(ctx, t, id)
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

// Exact normalized byte/count accounting runs on ingest, not on routine
// authority restoration. Only SQL aggregates and bounded headers are returned;
// no endpoint row blobs are decoded or restored into an authority transaction.
func (s *Store) checkSystemAdmission(ctx context.Context, t *transaction, _ string) error {
	globalBytes := 0
	for id, record := range t.system {
		body, _ := json.Marshal(record)
		deviceBytes := len(body)
		for _, name := range []string{"services", "sockets"} {
			c := record.section(name)
			var n, rowBytes, minOrdinal, maxOrdinal int
			if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(body)),0),coalesce(min(ordinal),0),coalesce(max(ordinal),-1) FROM enrollment_system_rows WHERE invitation_id=? AND section=?`, id, name).Scan(&n, &rowBytes, &minOrdinal, &maxOrdinal) != nil {
				return ErrStorage
			}
			if c == nil {
				if n != 0 {
					return ErrStorage
				}
				continue
			}
			header, _ := json.Marshal(struct {
				Meta  systeminventory.SectionMeta `json:"meta"`
				Items []int                       `json:"items"`
			}{c.Meta, []int{}})
			exactBytes := len(header) + rowBytes
			if n > 0 {
				exactBytes += n - 1
			}
			if n != int(*c.Meta.ObservedCount) || n > sectionRowLimit(name) || n > 0 && (minOrdinal != 0 || maxOrdinal != n-1) || exactBytes != c.PayloadBytes {
				return ErrStorage
			}
			deviceBytes += exactBytes
		}
		if deviceBytes > SystemDeviceQuota {
			return ErrSystemCapacity
		}
		globalBytes += deviceBytes
	}
	if globalBytes > SystemGlobalQuota {
		return ErrSystemCapacity
	}
	var orphans int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_system_rows r LEFT JOIN enrollment_system_sections s ON r.invitation_id=s.invitation_id AND r.section=s.section WHERE s.invitation_id IS NULL`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	return nil
}

func validateSystemRecords(t *transaction) error {
	for id, r := range t.system {
		snap, e := t.engine.Get(id)
		if e != nil || !validSystemRecord(snap, r) {
			return ErrStorage
		}
	}
	return nil
}
