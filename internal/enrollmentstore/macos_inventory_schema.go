package enrollmentstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
)

const macOSInventoryRecordBytes = 560 * 1024
const macOSInventoryMetaSchema = `CREATE TABLE enrollment_macos_inventory_meta(id INTEGER PRIMARY KEY CHECK(id=1), last_time TEXT NOT NULL) STRICT`
const macOSInventoryRecordSchema = `CREATE TABLE enrollment_macos_inventory(invitation TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=573440)) STRICT`

type macOSInventoryLatest struct {
	Sequence      uint64                `json:"sequence"`
	GenerationID  string                `json:"generationId"`
	CollectedAt   time.Time             `json:"collectedAt"`
	ExpiresAt     time.Time             `json:"expiresAt"`
	SourceQuality string                `json:"sourceQuality"`
	Sources       MacOSInventorySources `json:"sources"`
	Receipt       json.RawMessage       `json:"receipt"`
}
type macOSInventoryRecord struct {
	Origin         string                `json:"origin"`
	EnableRaw      json.RawMessage       `json:"enable"`
	EnableReceipt  json.RawMessage       `json:"enableReceipt"`
	DisableRaw     json.RawMessage       `json:"disable,omitempty"`
	DisableReceipt json.RawMessage       `json:"disableReceipt,omitempty"`
	Floor          uint64                `json:"floor"`
	LastAt         time.Time             `json:"lastAt"`
	Latest         *macOSInventoryLatest `json:"latest"`
	ReportRaw      json.RawMessage       `json:"report,omitempty"`
}

func macOSInventorySchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_macos_inventory_meta", SQL: macOSInventoryMetaSchema}, {Type: "table", Name: "enrollment_macos_inventory", SQL: macOSInventoryRecordSchema}}
}
func initializeMacOSInventory(ctx context.Context, c *sql.Conn) error {
	for _, q := range []string{macOSInventoryMetaSchema, macOSInventoryRecordSchema, `INSERT INTO enrollment_macos_inventory_meta(id,last_time) VALUES(1,'')`} {
		if _, e := c.ExecContext(ctx, q); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func readMacOSInventoryRecord(ctx context.Context, t *transaction, id string) (*macOSInventoryRecord, error) {
	var raw []byte
	e := t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_macos_inventory WHERE invitation=?`, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		if t.credentials[id].MacOSInventoryInitialized {
			return nil, ErrStorage
		}
		return nil, nil
	}
	if e != nil || len(raw) > macOSInventoryRecordBytes {
		return nil, ErrStorage
	}
	var r macOSInventoryRecord
	if json.Unmarshal(raw, &r) != nil {
		return nil, ErrStorage
	}
	canonical, e := json.Marshal(r)
	if e != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrStorage
	}
	return &r, nil
}
func saveMacOSInventoryRecord(ctx context.Context, t *transaction, id string, r *macOSInventoryRecord) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > macOSInventoryRecordBytes {
		return ErrStorage
	}
	_, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_macos_inventory(invitation,body) VALUES(?,?) ON CONFLICT(invitation) DO UPDATE SET body=excluded.body`, id, raw)
	if e != nil {
		return ErrStorage
	}
	return nil
}
func validateMacOSInventoryState(ctx context.Context, t *transaction, profile string) error {
	if profile != macosinventorywire.Profile {
		for _, c := range t.credentials {
			if c.MacOSInventoryInitialized {
				return ErrStorage
			}
		}
		return nil
	}
	var count int
	var last string
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_macos_inventory_meta`).Scan(&count) != nil || count != 1 || t.conn.QueryRowContext(ctx, `SELECT last_time FROM enrollment_macos_inventory_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	var clock time.Time
	if last != "" {
		var e error
		clock, e = time.Parse(time.RFC3339Nano, last)
		if e != nil || !validStoreTime(clock) || clock.Format(time.RFC3339Nano) != last {
			return ErrStorage
		}
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_macos_inventory`).Scan(&count) != nil || count > 25 {
		return ErrStorage
	}
	used := 0
	for id, c := range t.credentials {
		if !c.MacOSInventoryInitialized {
			var n int
			if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_macos_inventory WHERE invitation=?`, id).Scan(&n) != nil || n != 0 {
				return ErrStorage
			}
			continue
		}
		used++
		snap, e := t.engine.Get(id)
		if e != nil || snap.Platform != "darwin" || snap.Binding.Profile != "tls" || snap.Binding.CollectionProfile != macosinventorywire.Profile || snap.Activation.At == 0 {
			return ErrStorage
		}
		r, e := readMacOSInventoryRecord(ctx, t, id)
		if e != nil || r == nil || !validStoreTime(r.LastAt) || r.LastAt.After(clock) || r.Floor > macosinventorywire.MaxSequence {
			return ErrStorage
		}
		enabled, e := macosinventorywire.DecodeControl(r.EnableRaw)
		if e != nil || !enabled.Enabled || !validWindowsFullProcessesOrigin(r.Origin, "tls") || enabled.Binding != macOSInventoryBinding(snap, r.Origin) || enabled.ChangedAt.Unix() < snap.Activation.At {
			return ErrStorage
		}
		ack, e := macosinventorywire.DecodeReceipt(r.EnableReceipt, r.EnableRaw)
		if e != nil || ack.ReceivedAt.After(r.LastAt) {
			return ErrStorage
		}
		if len(r.DisableRaw) > 0 {
			disabled, e := macosinventorywire.DecodeControl(r.DisableRaw)
			if e != nil || disabled.Enabled || disabled.CaptureFloor != r.Floor {
				return ErrStorage
			}
			if _, e = macosinventorywire.ValidateControlTransition(r.EnableRaw, r.DisableRaw, r.Floor); e != nil {
				return ErrStorage
			}
			da, e := macosinventorywire.DecodeReceipt(r.DisableReceipt, r.DisableRaw)
			if e != nil || da.ReceivedAt.After(r.LastAt) || disabled.ChangedAt.Before(ack.ReceivedAt) {
				return ErrStorage
			}
		} else if len(r.DisableReceipt) > 0 {
			return ErrStorage
		}
		if r.Latest == nil {
			if len(r.ReportRaw) > 0 || r.Floor != 0 && len(r.DisableRaw) == 0 {
				return ErrStorage
			}
			continue
		}
		h := r.Latest
		if h.Sequence == 0 || h.Sequence > r.Floor || len(r.DisableRaw) == 0 && h.Sequence != r.Floor || !validStoreTime(h.CollectedAt) || !validStoreTime(h.ExpiresAt) || !h.ExpiresAt.Equal(h.CollectedAt.Add(macosinventorywire.Retention)) || h.CollectedAt.Before(ack.ReceivedAt) || h.CollectedAt.After(r.LastAt) {
			return ErrStorage
		}
		generation, e := macosinventorywire.GenerationID(enabled.Binding, enabled.GrantID, enabled.GrantRevision, h.Sequence)
		if e != nil || generation != h.GenerationID {
			return ErrStorage
		}
		if !validMacOSInventorySources(h.Sources, h.SourceQuality) {
			return ErrStorage
		}
		var receipt macosinventorywire.Receipt
		if json.Unmarshal(h.Receipt, &receipt) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(receipt)
		if !bytes.Equal(h.Receipt, canonical) || len(h.Receipt) > macosinventorywire.MaxReceiptBytes || receipt.SchemaVersion != macosinventorywire.ReceiptVersion || receipt.Kind != "report" || receipt.Status != "recorded" || receipt.Binding != enabled.Binding || receipt.GrantID != enabled.GrantID || receipt.GrantRevision != 1 || receipt.ControlRevision != 1 || receipt.CaptureFloor != h.Sequence || receipt.GenerationID != h.GenerationID || receipt.CollectedAt == nil || !validStoreTime(*receipt.CollectedAt) || !validStoreTime(receipt.ReceivedAt) || !enrollmentcrypto.ValidHash(receipt.SnapshotSHA256) || !enrollmentcrypto.ValidHash(receipt.RequestSHA256) || !receipt.CollectedAt.Equal(h.CollectedAt) || receipt.ReceivedAt.Before(h.CollectedAt) || !receipt.ReceivedAt.Before(h.ExpiresAt) || receipt.ReceivedAt.After(r.LastAt) {
			return ErrStorage
		}
		if len(r.ReportRaw) > 0 {
			report, e := macosinventorywire.DecodeReport(r.ReportRaw)
			if e != nil || report.CaptureSequence != h.Sequence || report.GenerationID != h.GenerationID || report.CollectedAt != h.CollectedAt || report.ExpiresAt != h.ExpiresAt || report.SourceQuality != h.SourceQuality || macOSInventorySourceStatuses(report) != h.Sources || macosinventorywire.ValidateReportBinding(report, enabled) != nil {
				return ErrStorage
			}
			if _, e = macosinventorywire.DecodeReceipt(h.Receipt, r.ReportRaw); e != nil {
				return ErrStorage
			}
		} else if clock.Before(h.ExpiresAt) {
			return ErrStorage
		}
	}
	if count != used {
		return ErrStorage
	}
	return nil
}
func macOSInventoryClock(ctx context.Context, t *transaction, now time.Time) error {
	var last string
	if t.conn.QueryRowContext(ctx, `SELECT last_time FROM enrollment_macos_inventory_meta WHERE id=1`).Scan(&last) != nil {
		return ErrStorage
	}
	if last != "" {
		at, e := time.Parse(time.RFC3339Nano, last)
		if e != nil {
			return ErrStorage
		}
		if now.Before(at) {
			return enrollmentstate.ErrInvalid
		}
	}
	if _, e := t.conn.ExecContext(ctx, `UPDATE enrollment_macos_inventory_meta SET last_time=? WHERE id=1`, now.Format(time.RFC3339Nano)); e != nil {
		return ErrStorage
	}
	return nil
}

func validMacOSInventorySources(s MacOSInventorySources, quality string) bool {
	observed := 0
	for _, v := range []struct {
		status macosinventory.Status
		source string
	}{{s.Hardware, macosinventory.HardwareSource}, {s.Receipts, macosinventory.ReceiptSource}, {s.Processes, macosinventory.ProcessSource}, {s.IPv4, macosinventory.IPv4Source}, {s.IPv6, macosinventory.IPv6Source}} {
		if v.status.Source != v.source {
			return false
		}
		switch v.status.Quality {
		case "observed":
			if v.status.Reason != "" {
				return false
			}
			observed++
		case "denied":
			if v.status.Reason != macosinventory.ErrDenied.Error() {
				return false
			}
		case "unavailable":
			switch v.status.Reason {
			case macosinventory.ErrUnavailable.Error(), macosinventory.ErrUnsupported.Error(), macosinventory.ErrMetadata.Error(), macosinventory.ErrBounds.Error(), macosinventory.ErrBudget.Error():
			default:
				return false
			}
		default:
			return false
		}
	}
	return quality == "unknown" && observed == 0 || quality == "full" && observed == 5 || quality == "partial" && observed > 0
}
