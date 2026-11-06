package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// These are authored manager metadata, never endpoint observations or grants.
const deviceAssetFieldsSchema = `CREATE TABLE IF NOT EXISTS device_asset_fields(manager TEXT NOT NULL, identity TEXT NOT NULL, device_id TEXT NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=262144 AND json_valid(body)), PRIMARY KEY(manager,identity,device_id))`
const MaxDeviceAssetFieldOperations = 100
const MaxDeviceAssetFieldIdentities = 100
const MaxDeviceAssetTagBytes = 80
const MaxDeviceAssetLocationBytes = 160
const maxDeviceAssetFieldsBytes = 256 * 1024
const deviceAssetFieldsVersion = "tracebolt.device-asset-fields.v1"

var ErrDeviceAssetFieldsInvalid = errors.New("invalid device asset fields")
var ErrDeviceAssetFieldsConflict = errors.New("device asset fields revision or operation changed")
var ErrDeviceAssetFieldsLimit = errors.New("device asset fields limit reached")

type DeviceAssetValues struct {
	AssetTag    string `json:"assetTag"`
	Location    string `json:"location"`
	WarrantyEnd string `json:"warrantyEnd"`
}
type DeviceAssetFieldOperation struct {
	ID            string            `json:"id"`
	Revision      uint64            `json:"revision"`
	RequestDigest string            `json:"requestDigest"`
	Fields        DeviceAssetValues `json:"fields"`
	ChangedAt     time.Time         `json:"changedAt"`
}
type DeviceAssetFields struct {
	Version    string                      `json:"version"`
	Manager    string                      `json:"manager"`
	Identity   string                      `json:"identity"`
	DeviceID   string                      `json:"deviceId"`
	Revision   uint64                      `json:"revision"`
	Fields     DeviceAssetValues           `json:"fields"`
	ChangedAt  *time.Time                  `json:"changedAt"`
	Operations []DeviceAssetFieldOperation `json:"operations"`
}

func validDeviceAssetBinding(manager, identity, deviceID string) bool {
	return enrollmentcrypto.ValidHash(manager) && enrollmentcrypto.ValidHash(identity) && enrollmentcrypto.ValidID(deviceID, "agent_")
}
func validDeviceAssetText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.ContainsRune(s, utf8.RuneError) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func ValidDeviceAssetValues(f DeviceAssetValues) bool {
	if !validDeviceAssetText(f.AssetTag, MaxDeviceAssetTagBytes) || !validDeviceAssetText(f.Location, MaxDeviceAssetLocationBytes) {
		return false
	}
	if f.WarrantyEnd == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", f.WarrantyEnd)
	return err == nil && t.Year() >= 1 && t.Year() <= 9999 && t.Format("2006-01-02") == f.WarrantyEnd
}
func emptyDeviceAssetFields(manager, identity, id string) DeviceAssetFields {
	return DeviceAssetFields{Version: deviceAssetFieldsVersion, Manager: manager, Identity: identity, DeviceID: id, Operations: []DeviceAssetFieldOperation{}}
}
func deviceAssetFieldsDigest(manager, identity, id, operation string, fields DeviceAssetValues, expected uint64) string {
	b, _ := json.Marshal(struct {
		Binding  []string
		Fields   DeviceAssetValues
		Expected uint64
	}{[]string{deviceAssetFieldsVersion, manager, identity, id, operation}, fields, expected})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validDeviceAssetTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Location() == time.UTC
}
func decodeDeviceAssetFields(raw []byte, manager, identity, id string) (DeviceAssetFields, error) {
	var n DeviceAssetFields
	if len(raw) > maxDeviceAssetFieldsBytes || json.Unmarshal(raw, &n) != nil || n.Version != deviceAssetFieldsVersion || n.Manager != manager || n.Identity != identity || n.DeviceID != id || !validDeviceAssetBinding(manager, identity, id) || n.Operations == nil || len(n.Operations) == 0 || len(n.Operations) > MaxDeviceAssetFieldOperations || n.Revision != uint64(len(n.Operations)) || n.ChangedAt == nil || !validDeviceAssetTime(*n.ChangedAt) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	seen := map[string]bool{}
	var last time.Time
	for i, op := range n.Operations {
		if seen[op.ID] || !enrollmentcrypto.ValidID(op.ID, "assetop_") || op.Revision != uint64(i+1) || !ValidDeviceAssetValues(op.Fields) || !validDeviceAssetTime(op.ChangedAt) || op.ChangedAt.Before(last) || op.RequestDigest != deviceAssetFieldsDigest(manager, identity, id, op.ID, op.Fields, op.Revision-1) {
			return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
		}
		seen[op.ID] = true
		last = op.ChangedAt
	}
	final := n.Operations[len(n.Operations)-1]
	if n.Fields != final.Fields || !n.ChangedAt.Equal(final.ChangedAt) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	canonical, err := json.Marshal(n)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	return n, nil
}

type deviceAssetFieldsReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readDeviceAssetFields(ctx context.Context, q deviceAssetFieldsReader, manager, identity, id string) (DeviceAssetFields, bool, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT body FROM device_asset_fields WHERE manager=? AND identity=? AND device_id=?`, manager, identity, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyDeviceAssetFields(manager, identity, id), false, nil
	}
	if err != nil {
		return DeviceAssetFields{}, false, err
	}
	n, err := decodeDeviceAssetFields(raw, manager, identity, id)
	return n, true, err
}
func (s *Store) ReadDeviceAssetFields(ctx context.Context, manager, identity, id string) (DeviceAssetFields, error) {
	if !validDeviceAssetBinding(manager, identity, id) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	n, _, err := readDeviceAssetFields(ctx, s.db, manager, identity, id)
	return n, err
}
func (s *Store) ApplyDeviceAssetFields(ctx context.Context, manager, identity, id, operation string, fields DeviceAssetValues, expected uint64, now time.Time, guard func() error) (DeviceAssetFields, error) {
	if !validDeviceAssetBinding(manager, identity, id) || !enrollmentcrypto.ValidID(operation, "assetop_") || !ValidDeviceAssetValues(fields) || expected > MaxDeviceAssetFieldOperations || guard == nil || !validDeviceAssetTime(now.UTC()) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceAssetFields{}, err
	}
	defer tx.Rollback()
	n, exists, err := readDeviceAssetFields(ctx, tx, manager, identity, id)
	if err != nil {
		return DeviceAssetFields{}, err
	}
	digest := deviceAssetFieldsDigest(manager, identity, id, operation, fields, expected)
	for _, op := range n.Operations {
		if op.ID == operation {
			if op.RequestDigest != digest {
				return DeviceAssetFields{}, ErrDeviceAssetFieldsConflict
			}
			if err = ctx.Err(); err != nil {
				return DeviceAssetFields{}, err
			}
			if err = guard(); err != nil {
				return DeviceAssetFields{}, err
			}
			return n, nil
		}
	}
	if n.Revision != expected || n.ChangedAt != nil && now.Before(*n.ChangedAt) {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsConflict
	}
	if len(n.Operations) >= MaxDeviceAssetFieldOperations {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsLimit
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM device_asset_fields`).Scan(&count); err != nil {
		return DeviceAssetFields{}, err
	}
	if count > MaxDeviceAssetFieldIdentities {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsInvalid
	}
	if !exists && count >= MaxDeviceAssetFieldIdentities {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsLimit
	}
	now = now.UTC()
	n.Revision++
	n.Fields = fields
	n.ChangedAt = &now
	n.Operations = append(n.Operations, DeviceAssetFieldOperation{operation, n.Revision, digest, fields, now})
	raw, err := json.Marshal(n)
	if err != nil {
		return DeviceAssetFields{}, err
	}
	if len(raw) > maxDeviceAssetFieldsBytes {
		return DeviceAssetFields{}, ErrDeviceAssetFieldsLimit
	}
	if _, err = decodeDeviceAssetFields(raw, manager, identity, id); err != nil {
		return DeviceAssetFields{}, err
	}
	if err = ctx.Err(); err != nil {
		return DeviceAssetFields{}, err
	}
	if err = guard(); err != nil {
		return DeviceAssetFields{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_asset_fields(manager,identity,device_id,body) VALUES(?,?,?,?) ON CONFLICT(manager,identity,device_id) DO UPDATE SET body=excluded.body`, manager, identity, id, raw); err != nil {
		return DeviceAssetFields{}, err
	}
	if err = guard(); err != nil {
		return DeviceAssetFields{}, err
	}
	if err = ctx.Err(); err != nil {
		return DeviceAssetFields{}, err
	}
	if err = tx.Commit(); err != nil {
		return DeviceAssetFields{}, err
	}
	return n, nil
}
