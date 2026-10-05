package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/systeminventory"
)

const (
	SystemMaxPageRows    = 100
	SystemPageScanRows   = 2048
	SystemMaxSearchBytes = 128
	SystemMaxCursorBytes = 2048
	SystemCursorTTL      = 15 * time.Minute
	systemCursorDomain   = "tracebolt.system-inventory.cursor.v1\x00"
)

type SystemSnapshotSummary struct {
	GenerationID string                      `json:"generationId"`
	CollectedAt  time.Time                   `json:"collectedAt"`
	DurationMS   int64                       `json:"durationMs"`
	Scope        string                      `json:"scope"`
	Services     systeminventory.SectionMeta `json:"services"`
	Sockets      systeminventory.SectionMeta `json:"sockets"`
}
type SystemSectionSummary struct {
	Sequence uint64                      `json:"sequence,string"`
	Meta     systeminventory.SectionMeta `json:"meta"`
	Status   string                      `json:"status"`
}
type SystemLastComplete struct {
	Services *SystemSectionSummary `json:"services"`
	Sockets  *SystemSectionSummary `json:"sockets"`
}
type SystemView struct {
	readState         *systemViewReadState
	CollectionProfile string                 `json:"collectionProfile"`
	SchemaVersion     string                 `json:"schemaVersion"`
	DeviceID          string                 `json:"deviceId"`
	Status            string                 `json:"status"`
	ServerNow         time.Time              `json:"serverNow"`
	MaxAgeSeconds     int64                  `json:"maxAgeSeconds"`
	Sequence          *uint64                `json:"sequence,string"`
	ReceivedAt        *time.Time             `json:"receivedAt"`
	Latest            *SystemSnapshotSummary `json:"latest"`
	LastComplete      SystemLastComplete     `json:"lastComplete"`
}

func systemAge(at, now time.Time) string {
	if now.Before(at) {
		return "unknown"
	}
	if !now.Before(at.Add(SystemRetention)) {
		return "expired"
	}
	if now.Sub(at) > SystemMaxAge {
		return "stale"
	}
	return "fresh"
}
func systemDevice(t *transaction, device string) (enrollmentstate.Snapshot, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") {
		return enrollmentstate.Snapshot{}, enrollmentstate.ErrInvalid
	}
	for _, snap := range t.engine.Snapshots() {
		if snap.Approval.DeviceID == device {
			return snap, nil
		}
	}
	return enrollmentstate.Snapshot{}, enrollmentstate.ErrNotFound
}
func systemIdentityStatus(snap enrollmentstate.Snapshot, now time.Time) string {
	switch snap.State {
	case enrollmentstate.Revoked, enrollmentstate.Canceled, enrollmentstate.Rejected:
		return "revoked"
	case enrollmentstate.Expired:
		return "expired"
	}
	if snap.Intent.NotAfter > 0 && now.Unix() >= snap.Intent.NotAfter {
		return "expired"
	}
	if !completeProfile(snap.Binding.CollectionProfile) || snap.State != enrollmentstate.Activated || snap.Platform != "linux" {
		return "unknown"
	}
	return "awaiting"
}

// SystemView exposes only bounded operator metadata. It never restores rows,
// silently treats corruption as no data, or changes collection timestamps.
func (s *Store) SystemView(ctx context.Context, device string, now time.Time) (SystemView, error) {
	zero := SystemView{}
	release, e := s.systemReadAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	out := SystemView{CollectionProfile: s.config.Binding.CollectionProfile, SchemaVersion: "tracebolt.system-inventory-view.v1", DeviceID: device, Status: "unknown", ServerNow: now, MaxAgeSeconds: int64(SystemMaxAge / time.Second)}
	e = s.transact(ctx, func(t *transaction) error {
		// Queueing for admission or SQL must not preserve pre-wait authority age.
		var err error
		now, err = systemViewNow(ctx, now)
		if err != nil {
			return err
		}
		out.ServerNow = now
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		out.readState = &systemViewReadState{checkedAt: now, certificateNotAfter: snap.Intent.NotAfter}
		out.Status = systemIdentityStatus(snap, now)
		r, ok := t.system[snap.InvitationID]
		if !ok {
			return nil
		}
		seq, received := r.Receipt.Sequence, r.Receipt.ReceivedAt
		out.Sequence = &seq
		out.ReceivedAt = &received
		if out.Status != "awaiting" {
			return nil
		}
		if _, e = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); e != nil {
			return e
		}
		out.readState.observationAt = r.Receipt.CollectedAt
		out.Status = systemAge(r.Receipt.CollectedAt, now)
		if r.Latest != nil && out.Status != "expired" {
			m := r.Latest
			out.Latest = &SystemSnapshotSummary{m.GenerationID, m.CollectedAt, m.DurationMS, m.Scope, m.Services, m.Sockets}
		}
		for _, name := range []string{"services", "sockets"} {
			c := r.section(name)
			if c == nil {
				continue
			}
			status := systemAge(c.Meta.ObservedAt, now)
			if status == "expired" {
				continue
			}
			summary := &SystemSectionSummary{c.Sequence, c.Meta, status}
			if name == "services" {
				out.LastComplete.Services = summary
			} else {
				out.LastComplete.Sockets = summary
			}
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	now, e = systemViewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	return out.RecheckAt(now)
}

type SystemPageRequest struct {
	Filter       string `json:"filter"`
	Section      string `json:"section"`
	GenerationID string `json:"generationId"`
	Search       string `json:"search"`
	Cursor       string `json:"cursor"`
	Limit        int    `json:"limit"`
}
type SystemPageResult struct {
	CursorExpiresAt *time.Time                  `json:"cursorExpiresAt"`
	Section         string                      `json:"section"`
	GenerationID    string                      `json:"generationId"`
	Meta            systeminventory.SectionMeta `json:"meta"`
	Status          string                      `json:"status"`
	TotalRows       uint64                      `json:"totalRows"`
	ReturnedCount   int                         `json:"returnedCount"`
	ScannedCount    int                         `json:"scannedCount"`
	Exhausted       bool                        `json:"exhausted"`
	NextCursor      string                      `json:"nextCursor"`
	Services        []systeminventory.Service   `json:"services"`
	Sockets         []systeminventory.Socket    `json:"sockets"`
}
type systemCursor struct {
	Filter       string    `json:"filter"`
	Version      int       `json:"v"`
	Device       string    `json:"device"`
	Section      string    `json:"section"`
	GenerationID string    `json:"generationId"`
	Query        string    `json:"query"`
	Limit        int       `json:"limit"`
	Next         int       `json:"next"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func normalizeSystemQuery(q string) (string, error) {
	if len(q) > SystemMaxSearchBytes || !utf8.ValidString(q) {
		return "", enrollmentstate.ErrInvalid
	}
	for _, r := range q {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return "", enrollmentstate.ErrInvalid
		}
	}
	return strings.ToLower(strings.TrimSpace(q)), nil
}
func signSystemCursor(c systemCursor, key []byte) string {
	raw, _ := json.Marshal(c)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(systemCursorDomain))
	m.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func parseSystemCursor(raw string, key []byte, device string, req SystemPageRequest, query string, now time.Time) (systemCursor, error) {
	zero := systemCursor{}
	if len(raw) == 0 || len(raw) > SystemMaxCursorBytes {
		return zero, ErrSystemCursor
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return zero, ErrSystemCursor
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return zero, ErrSystemCursor
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(signature) != sha256.Size {
		return zero, ErrSystemCursor
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(systemCursorDomain))
	m.Write(b)
	if !hmac.Equal(signature, m.Sum(nil)) {
		return zero, ErrSystemCursor
	}
	var c systemCursor
	if json.Unmarshal(b, &c) != nil {
		return zero, ErrSystemCursor
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(b, canonical) || c.Version != 1 || c.Device != device || c.Section != req.Section || c.GenerationID != req.GenerationID || c.Query != query || c.Filter != req.Filter || c.Limit != req.Limit || c.Next < 0 || c.Next > sectionRowLimit(req.Section) || !validStoreTime(c.ExpiresAt) || c.ExpiresAt.Location() != time.UTC || c.ExpiresAt.After(now.Add(SystemCursorTTL)) {
		return zero, ErrSystemCursor
	}
	if !now.Before(c.ExpiresAt) {
		return zero, ErrSystemCursorExpired
	}
	return c, nil
}
func serviceSearch(row systeminventory.Service) string {
	parts := []string{row.Name}
	if row.Runtime != nil {
		parts = append(parts, row.Runtime.LoadState, row.Runtime.ActiveState, row.Runtime.SubState)
	}
	if row.Enablement != nil {
		parts = append(parts, *row.Enablement)
	}
	return strings.ToLower(strings.Join(parts, " "))
}
func socketSearch(row systeminventory.Socket) string {
	parts := []string{row.Protocol, row.Family, row.Kind, row.Local.Address, strconv.Itoa(int(row.Local.Port)), row.Remote.Address, strconv.Itoa(int(row.Remote.Port)), row.State}
	for _, o := range row.Owners {
		parts = append(parts, strconv.FormatUint(uint64(o.PID), 10))
		if o.ProcessName != nil {
			parts = append(parts, *o.ProcessName)
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

// Search and cursor are POST-body fields. An empty, nonexhausted page is a
// legitimate continuation after the bounded scan of a sparse search window.
func (s *Store) SystemPage(ctx context.Context, device string, req SystemPageRequest, now time.Time) (SystemPageResult, error) {
	zero := SystemPageResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validSystemFilter(req.Section, req.Filter) || req.Section != "services" && req.Section != "sockets" || !enrollmentcrypto.ValidID(req.GenerationID, "sample_") || req.Limit < 1 || req.Limit > SystemMaxPageRows || len(req.Cursor) > SystemMaxCursorBytes || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	query, e := normalizeSystemQuery(req.Search)
	if e != nil {
		return zero, e
	}
	now = now.UTC()
	var out SystemPageResult
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		if _, e = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); e != nil {
			return e
		}
		r, ok := t.system[snap.InvitationID]
		if !ok {
			return ErrSystemConflict
		}
		section := r.section(req.Section)
		if section == nil || section.Meta.GenerationID != req.GenerationID || systemAge(section.Meta.ObservedAt, now) == "expired" {
			return ErrSystemConflict
		}
		if now.Before(section.Meta.ObservedAt) {
			return enrollmentstate.ErrInvalid
		}
		var key []byte
		if t.conn.QueryRowContext(ctx, `SELECT cursor_key FROM enrollment_inventory_meta WHERE id=1`).Scan(&key) != nil || len(key) != 32 {
			return ErrStorage
		}
		expiry := now.Add(SystemCursorTTL)
		if section.Meta.ObservedAt.Add(SystemRetention).Before(expiry) {
			expiry = section.Meta.ObservedAt.Add(SystemRetention)
		}
		cursor := systemCursor{Version: 1, Device: device, Section: req.Section, GenerationID: req.GenerationID, Query: query, Filter: req.Filter, Limit: req.Limit, Next: 0, ExpiresAt: expiry}
		if req.Cursor != "" {
			cursor, e = parseSystemCursor(req.Cursor, key, device, req, query, now)
			if e != nil {
				return e
			}
		}
		total := int(*section.Meta.ObservedCount)
		if cursor.Next > total {
			return ErrSystemCursor
		}
		out = SystemPageResult{Section: req.Section, GenerationID: req.GenerationID, Meta: section.Meta, Status: systemAge(section.Meta.ObservedAt, now), TotalRows: *section.Meta.ObservedCount, Services: []systeminventory.Service{}, Sockets: []systeminventory.Socket{}}
		rows, e := t.conn.QueryContext(ctx, `SELECT ordinal,body FROM enrollment_system_rows WHERE invitation_id=? AND section=? AND ordinal>=? ORDER BY ordinal LIMIT ?`, snap.InvitationID, req.Section, cursor.Next, SystemPageScanRows)
		if e != nil {
			return ErrStorage
		}
		next := cursor.Next
		for rows.Next() {
			var ordinal int
			var raw []byte
			if rows.Scan(&ordinal, &raw) != nil || ordinal != next || ordinal >= total || len(raw) == 0 || len(raw) > systemRowLimit {
				rows.Close()
				return ErrStorage
			}
			next++
			out.ScannedCount++
			if req.Section == "services" {
				var row systeminventory.Service
				if json.Unmarshal(raw, &row) != nil || systeminventory.ValidateService(row) != nil {
					rows.Close()
					return ErrStorage
				}
				canonical, _ := json.Marshal(row)
				if !bytes.Equal(raw, canonical) {
					rows.Close()
					return ErrStorage
				}
				if systemServiceFilter(row, req.Filter) && (query == "" || strings.Contains(serviceSearch(row), query)) {
					out.Services = append(out.Services, row)
					out.ReturnedCount++
				}
			} else {
				var row systeminventory.Socket
				if json.Unmarshal(raw, &row) != nil || systeminventory.ValidateSocket(row) != nil {
					rows.Close()
					return ErrStorage
				}
				canonical, _ := json.Marshal(row)
				if !bytes.Equal(raw, canonical) {
					rows.Close()
					return ErrStorage
				}
				if systemSocketFilter(row, req.Filter) && (query == "" || strings.Contains(socketSearch(row), query)) {
					out.Sockets = append(out.Sockets, row)
					out.ReturnedCount++
				}
			}
			if out.ReturnedCount == req.Limit {
				break
			}
		}
		if rows.Err() != nil {
			rows.Close()
			return ErrStorage
		}
		if rows.Close() != nil {
			return ErrStorage
		}
		if next < total && out.ReturnedCount < req.Limit && out.ScannedCount < SystemPageScanRows {
			return ErrStorage
		}
		out.Exhausted = next == total
		if !out.Exhausted {
			cursor.Next = next
			out.NextCursor = signSystemCursor(cursor, key)
			out.CursorExpiresAt = &cursor.ExpiresAt
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

type SystemCleanupResult struct {
	ClearedLatest           bool `json:"clearedLatest"`
	ClearedSections         int  `json:"clearedSections"`
	ClearedEndpointIdentity bool `json:"clearedEndpointIdentity,omitempty"`
	ClearedCachedUpdates    bool `json:"clearedCachedUpdates,omitempty"`
}

// SystemCleanup is privileged local maintenance, with no agent endpoint. It
// clears only 24h-expired payloads and keeps sequence floor, exact body digest,
// original receipt and current enrollment authority. It never advances age.
func (s *Store) SystemCleanup(ctx context.Context, device string, now time.Time) (SystemCleanupResult, error) {
	zero := SystemCleanupResult{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	var out SystemCleanupResult
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		if !completeProfile(snap.Binding.CollectionProfile) || snap.Platform != "linux" || snap.Activation.At == 0 {
			return enrollmentstate.ErrProof
		}
		r, ok := t.system[snap.InvitationID]
		if !ok {
			return nil
		}
		if now.Unix() < snap.UpdatedAt || now.Before(r.Receipt.ReceivedAt) || r.MaintenanceAt != nil && now.Before(*r.MaintenanceAt) {
			return enrollmentstate.ErrInvalid
		}
		if r.Latest != nil && !now.Before(r.Latest.CollectedAt.Add(SystemRetention)) {
			r.Latest = nil
			out.ClearedLatest = true
		}
		for _, name := range []string{"services", "sockets"} {
			c := r.section(name)
			if c != nil && !now.Before(c.Meta.ObservedAt.Add(SystemRetention)) {
				if _, e = t.conn.ExecContext(ctx, `DELETE FROM enrollment_system_sections WHERE invitation_id=? AND section=?`, snap.InvitationID, name); e != nil {
					return ErrStorage
				}
				r.setSection(name, nil)
				out.ClearedSections++
			}
		}
		if r.EndpointIdentity != nil && r.EndpointIdentity.Snapshot != nil && !now.Before(r.EndpointIdentity.Receipt.CollectedAt.Add(SystemRetention)) {
			r.EndpointIdentity.Snapshot = nil
			out.ClearedEndpointIdentity = true
		}
		if r.CachedUpdates != nil && r.CachedUpdates.Snapshot != nil && !now.Before(r.CachedUpdates.Receipt.CollectedAt.Add(SystemRetention)) {
			r.CachedUpdates.Snapshot = nil
			out.ClearedCachedUpdates = true
		}
		if !out.ClearedLatest && out.ClearedSections == 0 && !out.ClearedEndpointIdentity && !out.ClearedCachedUpdates {
			return nil
		}
		r.MaintenanceAt = &now
		if !validSystemRecord(snap, r) {
			return ErrStorage
		}
		raw, e := json.Marshal(r)
		if e != nil || len(raw) > systemMetadataLimit {
			return ErrStorage
		}
		if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, raw, snap.InvitationID); e != nil {
			return ErrStorage
		}
		t.system[snap.InvitationID] = r
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}

func validSystemFilter(section, filter string) bool {
	if filter == "" || filter == "all" {
		return true
	}
	if section == "services" {
		return filter == "active" || filter == "failed" || filter == "enabled"
	}
	return section == "sockets" && (filter == "tcp-listeners" || filter == "udp" || filter == "connections")
}
func systemServiceFilter(row systeminventory.Service, filter string) bool {
	switch filter {
	case "active":
		return row.Runtime != nil && row.Runtime.ActiveState == "active"
	case "failed":
		return row.Runtime != nil && row.Runtime.ActiveState == "failed"
	case "enabled":
		return row.Enablement != nil && (*row.Enablement == "enabled" || *row.Enablement == "enabled-runtime")
	}
	return true
}
func systemSocketFilter(row systeminventory.Socket, filter string) bool {
	switch filter {
	case "tcp-listeners":
		return row.Protocol == "tcp" && row.Kind == "listener"
	case "udp":
		return row.Protocol == "udp"
	case "connections":
		return row.Kind == "connection"
	}
	return true
}
