package windowsnetworkcontext

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
)

func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func ValidHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func ValidTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 2020 && t.Year() <= 9999
}
func ValidSequence(v uint64) bool { return v > 0 && v <= MaxSequence }
func ValidateConsent(c Consent) error {
	if c.SchemaVersion != ConsentVersion || c.Scope != Scope || !ValidHex(c.SenderBinding, 64) || !ValidHex(c.GrantID, 32) || !ValidSequence(c.Revision) || !ValidTime(c.ChangedAt) {
		return ErrInvalid
	}
	return nil
}
func EncodeConsent(c Consent) ([]byte, error) {
	if e := ValidateConsent(c); e != nil {
		return nil, e
	}
	return json.Marshal(c)
}
func DecodeConsent(raw []byte) (Consent, error) {
	var c Consent
	if strict(raw, 2048, &c) != nil || ValidateConsent(c) != nil {
		return Consent{}, ErrInvalid
	}
	return c, nil
}
func validText(s string, empty bool) bool {
	return (empty || s != "") && len(s) <= MaxFieldBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(utf16.Encode([]rune(s))) <= MaxFieldUTF16
}
func validCounter(s string) bool {
	v, e := strconv.ParseUint(s, 10, 64)
	return e == nil && strconv.FormatUint(v, 10) == s
}
func ValidateRow(r Row) error {
	if r.ID == 0 || r.ID > MaxRows || r.InterfaceIndex == 0 {
		return ErrInvalid
	}
	switch r.Kind {
	case "route":
		if r.Route == nil || r.Counters != nil {
			return ErrInvalid
		}
		p, e := netip.ParsePrefix(r.Route.Destination)
		h, he := netip.ParseAddr(r.Route.NextHop)
		if e != nil || he != nil || p.String() != r.Route.Destination || p != p.Masked() || h.String() != r.Route.NextHop || p.Addr().Is4() != h.Is4() || p.Addr().Is4In6() || h.Is4In6() || p.Addr().Is4() && r.Route.DestinationScopeID != 0 {
			return ErrInvalid
		}
		if h.Zone() != "" {
			v, e := strconv.ParseUint(h.Zone(), 10, 32)
			if e != nil || v == 0 || strconv.FormatUint(v, 10) != h.Zone() {
				return ErrInvalid
			}
		}
	case "interface":
		if r.Route != nil || r.Counters == nil {
			return ErrInvalid
		}
		c := r.Counters
		if c.Alias == nil {
			if c.AliasQuality != "unavailable" {
				return ErrInvalid
			}
		} else if c.AliasQuality != "observed" || !validText(*c.Alias, false) {
			return ErrInvalid
		}
		for _, v := range []string{c.InOctets, c.OutOctets, c.InErrors, c.OutErrors, c.InDiscards, c.OutDiscards} {
			if !validCounter(v) {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}

// RowsDigest validates capture-local row order only. It never treats an
// interface index as a join between independently captured source tables.
func RowsDigest(rows []Row) (string, int, error) {
	if len(rows) > MaxRows {
		return "", 0, ErrBudget
	}
	if rows == nil {
		return "", 0, ErrInvalid
	}
	routes, interfaces := 0, 0
	for i, r := range rows {
		if ValidateRow(r) != nil || i > 0 && rows[i-1].ID >= r.ID {
			return "", 0, ErrInvalid
		}
		if r.Kind == "route" {
			routes++
		} else {
			interfaces++
		}
	}
	if routes > MaxRoutes || interfaces > MaxInterfaces {
		return "", 0, ErrBudget
	}
	raw, e := json.Marshal(rows)
	if e != nil || len(raw) > MaxSourceBytes {
		return "", 0, ErrBudget
	}
	return Hash(append([]byte("tracebolt.windows-network-context.rows.v1\x00"), raw...)), len(raw), nil
}
func GenerationID(device, grant string, sequence uint64) (string, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") || !ValidHex(grant, 32) || !ValidSequence(sequence) {
		return "", ErrInvalid
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	h := sha256.New()
	h.Write([]byte("tracebolt.windows-network-context.generation.v1\x00"))
	h.Write([]byte(device))
	h.Write([]byte{0})
	h.Write([]byte(grant))
	h.Write(seq[:])
	return "sample_" + hex.EncodeToString(h.Sum(nil)[:16]), nil
}
func ValidateManifest(m Manifest) error {
	id, e := GenerationID(m.DeviceID, m.GrantID, m.Sequence)
	if e != nil || id != m.GenerationID || m.SchemaVersion != ManifestVersion || m.Scope != Scope || m.Source != Source || m.Coverage != Coverage || !ValidHex(m.SenderBinding, 64) || !ValidSequence(m.GrantRevision) || !ValidTime(m.CaptureStartedAt) || !ValidTime(m.CaptureFinishedAt) || !ValidTime(m.ExpiresAt) || m.CaptureFinishedAt.Before(m.CaptureStartedAt) || m.CaptureFinishedAt.Sub(m.CaptureStartedAt) > CaptureTimeout || !m.ExpiresAt.Equal(m.CaptureStartedAt.Add(Retention)) || m.RowCount < 0 || m.RowCount > MaxRows || m.RowsBytes < 2 || m.RowsBytes > MaxSourceBytes || !ValidHex(m.RowsSHA256, 64) || m.ChunkCount < 1 || m.ChunkCount > MaxChunks || m.RowCount == 0 && m.ChunkCount != 1 || m.RowCount > 0 && (m.ChunkCount > m.RowCount || m.RowCount > m.ChunkCount*MaxChunkRows) {
		return ErrInvalid
	}
	return nil
}
func ManifestDigest(m Manifest) (string, error) {
	if e := ValidateManifest(m); e != nil {
		return "", e
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return "", ErrInvalid
	}
	return Hash(append([]byte("tracebolt.windows-network-context.manifest.v1\x00"), raw...)), nil
}
func ValidFailureReason(s string) bool {
	switch s {
	case "access_denied", "unavailable", "unsupported", "source_changed", "malformed_source", "resource_limit", "deadline", "canceled":
		return true
	}
	return false
}
func (m Message) WireSequence() uint64 {
	if m.Operation == "scope" {
		return m.Consent.Revision
	}
	return m.Sequence
}
func ValidateMessage(m Message) error {
	if m.SchemaVersion != MessageVersion || !enrollmentcrypto.ValidID(m.DeviceID, "agent_") || ValidateConsent(m.Consent) != nil {
		return ErrInvalid
	}
	switch m.Operation {
	case "scope":
		if m.Sequence != 0 || m.Manifest != nil || m.ManifestSHA256 != "" || m.Index != 0 || m.Offset != 0 || len(m.Rows) != 0 || m.AttemptedAt != nil || m.Reason != "" {
			return ErrInvalid
		}
	case "failure":
		if !m.Consent.Enabled || !ValidSequence(m.Sequence) || m.Manifest != nil || m.ManifestSHA256 != "" || m.Index != 0 || m.Offset != 0 || len(m.Rows) != 0 || m.AttemptedAt == nil || !ValidTime(*m.AttemptedAt) || m.AttemptedAt.Before(m.Consent.ChangedAt) || !ValidFailureReason(m.Reason) {
			return ErrInvalid
		}
	case "chunk":
		if !m.Consent.Enabled || m.Manifest == nil || m.AttemptedAt != nil || m.Reason != "" {
			return ErrInvalid
		}
		v := m.Manifest
		digest, e := ManifestDigest(*v)
		if e != nil || digest != m.ManifestSHA256 || m.DeviceID != v.DeviceID || m.Consent.SenderBinding != v.SenderBinding || m.Consent.GrantID != v.GrantID || m.Consent.Revision != v.GrantRevision || m.Sequence != v.Sequence || v.CaptureStartedAt.Before(m.Consent.ChangedAt) || m.Index < 0 || m.Index >= v.ChunkCount || m.Offset < 0 || m.Offset > v.RowCount || len(m.Rows) > MaxChunkRows || m.Offset+len(m.Rows) > v.RowCount || v.RowCount > 0 && len(m.Rows) == 0 || m.Index == 0 && m.Offset != 0 || m.Index == v.ChunkCount-1 && m.Offset+len(m.Rows) != v.RowCount {
			return ErrInvalid
		}
		for i, row := range m.Rows {
			if row.ID != uint32(m.Offset+i+1) {
				return ErrInvalid
			}
		}
		if _, _, e := RowsDigest(append([]Row{}, m.Rows...)); e != nil {
			return e
		}
	default:
		return ErrInvalid
	}
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > MaxChunkBytes {
		return ErrBudget
	}
	return nil
}
func EncodeMessage(m Message) ([]byte, error) {
	if e := ValidateMessage(m); e != nil {
		return nil, e
	}
	return json.Marshal(m)
}
func DecodeMessage(raw []byte) (Message, error) {
	var m Message
	if strict(raw, MaxChunkBytes, &m) != nil || ValidateMessage(m) != nil {
		return Message{}, ErrInvalid
	}
	return m, nil
}
func strict(raw []byte, max int, out any) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}
func DecodeReceipt(raw, request []byte) (Receipt, error) {
	var r Receipt
	m, e := DecodeMessage(request)
	if e != nil || strict(raw, 2048, &r) != nil || r.SchemaVersion != ReceiptVersion || r.Operation != m.Operation || r.DeviceID != m.DeviceID || r.GrantID != m.Consent.GrantID || r.GrantRevision != m.Consent.Revision || r.Sequence != m.Sequence || r.RequestSHA256 != Hash(request) || r.Index != m.Index || !ValidTime(r.ReceivedAt) {
		return Receipt{}, ErrInvalid
	}
	expected := "accepted"
	if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
		expected = "complete"
	}
	if r.Status != expected {
		return Receipt{}, ErrInvalid
	}
	return r, nil
}
func ValidateQuery(q Query) error {
	if q.Kind != "all" && q.Kind != "route" && q.Kind != "interface" {
		return ErrInvalid
	}
	if !utf8.ValidString(q.Search) || strings.ContainsRune(q.Search, 0) || len(q.Search) > MaxQueryBytes || q.Limit < 1 || q.Limit > MaxPageRows || len(q.Cursor) > MaxCursorBytes {
		return ErrInvalid
	}
	for _, r := range q.Cursor {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return ErrInvalid
		}
	}
	switch q.Sort {
	case "source-asc", "source-desc", "interface-asc", "interface-desc":
		return nil
	}
	return ErrInvalid
}

// Build freezes one complete capture before any transport call. The canonical
// rows and request bytes have independent byte ceilings; none are truncated.
func Build(device string, c Consent, sequence uint64, capture Capture) ([]Message, error) {
	if ValidateConsent(c) != nil || !c.Enabled || !capture.Complete || capture.Reason != "" {
		return nil, ErrInvalid
	}
	rows := append([]Row{}, capture.Rows...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	digest, size, e := RowsDigest(rows)
	if e != nil {
		return nil, e
	}
	id, e := GenerationID(device, c.GrantID, sequence)
	if e != nil {
		return nil, e
	}
	// Reserve 4 KiB for the typed envelope, larger than the validated manifest and
	// consent. Compute each source row once to avoid quadratic full-generation work.
	pieces := [][]Row{}
	start, used := 0, 2
	for i, row := range rows {
		raw, _ := json.Marshal(row)
		needed := len(raw) + 1
		if i > start && (i-start >= MaxChunkRows || used+needed > MaxChunkBytes-4096) {
			pieces = append(pieces, rows[start:i])
			start = i
			used = 2
		}
		used += needed
	}
	pieces = append(pieces, rows[start:])
	m := Manifest{ManifestVersion, Scope, Source, Coverage, device, c.SenderBinding, c.GrantID, c.Revision, sequence, id, capture.StartedAt, capture.FinishedAt, capture.StartedAt.Add(Retention), len(rows), size, digest, len(pieces)}
	hash, e := ManifestDigest(m)
	if e != nil {
		return nil, e
	}
	out := make([]Message, 0, len(pieces))
	offset := 0
	for index, part := range pieces {
		v := m
		message := Message{SchemaVersion: MessageVersion, Operation: "chunk", DeviceID: device, Consent: c, Sequence: sequence, Manifest: &v, ManifestSHA256: hash, Index: index, Offset: offset, Rows: part}
		if ValidateMessage(message) != nil {
			return nil, ErrBudget
		}
		out = append(out, message)
		offset += len(part)
	}
	return out, nil
}

// SenderBinding matches the existing Windows identity binding without exposing
// local paths or broadening any old grant. The manager recomputes it from its
// independently authenticated identity and pinned ingress origin.
func SenderBinding(profile, origin, certificateHash, device string) string {
	return Hash([]byte("tracebolt.sender-binding.windows.v1\nwindows-inventory-v1\n" + profile + "\n" + origin + "\n" + certificateHash + "\n" + device))
}

// IdentityKey normalizes literal Unicode case-insensitive search only. It is
// never used for interface identity, table joining or deduplication.
func IdentityKey(name string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		return smallest
	}, name)
}
