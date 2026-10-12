package windowsusersoftware

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
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
func ValidateRow(r Row) error {
	if !ValidHex(r.RegistrationID, 64) || (r.Source != "hkcu" && r.Source != "msix") {
		return ErrInvalid
	}
	for _, f := range []struct {
		value   *string
		quality string
	}{{r.Name, r.NameQuality}, {r.Version, r.VersionQuality}, {r.Publisher, r.PublisherQuality}} {
		if f.value == nil && f.quality != "unavailable" || f.value != nil && (f.quality != "observed" || !validText(*f.value, true)) {
			return ErrInvalid
		}
	}
	return nil
}

// RegistrationID is an opaque source-scoped identity, never an application or action ID.
func RegistrationID(source string, name []uint16) (string, error) {
	if (source != "hkcu" && source != "msix") || len(name) == 0 || len(name) > 512 {
		return "", ErrInvalid
	}
	raw := []byte("tracebolt.windows-selected-user-software.registration.v1\x00" + source + "\x00")
	for i, v := range name {
		if v == 0 || v >= 0xd800 && v <= 0xdbff && (i+1 == len(name) || name[i+1] < 0xdc00 || name[i+1] > 0xdfff) || v >= 0xdc00 && v <= 0xdfff && (i == 0 || name[i-1] < 0xd800 || name[i-1] > 0xdbff) {
			return "", ErrInvalid
		}
		raw = binary.LittleEndian.AppendUint16(raw, v)
	}
	return Hash(raw), nil
}

// AccountContextID must only receive the SID from the agent's held, OS-verified
// local peer token. It must never be computed from a caller-supplied SID.
func AccountContextID(device, verifiedSID string) (string, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") || len(verifiedSID) > 184 || !strings.HasPrefix(verifiedSID, "S-1-") {
		return "", ErrInvalid
	}
	for _, r := range verifiedSID[4:] {
		if !(r >= '0' && r <= '9' || r == '-') {
			return "", ErrInvalid
		}
	}
	return Hash([]byte("tracebolt.windows-selected-user-software.account.v1\x00" + device + "\x00" + verifiedSID)), nil
}
func ValidAccount(id, label, nonce string) bool {
	return ValidHex(id, 64) && validText(label, false) && len(label) <= 256 && ValidHex(nonce, 64)
}
func ValidSourceStatus(status string) bool { return status == "complete" || ValidFailureReason(status) }
func CaptureCoverage(hkcu, msix string) string {
	if hkcu == "complete" && msix == "complete" {
		return Coverage
	}
	return PartialCoverage
}
func ValidateSourceRows(rows []Row, hkcu, msix string) error {
	if !ValidSourceStatus(hkcu) || !ValidSourceStatus(msix) {
		return ErrInvalid
	}
	for _, r := range rows {
		if r.Source == "hkcu" && hkcu != "complete" || r.Source == "msix" && msix != "complete" {
			return ErrInvalid
		}
	}
	return nil
}

// RowsDigest validates exact opaque registration order. Duplicate display names
// are retained; only duplicate source-key identities are rejected.
func RowsDigest(rows []Row) (string, int, error) {
	if rows == nil || len(rows) > MaxRows {
		return "", 0, ErrInvalid
	}
	seen := make(map[string]bool, len(rows))
	for i, r := range rows {
		key := r.RegistrationID
		if ValidateRow(r) != nil || seen[key] || i > 0 && rows[i-1].RegistrationID >= r.RegistrationID {
			return "", 0, ErrInvalid
		}
		seen[key] = true
	}
	raw, e := json.Marshal(rows)
	if e != nil || len(raw) > MaxSourceBytes {
		return "", 0, ErrBudget
	}
	return Hash(append([]byte("tracebolt.windows-selected-user-software.rows.v1\x00"), raw...)), len(raw), nil
}
func GenerationID(device, grant string, sequence uint64) (string, error) {
	if !enrollmentcrypto.ValidID(device, "agent_") || !ValidHex(grant, 32) || !ValidSequence(sequence) {
		return "", ErrInvalid
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	h := sha256.New()
	h.Write([]byte("tracebolt.windows-selected-user-software.generation.v1\x00"))
	h.Write([]byte(device))
	h.Write([]byte{0})
	h.Write([]byte(grant))
	h.Write(seq[:])
	return "sample_" + hex.EncodeToString(h.Sum(nil)[:16]), nil
}
func ValidateManifest(m Manifest) error {
	id, e := GenerationID(m.DeviceID, m.GrantID, m.Sequence)
	if e != nil || id != m.GenerationID || m.SchemaVersion != ManifestVersion || m.Scope != Scope || m.Source != Source || m.Coverage != CaptureCoverage(m.HKCUStatus, m.MSIXStatus) || !ValidSourceStatus(m.HKCUStatus) || !ValidSourceStatus(m.MSIXStatus) || !ValidAccount(m.AccountContextID, m.AccountLabel, m.CaptureNonce) || !ValidHex(m.SenderBinding, 64) || !ValidSequence(m.GrantRevision) || !ValidTime(m.CaptureStartedAt) || !ValidTime(m.CaptureFinishedAt) || !ValidTime(m.ExpiresAt) || m.CaptureFinishedAt.Before(m.CaptureStartedAt) || m.CaptureFinishedAt.Sub(m.CaptureStartedAt) > CaptureTimeout || !m.ExpiresAt.Equal(m.CaptureStartedAt.Add(Retention)) || m.RowCount < 0 || m.RowCount > MaxRows || m.RowsBytes < 2 || m.RowsBytes > MaxSourceBytes || !ValidHex(m.RowsSHA256, 64) || m.ChunkCount < 1 || m.ChunkCount > MaxChunks || m.RowCount == 0 && m.ChunkCount != 1 || m.RowCount > 0 && (m.ChunkCount > m.RowCount || m.RowCount > m.ChunkCount*MaxChunkRows) {
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
	return Hash(append([]byte("tracebolt.windows-selected-user-software.manifest.v1\x00"), raw...)), nil
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
		if m.AccountContextID != "" || m.AccountLabel != "" || m.CaptureNonce != "" {
			return ErrInvalid
		}
		if m.Sequence != 0 || m.Manifest != nil || m.ManifestSHA256 != "" || m.Index != 0 || m.Offset != 0 || len(m.Rows) != 0 || m.AttemptedAt != nil || m.Reason != "" {
			return ErrInvalid
		}
	case "failure":
		if !ValidAccount(m.AccountContextID, m.AccountLabel, m.CaptureNonce) {
			return ErrInvalid
		}
		if !m.Consent.Enabled || !ValidSequence(m.Sequence) || m.Manifest != nil || m.ManifestSHA256 != "" || m.Index != 0 || m.Offset != 0 || len(m.Rows) != 0 || m.AttemptedAt == nil || !ValidTime(*m.AttemptedAt) || m.AttemptedAt.Before(m.Consent.ChangedAt) || !ValidFailureReason(m.Reason) {
			return ErrInvalid
		}
	case "chunk":
		if m.AccountContextID != "" || m.AccountLabel != "" || m.CaptureNonce != "" {
			return ErrInvalid
		}
		if !m.Consent.Enabled || m.Manifest == nil || m.AttemptedAt != nil || m.Reason != "" {
			return ErrInvalid
		}
		v := m.Manifest
		digest, e := ManifestDigest(*v)
		if e != nil || digest != m.ManifestSHA256 || m.DeviceID != v.DeviceID || m.Consent.SenderBinding != v.SenderBinding || m.Consent.GrantID != v.GrantID || m.Consent.Revision != v.GrantRevision || m.Sequence != v.Sequence || v.CaptureStartedAt.Before(m.Consent.ChangedAt) || m.Index < 0 || m.Index >= v.ChunkCount || m.Offset < 0 || m.Offset > v.RowCount || len(m.Rows) > MaxChunkRows || m.Offset+len(m.Rows) > v.RowCount || v.RowCount > 0 && len(m.Rows) == 0 || m.Index == 0 && m.Offset != 0 || m.Index == v.ChunkCount-1 && m.Offset+len(m.Rows) != v.RowCount {
			return ErrInvalid
		}
		if ValidateSourceRows(m.Rows, v.HKCUStatus, v.MSIXStatus) != nil {
			return ErrInvalid
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
	if q.AccountContextID != "" && !ValidHex(q.AccountContextID, 64) || q.Source != "" && q.Source != "hkcu" && q.Source != "msix" {
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
	case "name-asc", "name-desc", "version-asc", "version-desc", "publisher-asc", "publisher-desc", "source-asc", "source-desc":
		return nil
	}
	return ErrInvalid
}

// Build freezes one complete capture before any transport call. The canonical
// rows and request bytes have independent byte ceilings; none are truncated.
func Build(device string, c Consent, sequence uint64, capture Capture) ([]Message, error) {
	if ValidateConsent(c) != nil || !c.Enabled || !capture.Complete || capture.Reason != "" || !ValidAccount(capture.AccountContextID, capture.AccountLabel, capture.CaptureNonce) || ValidateSourceRows(capture.Rows, capture.HKCUStatus, capture.MSIXStatus) != nil {
		return nil, ErrInvalid
	}
	rows := append([]Row{}, capture.Rows...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].RegistrationID < rows[j].RegistrationID })
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
	m := Manifest{SchemaVersion: ManifestVersion, Scope: Scope, Source: Source, Coverage: CaptureCoverage(capture.HKCUStatus, capture.MSIXStatus), DeviceID: device, SenderBinding: c.SenderBinding, GrantID: c.GrantID, GrantRevision: c.Revision, Sequence: sequence, GenerationID: id, CaptureStartedAt: capture.StartedAt, CaptureFinishedAt: capture.FinishedAt, ExpiresAt: capture.StartedAt.Add(Retention), RowCount: len(rows), RowsBytes: size, RowsSHA256: digest, ChunkCount: len(pieces), AccountContextID: capture.AccountContextID, AccountLabel: capture.AccountLabel, CaptureNonce: capture.CaptureNonce, HKCUStatus: capture.HKCUStatus, MSIXStatus: capture.MSIXStatus}
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
// never used for native registry key identity or registration deduplication.
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

// ValidateAttempt keeps even unsuccessful captures explicitly account-bound.
func ValidateAttempt(a Attempt) error {
	if !ValidSequence(a.Sequence) || !ValidTime(a.AttemptedAt) || !ValidAccount(a.AccountContextID, a.AccountLabel, a.CaptureNonce) {
		return ErrInvalid
	}
	switch a.Status {
	case "pending", "complete", "expired":
		if a.Reason != "" {
			return ErrInvalid
		}
	case "source_failed":
		if !ValidFailureReason(a.Reason) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
