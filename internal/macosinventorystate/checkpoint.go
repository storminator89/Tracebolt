// Package macosinventorystate is an inactive, pure sender-state foundation.
// It neither authenticates authority nor supplies disk storage, collection,
// transport, cancellation, credentials or runtime registration.
package macosinventorystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	wire "localrmm/internal/macosinventorywire"
)

const (
	CheckpointVersion = "tracebolt.macos-read-inventory-sender.v1"
	// MaxCheckpointBytes includes all JSON syntax and base64 expansion of exact
	// request/receipt bytes. There is at most one 520 KiB report, not a history.
	MaxCheckpointBytes = 768 * 1024
)

var (
	ErrInvalid    = errors.New("macos_inventory_state_invalid")
	ErrBounds     = errors.New("macos_inventory_state_bounds")
	ErrMissing    = errors.New("macos_inventory_state_missing_used_checkpoint")
	ErrConflict   = errors.New("macos_inventory_state_conflict")
	ErrUncertain  = errors.New("macos_inventory_state_commit_uncertain")
	ErrClosed     = errors.New("macos_inventory_state_closed")
	ErrDisabled   = errors.New("macos_inventory_state_terminal_disabled")
	ErrNotEnabled = errors.New("macos_inventory_state_enable_unacknowledged")
	ErrBusy       = errors.New("macos_inventory_state_attempt_unsettled")
	ErrPacing     = errors.New("macos_inventory_state_capture_too_soon")
	ErrClock      = errors.New("macos_inventory_state_clock_invalid")
	ErrExpired    = errors.New("macos_inventory_state_original_capture_expired")
	ErrNoPending  = errors.New("macos_inventory_state_no_pending_request")
)

// FailureReason is a closed safe vocabulary. Provider/source error text is never
// accepted. Lost attempts remain consumed even when no report exists.
type FailureReason string

const (
	FailureCollection  FailureReason = "collection_failed"
	FailureInterrupted FailureReason = "interrupted"
	FailureDisabled    FailureReason = "terminal_disabled"
)

type attempt struct {
	Sequence    uint64        `json:"sequence"`
	CollectedAt time.Time     `json:"collectedAt"`
	Status      string        `json:"status"`
	Reason      FailureReason `json:"reason"`
}

type reportRecord struct {
	Sequence       uint64    `json:"sequence"`
	GenerationID   string    `json:"generationId"`
	CollectedAt    time.Time `json:"collectedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	SnapshotSHA256 string    `json:"snapshotSha256"`
	RequestSHA256  string    `json:"requestSha256"`
	SourceQuality  string    `json:"sourceQuality"`
	Body           []byte    `json:"body"`
	Receipt        []byte    `json:"receipt"`
}

type checkpoint struct {
	SchemaVersion  string        `json:"schemaVersion"`
	Used           bool          `json:"used"`
	Enable         []byte        `json:"enable"`
	EnableReceipt  []byte        `json:"enableReceipt"`
	Disable        []byte        `json:"disable"`
	DisableReceipt []byte        `json:"disableReceipt"`
	Floor          uint64        `json:"floor"`
	LastCaptureAt  *time.Time    `json:"lastCaptureAt"`
	ClockAt        time.Time     `json:"clockAt"`
	Attempt        *attempt      `json:"attempt"`
	LastFailure    *attempt      `json:"lastFailure"`
	Report         *reportRecord `json:"report"`
}

func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func strict(raw []byte, max int, out any) error {
	if len(raw) > max {
		return ErrBounds
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrInvalid
	}
	return nil
}
func decode(raw []byte) (checkpoint, error) {
	var c checkpoint
	if len(raw) == 0 {
		return c, ErrMissing
	}
	if e := strict(raw, MaxCheckpointBytes, &c); e != nil {
		return checkpoint{}, e
	}
	if e := validate(c); e != nil {
		return checkpoint{}, e
	}
	return c, nil
}
func encode(c checkpoint) ([]byte, error) {
	if e := validate(c); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, ErrInvalid
	}
	if len(raw) > MaxCheckpointBytes {
		return nil, ErrBounds
	}
	return raw, nil
}

// ValidateCheckpoint is structural only. The expected original enable must come
// from the authenticated initializer's immutable binding, not a current leaf.
// Neither canonical bytes nor this check proves provenance or storage integrity.
func ValidateCheckpoint(raw, originalEnable []byte) error {
	c, e := decode(raw)
	if e != nil {
		return e
	}
	if !bytes.Equal(c.Enable, originalEnable) {
		return ErrConflict
	}
	return nil
}

func receipt(raw, request []byte, now time.Time) error {
	if len(raw) == 0 {
		return ErrInvalid
	}
	r, e := wire.DecodeReceipt(raw, request)
	if e != nil || r.ReceivedAt.After(now) {
		return ErrInvalid
	}
	return nil
}
func describe(raw []byte) (*reportRecord, error) {
	r, e := wire.DecodeReport(raw)
	if e != nil {
		return nil, ErrInvalid
	}
	// This computes a digest/metadata, never an actual admission receipt.
	proof, e := wire.ReceiptFor(raw, r.CollectedAt)
	if e != nil {
		return nil, ErrInvalid
	}
	return &reportRecord{Sequence: r.CaptureSequence, GenerationID: r.GenerationID, CollectedAt: r.CollectedAt, ExpiresAt: r.ExpiresAt, SnapshotSHA256: r.SnapshotSHA256, RequestSHA256: proof.RequestSHA256, SourceQuality: r.SourceQuality, Body: bytes.Clone(raw)}, nil
}
func validReport(p reportRecord, enable wire.Control, now time.Time) bool {
	id, e := wire.GenerationID(enable.Binding, enable.GrantID, enable.GrantRevision, p.Sequence)
	if e != nil || p.GenerationID != id || !validTime(p.CollectedAt) || !validTime(p.ExpiresAt) || p.CollectedAt.Before(enable.ChangedAt) || p.CollectedAt.After(now) || !p.ExpiresAt.Equal(p.CollectedAt.Add(wire.Retention)) || !hex(p.SnapshotSHA256) || !hex(p.RequestSHA256) {
		return false
	}
	switch p.SourceQuality {
	case "full", "partial", "unknown":
	default:
		return false
	}
	if len(p.Body) != 0 {
		if !now.Before(p.ExpiresAt) {
			return false
		}
		r, e := wire.DecodeReport(p.Body)
		if e != nil || wire.ValidateReportBinding(r, enable) != nil {
			return false
		}
		want, e := describe(p.Body)
		if e != nil || want.Sequence != p.Sequence || want.GenerationID != p.GenerationID || !want.CollectedAt.Equal(p.CollectedAt) || !want.ExpiresAt.Equal(p.ExpiresAt) || want.SnapshotSHA256 != p.SnapshotSHA256 || want.RequestSHA256 != p.RequestSHA256 || want.SourceQuality != p.SourceQuality {
			return false
		}
	} else if p.Body != nil || now.Before(p.ExpiresAt) {
		return false
	}
	if p.Receipt != nil {
		if len(p.Body) != 0 {
			return receipt(p.Receipt, p.Body, now) == nil
		}
		// Expired source bytes are gone. The immutable bounded receipt and digest
		// tombstone remain. This checks their exact fields, not deleted payloads.
		var r wire.Receipt
		if strict(p.Receipt, wire.MaxReceiptBytes, &r) != nil || r.CollectedAt == nil || !validTime(*r.CollectedAt) || !r.CollectedAt.Equal(p.CollectedAt) || !validTime(r.ReceivedAt) || r.ReceivedAt.Before(p.CollectedAt) || !r.ReceivedAt.Before(p.ExpiresAt) || r.ReceivedAt.After(now) {
			return false
		}
		r.CollectedAt = nil
		want := wire.Receipt{SchemaVersion: wire.ReceiptVersion, Kind: "report", Binding: enable.Binding, GrantID: enable.GrantID, GrantRevision: enable.GrantRevision, ControlRevision: enable.ControlRevision, CaptureFloor: p.Sequence, GenerationID: p.GenerationID, SnapshotSHA256: p.SnapshotSHA256, RequestSHA256: p.RequestSHA256, Status: "recorded", ReceivedAt: r.ReceivedAt}
		if r != want {
			return false
		}
	}
	return true
}
func validate(c checkpoint) error {
	enable, e := wire.DecodeControl(c.Enable)
	if e != nil || !enable.Enabled || c.SchemaVersion != CheckpointVersion || !c.Used || !validTime(c.ClockAt) || c.ClockAt.Before(enable.ChangedAt) || c.Floor > wire.MaxSequence {
		return ErrInvalid
	}
	if c.EnableReceipt != nil && receipt(c.EnableReceipt, c.Enable, c.ClockAt) != nil {
		return ErrInvalid
	}
	enableAck, _ := wire.DecodeReceipt(c.EnableReceipt, c.Enable)
	if c.Disable != nil {
		disable, e := wire.DecodeControl(c.Disable)
		if e != nil || disable.Enabled || disable.CaptureFloor != c.Floor || disable.ChangedAt.After(c.ClockAt) {
			return ErrInvalid
		}
		if _, e := wire.ValidateControlTransition(c.Enable, c.Disable, c.Floor); e != nil {
			return ErrInvalid
		}
		if c.EnableReceipt != nil && disable.ChangedAt.Before(enableAck.ReceivedAt) {
			return ErrInvalid
		}
		if c.LastCaptureAt != nil && disable.ChangedAt.Before(*c.LastCaptureAt) {
			return ErrInvalid
		}
		if c.DisableReceipt != nil && receipt(c.DisableReceipt, c.Disable, c.ClockAt) != nil {
			return ErrInvalid
		}
	} else if c.DisableReceipt != nil {
		return ErrInvalid
	}
	if c.Floor == 0 {
		if c.LastCaptureAt != nil || c.Attempt != nil || c.LastFailure != nil || c.Report != nil {
			return ErrInvalid
		}
		return nil
	}
	if c.EnableReceipt == nil || c.LastCaptureAt == nil || !validTime(*c.LastCaptureAt) || c.LastCaptureAt.Before(enable.ChangedAt) || c.LastCaptureAt.Before(enableAck.ReceivedAt) || c.LastCaptureAt.After(c.ClockAt) || c.Attempt == nil || c.Attempt.Sequence != c.Floor || !validTime(c.Attempt.CollectedAt) || !c.Attempt.CollectedAt.Equal(*c.LastCaptureAt) {
		return ErrInvalid
	}
	if c.LastFailure != nil {
		f := c.LastFailure
		if f.Reason == FailureDisabled && (c.Disable == nil || f.Sequence != c.Floor) || f.Sequence < c.Floor && f.CollectedAt.Add(wire.CaptureInterval).After(*c.LastCaptureAt) {
			return ErrInvalid
		}
		if f.Sequence == 0 || f.Sequence > c.Floor || !validTime(f.CollectedAt) || f.CollectedAt.Before(enable.ChangedAt) || f.CollectedAt.Before(enableAck.ReceivedAt) || f.CollectedAt.After(*c.LastCaptureAt) || !failure(*f) {
			return ErrInvalid
		}
	}
	if c.Report != nil {
		p := c.Report
		if p.Sequence > c.Floor || p.CollectedAt.Before(enableAck.ReceivedAt) || p.CollectedAt.After(*c.LastCaptureAt) || !validReport(*p, enable, c.ClockAt) {
			return ErrInvalid
		}
		var ack wire.Receipt
		if p.Receipt != nil {
			if strict(p.Receipt, wire.MaxReceiptBytes, &ack) != nil {
				return ErrInvalid
			}
			if p.Sequence < c.Floor && ack.ReceivedAt.After(*c.LastCaptureAt) {
				return ErrInvalid
			}
			if c.Disable != nil {
				disabled, _ := wire.DecodeControl(c.Disable)
				if ack.ReceivedAt.After(disabled.ChangedAt) {
					return ErrInvalid
				}
			}
		}
		if p.Sequence == c.Floor && !p.CollectedAt.Equal(*c.LastCaptureAt) {
			return ErrInvalid
		}
		if p.Sequence < c.Floor && (p.CollectedAt.Add(wire.CaptureInterval).After(*c.LastCaptureAt) || p.Receipt == nil && (p.Body != nil || c.LastCaptureAt.Before(p.ExpiresAt))) {
			return ErrInvalid
		}
		if f := c.LastFailure; f != nil {
			switch {
			case f.Sequence == p.Sequence:
				return ErrInvalid // one reservation cannot both produce a report and fail.
			case f.Sequence < p.Sequence:
				if f.CollectedAt.Add(wire.CaptureInterval).After(p.CollectedAt) {
					return ErrInvalid
				}
			case f.Sequence > p.Sequence:
				if p.CollectedAt.Add(wire.CaptureInterval).After(f.CollectedAt) || p.Receipt != nil && ack.ReceivedAt.After(f.CollectedAt) || p.Receipt == nil && f.CollectedAt.Before(p.ExpiresAt) {
					return ErrInvalid
				}
			}
		}
	}
	a := c.Attempt
	if c.LastFailure != nil && c.LastFailure.Sequence == c.Floor && *c.LastFailure != *a {
		return ErrInvalid
	}
	same := c.Report != nil && c.Report.Sequence == c.Floor
	switch a.Status {
	case "reserved":
		if c.Disable != nil || same || a.Reason != "" {
			return ErrInvalid
		}
	case "pending":
		if c.Disable != nil || !same || c.Report.Body == nil || c.Report.Receipt != nil || a.Reason != "" {
			return ErrInvalid
		}
	case "recorded":
		if !same || c.Report.Receipt == nil || a.Reason != "" {
			return ErrInvalid
		}
	case "expired":
		if !same || c.Report.Body != nil || c.Report.Receipt != nil || a.Reason != "" {
			return ErrInvalid
		}
	case "abandoned":
		if c.Disable == nil || !same || c.Report.Receipt != nil || a.Reason != FailureDisabled {
			return ErrInvalid
		}
	case "failed", "lost":
		if same || !failure(*a) || c.LastFailure == nil || *a != *c.LastFailure {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func failure(a attempt) bool {
	return a.Status == "failed" && a.Reason == FailureCollection || a.Status == "lost" && (a.Reason == FailureInterrupted || a.Reason == FailureDisabled)
}
func clone(c checkpoint) checkpoint {
	c.Enable, c.EnableReceipt = bytes.Clone(c.Enable), bytes.Clone(c.EnableReceipt)
	c.Disable, c.DisableReceipt = bytes.Clone(c.Disable), bytes.Clone(c.DisableReceipt)
	if c.LastCaptureAt != nil {
		v := *c.LastCaptureAt
		c.LastCaptureAt = &v
	}
	if c.Attempt != nil {
		v := *c.Attempt
		c.Attempt = &v
	}
	if c.LastFailure != nil {
		v := *c.LastFailure
		c.LastFailure = &v
	}
	if c.Report != nil {
		v := *c.Report
		v.Body, v.Receipt = bytes.Clone(v.Body), bytes.Clone(v.Receipt)
		c.Report = &v
	}
	return c
}
func advance(c checkpoint, now time.Time) checkpoint {
	c = clone(c)
	c.ClockAt = now
	if c.Report != nil && !now.Before(c.Report.ExpiresAt) {
		c.Report.Body = nil
		if c.Attempt.Status == "pending" {
			c.Attempt.Status = "expired"
		}
	}
	return c
}
