package windowsfullprocesses

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Storage is implemented only by protected windowsstate in production; fixture
// memory is not evidence of native file/ACL acceptance.
type Storage interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}
type senderRecord struct {
	Version        string     `json:"version"`
	DeviceID       string     `json:"deviceId"`
	SenderBinding  string     `json:"senderBinding"`
	Floor          uint64     `json:"floor"`
	Phase          string     `json:"phase"`
	Consent        *Consent   `json:"consent"`
	AttemptedAt    *time.Time `json:"attemptedAt"`
	LastAt         *time.Time `json:"lastAt"`
	PackSHA256     string     `json:"packSha256"`
	Next           int        `json:"next"`
	ScopeACKSHA256 string     `json:"scopeAckSha256"`
}
type packRecord struct {
	Version       string            `json:"version"`
	DeviceID      string            `json:"deviceId"`
	SenderBinding string            `json:"senderBinding"`
	Sequence      uint64            `json:"sequence"`
	Messages      []json.RawMessage `json:"messages"`
}
type State struct {
	storage  Storage
	record   senderRecord
	pack     packRecord
	poisoned bool
}

func (*State) String() string               { return "Windows complete process inventory state (contents redacted)" }
func (s *State) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*State) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }
func InitializeState(st Storage, device, binding string) error {
	if st == nil || !ValidHex(binding, 64) {
		return ErrState
	}
	if _, e := GenerationID(device, "00000000000000000000000000000000", 1); e != nil {
		return ErrState
	}
	p := packRecord{"tracebolt.windows-full-processes-pack.v1", device, binding, 0, []json.RawMessage{}}
	raw, _ := json.Marshal(p)
	if st.Write("pack.json", raw) != nil {
		return ErrState
	}
	r := senderRecord{Version: "tracebolt.windows-full-processes-sender.v1", DeviceID: device, SenderBinding: binding, Phase: "idle"}
	raw, _ = json.Marshal(r)
	if st.Write("sender.json", raw) != nil {
		return ErrState
	}
	return nil
}
func OpenState(st Storage, device, binding string) (*State, error) {
	if st == nil {
		return nil, ErrState
	}
	raw, e := st.Read("sender.json")
	var r senderRecord
	if e != nil || strict(raw, 8192, &r) != nil || r.Version != "tracebolt.windows-full-processes-sender.v1" || r.DeviceID != device || r.SenderBinding != binding || !ValidHex(binding, 64) || r.Floor > MaxSequence || r.Next < 0 || r.Next > MaxChunks || r.ScopeACKSHA256 != "" && !ValidHex(r.ScopeACKSHA256, 64) {
		return nil, ErrState
	}
	if _, e := GenerationID(device, "00000000000000000000000000000000", 1); e != nil {
		return nil, ErrState
	}
	if r.Floor == 0 {
		if r.Phase != "idle" || r.Consent != nil || r.AttemptedAt != nil || r.Next != 0 || r.PackSHA256 != "" {
			return nil, ErrState
		}
	} else if r.Consent == nil || ValidateConsent(*r.Consent) != nil || r.Consent.SenderBinding != binding || !r.Consent.Enabled || r.AttemptedAt == nil || !ValidTime(*r.AttemptedAt) || r.AttemptedAt.Before(r.Consent.ChangedAt) {
		return nil, ErrState
	}
	if r.Floor > 0 && r.LastAt == nil {
		return nil, ErrState
	}
	if r.LastAt != nil && (!ValidTime(*r.LastAt) || r.AttemptedAt != nil && r.LastAt.Before(*r.AttemptedAt)) {
		return nil, ErrState
	}
	switch r.Phase {
	case "idle", "capturing":
		if r.Next != 0 || r.PackSHA256 != "" {
			return nil, ErrState
		}
	case "pending":
		if !ValidHex(r.PackSHA256, 64) {
			return nil, ErrState
		}
	default:
		return nil, ErrState
	}
	raw, e = st.Read("pack.json")
	var p packRecord
	if e != nil || strict(raw, MaxPackBytes, &p) != nil || p.Version != "tracebolt.windows-full-processes-pack.v1" || p.DeviceID != device || p.SenderBinding != binding || p.Messages == nil || len(p.Messages) > MaxChunks {
		return nil, ErrState
	}
	if len(p.Messages) == 0 {
		if p.Sequence != 0 {
			return nil, ErrState
		}
	} else if validatePack(p) != nil {
		return nil, ErrState
	}
	if r.Phase == "pending" && (p.Sequence != r.Floor || Hash(raw) != r.PackSHA256 || len(p.Messages) == 0 || r.Next >= len(p.Messages)) {
		return nil, ErrState
	}
	s := &State{storage: st, record: r, pack: p}
	if r.Phase == "pending" {
		m, _ := DecodeMessage(p.Messages[0])
		if r.Consent == nil || m.Consent != *r.Consent {
			return nil, ErrState
		}
	}
	return s, nil
}
func validatePack(p packRecord) error {
	rows := []Row{}
	var first Message
	for i, raw := range p.Messages {
		m, e := DecodeMessage(raw)
		if e != nil || m.DeviceID != p.DeviceID || m.Consent.SenderBinding != p.SenderBinding || m.Sequence != p.Sequence || m.Operation == "scope" {
			return ErrState
		}
		if i == 0 {
			first = m
		}
		if m.Consent != first.Consent || m.Operation != first.Operation {
			return ErrState
		}
		if m.Operation == "failure" {
			if len(p.Messages) != 1 {
				return ErrState
			}
			continue
		}
		if m.ManifestSHA256 != first.ManifestSHA256 || m.Index != i || m.Offset != len(rows) || m.Manifest.ChunkCount != len(p.Messages) {
			return ErrState
		}
		rows = append(rows, m.Rows...)
	}
	if first.Operation == "chunk" {
		hash, n, e := RowsDigest(rows)
		if e != nil || len(rows) != first.Manifest.RowCount || n != first.Manifest.RowsBytes || hash != first.Manifest.RowsSHA256 {
			return ErrState
		}
	}
	return nil
}
func (s *State) save(r senderRecord) error {
	if s == nil || s.poisoned {
		return ErrState
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 8192 || s.storage.Write("sender.json", raw) != nil {
		s.poisoned = true
		return ErrState
	}
	s.record = r
	return nil
}
func (s *State) Close() error {
	if s == nil {
		return nil
	}
	for _, raw := range s.pack.Messages {
		clear(raw)
	}
	s.pack.Messages = nil
	return s.storage.Close()
}
func (s *State) Floor() uint64 {
	if s == nil {
		return 0
	}
	return s.record.Floor
}
func (s *State) Pending() bool { return s != nil && s.record.Phase != "idle" }
func (s *State) checkTime(now time.Time) error {
	if s == nil || s.poisoned || !ValidTime(now) || s.record.LastAt != nil && now.Before(*s.record.LastAt) {
		return ErrState
	}
	return nil
}
func (s *State) Scope(c Consent) ([]byte, bool, error) {
	if s == nil || s.poisoned || ValidateConsent(c) != nil || c.SenderBinding != s.record.SenderBinding {
		return nil, false, ErrState
	}
	raw, e := EncodeMessage(Message{SchemaVersion: MessageVersion, Operation: "scope", DeviceID: s.record.DeviceID, Consent: c})
	if e != nil {
		return nil, false, e
	}
	return raw, Hash(raw) != s.record.ScopeACKSHA256, nil
}
func (s *State) AcknowledgeScope(raw, receipt []byte, now time.Time) error {
	m, e := DecodeMessage(raw)
	if e != nil || m.Operation != "scope" || m.DeviceID != s.record.DeviceID || m.Consent.SenderBinding != s.record.SenderBinding || s.checkTime(now) != nil {
		return ErrState
	}
	if _, e := DecodeReceipt(receipt, raw); e != nil {
		return e
	}
	r := s.record
	r.ScopeACKSHA256 = Hash(raw)
	r.LastAt = &now
	return s.save(r)
}

// Reserve consumes a floor before capture; restart cannot recapture on it.
func (s *State) Reserve(c Consent, now time.Time) (uint64, error) {
	if s.checkTime(now) != nil || s.record.Phase != "idle" || !c.Enabled || ValidateConsent(c) != nil || c.SenderBinding != s.record.SenderBinding || now.Before(c.ChangedAt) || s.record.Floor == MaxSequence {
		return 0, ErrState
	}
	if s.record.AttemptedAt != nil && now.Sub(*s.record.AttemptedAt) < CaptureInterval {
		return 0, ErrUnavailable
	}
	r := s.record
	r.Floor++
	r.Phase = "capturing"
	r.Consent = &c
	r.AttemptedAt = &now
	r.LastAt = &now
	r.Next = 0
	r.PackSHA256 = ""
	if s.save(r) != nil {
		return 0, ErrState
	}
	return r.Floor, nil
}
func (s *State) freeze(messages []Message, now time.Time) error {
	if s.checkTime(now) != nil || s.record.Phase != "capturing" || len(messages) == 0 {
		return ErrState
	}
	p := packRecord{"tracebolt.windows-full-processes-pack.v1", s.record.DeviceID, s.record.SenderBinding, s.record.Floor, []json.RawMessage{}}
	for _, m := range messages {
		raw, e := EncodeMessage(m)
		if e != nil {
			return e
		}
		p.Messages = append(p.Messages, raw)
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxPackBytes {
		return ErrBudget
	}
	if validatePack(p) != nil {
		return ErrState
	}
	if s.storage.Write("pack.json", raw) != nil {
		s.poisoned = true
		return ErrState
	}
	s.pack = p
	r := s.record
	r.Phase = "pending"
	r.PackSHA256 = Hash(raw)
	r.Next = 0
	r.LastAt = &now
	return s.save(r)
}
func (s *State) Finish(capture Capture, sourceErr error, now time.Time) error {
	if s == nil || s.record.Phase != "capturing" || s.record.Consent == nil || s.record.AttemptedAt == nil {
		return ErrState
	}
	c := *s.record.Consent
	if sourceErr == nil && capture.Complete && (capture.StartedAt.Before(*s.record.AttemptedAt) || capture.FinishedAt.After(now)) {
		capture.Complete = false
		capture.Reason = "malformed_source"
	}
	if sourceErr == nil && capture.Complete {
		messages, e := Build(s.record.DeviceID, c, s.record.Floor, capture)
		if e == nil {
			return s.freeze(messages, now)
		}
		if e == ErrBudget {
			capture.Reason = "resource_limit"
		} else {
			capture.Reason = "malformed_source"
		}
	}
	reason := capture.Reason
	if !ValidFailureReason(reason) {
		switch {
		case errors.Is(sourceErr, context.DeadlineExceeded):
			reason = "deadline"
		case errors.Is(sourceErr, context.Canceled):
			reason = "canceled"
		case errors.Is(sourceErr, ErrBudget):
			reason = "resource_limit"
		case errors.Is(sourceErr, ErrUnsupported):
			reason = "unsupported"
		case errors.Is(sourceErr, ErrDenied):
			reason = "access_denied"
		default:
			reason = "unavailable"
		}
	}
	at := *s.record.AttemptedAt
	return s.freeze([]Message{{SchemaVersion: MessageVersion, Operation: "failure", DeviceID: s.record.DeviceID, Consent: c, Sequence: s.record.Floor, AttemptedAt: &at, Reason: reason}}, now)
}
func (s *State) Recover(now time.Time) error {
	if s == nil || s.record.Phase != "capturing" {
		return nil
	}
	if s.checkTime(now) != nil {
		return ErrState
	}
	if s.pack.Sequence == s.record.Floor && len(s.pack.Messages) > 0 {
		first, e := DecodeMessage(s.pack.Messages[0])
		if e != nil || first.Consent != *s.record.Consent {
			return ErrState
		}
		raw, _ := json.Marshal(s.pack)
		r := s.record
		r.Phase = "pending"
		r.PackSHA256 = Hash(raw)
		r.LastAt = &now
		return s.save(r)
	}
	return s.Finish(Capture{Reason: "unavailable"}, ErrUnavailable, now)
}
func (s *State) Next(c Consent, now time.Time) ([]byte, string, error) {
	if s.checkTime(now) != nil || ValidateConsent(c) != nil || c.SenderBinding != s.record.SenderBinding {
		return nil, "", ErrState
	}
	if !c.Enabled {
		return nil, "disabled", nil
	}
	if s.record.Phase == "capturing" {
		if e := s.Recover(now); e != nil {
			return nil, "", e
		}
	}
	if s.record.Phase == "idle" {
		if s.record.AttemptedAt != nil && now.Sub(*s.record.AttemptedAt) < CaptureInterval {
			return nil, "not_due", nil
		}
		return nil, "capture_due", nil
	}
	first, e := DecodeMessage(s.pack.Messages[0])
	if e != nil {
		return nil, "", ErrState
	}
	expired := first.Operation == "chunk" && !now.Before(first.Manifest.ExpiresAt) || first.Operation == "failure" && !now.Before(first.AttemptedAt.Add(Retention))
	if first.Consent != c || expired {
		status := "discarded_unconsented"
		if expired {
			status = "expired"
		}
		r := s.record
		r.Phase = "idle"
		r.Next = 0
		r.PackSHA256 = ""
		r.LastAt = &now
		if s.save(r) != nil {
			return nil, "", ErrState
		}
		return nil, status, nil
	}
	return bytes.Clone(s.pack.Messages[s.record.Next]), "pending", nil
}
func (s *State) Acknowledge(raw, receipt []byte, now time.Time) error {
	if s.checkTime(now) != nil || s.record.Phase != "pending" || s.record.Next >= len(s.pack.Messages) || !bytes.Equal(raw, s.pack.Messages[s.record.Next]) {
		return ErrState
	}
	if _, e := DecodeReceipt(receipt, raw); e != nil {
		return e
	}
	r := s.record
	r.Next++
	r.LastAt = &now
	if r.Next == len(s.pack.Messages) {
		r.Phase = "idle"
		r.Next = 0
		r.PackSHA256 = ""
	}
	return s.save(r)
}
