// Package windowshistorystate holds non-content consume-once and capability
// metadata. A protected Windows store supplies exclusive locking and atomic,
// durable writes; this package never initializes missing used files or captures.
package windowshistorystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
)

const Version = "tracebolt.windows-event-history-state.v1"
const MaxBytes = 32 << 10

var ErrState = errors.New("windows_event_history_state_unavailable")
var ErrConsumed = errors.New("windows_event_history_already_attempted")

// Storage is held exclusively for an operation. Write must durably commit
// before returning nil. Production uses windowsstate.Store without a fallback.
type Storage interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
}
type Binding struct {
	SenderBinding   string `json:"senderBinding"`
	Profile         string `json:"profile"`
	DeviceID        string `json:"deviceId"`
	CertificateHash string `json:"certificateHash"`
}

func Bound(local windowshistoryrequest.LocalContext) Binding {
	return Binding{local.SenderBinding, local.Profile, local.DeviceID, local.CertificateHash}
}

type Attempt struct {
	Identity     windowshistoryrequest.Identity `json:"identity"`
	PolicyDigest string                         `json:"policyDigest"`
	GrantID      string                         `json:"grantId"`
	ExpiresAt    time.Time                      `json:"expiresAt"`
}

func AttemptFor(d windowshistoryrequest.Description, policy string) Attempt {
	return Attempt{d.Identity, policy, d.GrantID, d.ExpiresAt}
}

type Reports struct {
	SchemaVersion string  `json:"schemaVersion"`
	Binding       Binding `json:"binding"`
	Sequence      uint64  `json:"sequence,string"`
	Pending       []byte  `json:"pending"`
	Attempt       Attempt `json:"attempt"`
}
type Consumption struct {
	SchemaVersion string  `json:"schemaVersion"`
	Binding       Binding `json:"binding"`
	Attempt       Attempt `json:"attempt"`
}

func (Reports) Format(f fmt.State, _ rune)     { _, _ = f.Write([]byte("<event metadata state>")) }
func (Consumption) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("<event consumption state>")) }

func canonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return ErrState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrState
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrState
	}
	return nil
}
func validBinding(b Binding) bool {
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: b.SenderBinding, GrantID: "11111111111111111111111111111111", Profile: b.Profile, ContentAcknowledged: true, HistoryAcknowledged: true, HTTPPlaintextAcknowledged: b.Profile == "http-test"}
	_, e := windowshistorywire.CapabilityFor(c, windowshistoryrequest.LocalContext{SenderBinding: b.SenderBinding, Profile: b.Profile, DeviceID: b.DeviceID, CertificateHash: b.CertificateHash}, 1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	return e == nil
}
func validAttempt(a Attempt) bool {
	if a == (Attempt{}) {
		return true
	}
	_, e := windowshistorywire.EncodeClaim(windowshistorywire.Claim{Identity: a.Identity, PolicyDigest: a.PolicyDigest, DeviceID: "agent_11111111111111111111111111111111", CertificateHash: "1111111111111111111111111111111111111111111111111111111111111111", GrantID: a.GrantID, ExpiresAt: a.ExpiresAt})
	return e == nil
}
func NewReports(local windowshistoryrequest.LocalContext) (Reports, error) {
	b := Bound(local)
	if !validBinding(b) {
		return Reports{}, ErrState
	}
	return Reports{SchemaVersion: Version, Binding: b}, nil
}
func NewConsumption(local windowshistoryrequest.LocalContext) (Consumption, error) {
	b := Bound(local)
	if !validBinding(b) {
		return Consumption{}, ErrState
	}
	return Consumption{SchemaVersion: Version, Binding: b}, nil
}
func EncodeReports(r Reports) ([]byte, error) {
	if r.SchemaVersion != Version || !validBinding(r.Binding) || !validAttempt(r.Attempt) {
		return nil, ErrState
	}
	if len(r.Pending) > 0 {
		c, e := windowshistorywire.DecodeCapability(r.Pending)
		if e != nil || c.Sequence != r.Sequence || c.Consent.SenderBinding != r.Binding.SenderBinding || c.Consent.Profile != r.Binding.Profile || c.DeviceID != r.Binding.DeviceID || c.CertificateHash != r.Binding.CertificateHash {
			return nil, ErrState
		}
	}
	return json.Marshal(r)
}
func ReadReports(s Storage, local windowshistoryrequest.LocalContext) (Reports, error) {
	var r Reports
	if s == nil {
		return r, ErrState
	}
	raw, e := s.Read("reports.json")
	if e != nil || canonical(raw, &r) != nil || r.Binding != Bound(local) {
		return Reports{}, ErrState
	}
	if _, e = EncodeReports(r); e != nil {
		return Reports{}, ErrState
	}
	return r, nil
}
func EncodeConsumption(c Consumption) ([]byte, error) {
	if c.SchemaVersion != Version || !validBinding(c.Binding) || !validAttempt(c.Attempt) {
		return nil, ErrState
	}
	return json.Marshal(c)
}
func ReadConsumption(s Storage, local windowshistoryrequest.LocalContext) (Consumption, error) {
	var c Consumption
	if s == nil {
		return c, ErrState
	}
	raw, e := s.Read("consumed.json")
	if e != nil || canonical(raw, &c) != nil || c.Binding != Bound(local) {
		return Consumption{}, ErrState
	}
	if _, e = EncodeConsumption(c); e != nil {
		return Consumption{}, ErrState
	}
	return c, nil
}
func writeReports(s Storage, r Reports) error {
	raw, e := EncodeReports(r)
	if e != nil || s.Write("reports.json", raw) != nil {
		return ErrState
	}
	return nil
}

// StageCapability retains exact canonical metadata for a transport retry. A
// replaced consent or expired pending report consumes the old sequence and
// stages a strictly greater one. Disable/re-enable never resets either floor.
func StageCapability(s Storage, local windowshistoryrequest.LocalContext, c windowshistoryrequest.Consent, now time.Time) ([]byte, error) {
	r, e := ReadReports(s, local)
	if e != nil {
		return nil, e
	}
	if len(r.Pending) > 0 {
		old, e := windowshistorywire.DecodeCapability(r.Pending)
		if e != nil {
			return nil, ErrState
		}
		if old.Consent == c && windowshistorywire.CapabilityFresh(old, now) == nil {
			return bytes.Clone(r.Pending), nil
		}
	}
	if r.Sequence == ^uint64(0) {
		return nil, ErrState
	}
	cap, e := windowshistorywire.CapabilityFor(c, local, r.Sequence+1, now)
	if e != nil {
		return nil, ErrState
	}
	raw, e := windowshistorywire.EncodeCapability(cap)
	if e != nil {
		return nil, ErrState
	}
	r.Sequence++
	r.Pending = bytes.Clone(raw)
	if writeReports(s, r) != nil {
		return nil, ErrState
	}
	return raw, nil
}
func AcknowledgeCapability(s Storage, local windowshistoryrequest.LocalContext, raw []byte) error {
	r, e := ReadReports(s, local)
	if e != nil || len(r.Pending) == 0 || !bytes.Equal(r.Pending, raw) {
		return ErrState
	}
	r.Pending = nil
	return writeReports(s, r)
}

// BeginClaim is called by the parent before sending a claim. A lost response or
// crash can never be turned into another attempt, even if no child was started.
func BeginClaim(s Storage, local windowshistoryrequest.LocalContext, d windowshistoryrequest.Description, c windowshistoryrequest.Consent, policy string, now time.Time) error {
	r, e := ReadReports(s, local)
	if e != nil {
		return e
	}
	digest, e := windowshistoryrequest.Authorize(d, c, local, now)
	if e != nil || digest != policy {
		return ErrState
	}
	if d.Identity.Sequence <= r.Attempt.Identity.Sequence {
		return ErrConsumed
	}
	r.Attempt = AttemptFor(d, policy)
	return writeReports(s, r)
}
func VerifyAttempt(s Storage, local windowshistoryrequest.LocalContext, d windowshistoryrequest.Description, policy string) error {
	r, e := ReadReports(s, local)
	if e != nil || r.Attempt != AttemptFor(d, policy) {
		return ErrState
	}
	return nil
}

// Consume is called only by the isolated child, after independently validating
// identity/grant and the exact parent attempt. Its successful durable write must
// precede the first source API. Failures and replays never produce a permit.
func Consume(s Storage, local windowshistoryrequest.LocalContext, d windowshistoryrequest.Description, c windowshistoryrequest.Consent, policy string, now time.Time) error {
	r, e := ReadConsumption(s, local)
	if e != nil {
		return e
	}
	digest, e := windowshistoryrequest.Authorize(d, c, local, now)
	if e != nil || digest != policy {
		return ErrState
	}
	if d.Identity.Sequence <= r.Attempt.Identity.Sequence {
		return ErrConsumed
	}
	r.Attempt = AttemptFor(d, policy)
	raw, e := EncodeConsumption(r)
	if e != nil || s.Write("consumed.json", raw) != nil {
		return ErrState
	}
	return nil
}
