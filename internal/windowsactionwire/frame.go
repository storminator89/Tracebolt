// Package actionwire is the strict purpose-separated service-action transport.
// It does not grant actions, sign manager permits, retain state or run a helper.
package windowsactionwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
)

const MaxBodyBytes = 16 << 10

var ErrContract = errors.New("action_wire_invalid")

func validPath(path string) bool {
	return path == CapabilitiesPath || path == PeekPath || path == ClaimPath || path == ResultPath
}
func BodyLimit(path string) int64 {
	if path == CapabilitiesPath {
		return MaxBodyBytes
	}
	return 8192
}
func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxBodyBytes || !utf8.Valid(raw) || json.Unmarshal(raw, out) != nil {
		return ErrContract
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrContract
	}
	return nil
}
func encode(value any) ([]byte, error) {
	b, e := json.Marshal(value)
	if e != nil || len(b) > MaxBodyBytes {
		return nil, ErrContract
	}
	return b, nil
}
func EncodePeek() ([]byte, error) { return []byte("{}"), nil }
func DecodePeek(raw []byte) error {
	if !bytes.Equal(raw, []byte("{}")) {
		return ErrContract
	}
	return nil
}
func EncodeCapabilities(c windowsaction.Capabilities) ([]byte, error) {
	if c.Version != windowsaction.CapabilitiesVersion || windowsaction.ValidateCapabilities(c) != nil {
		return nil, ErrContract
	}
	return encode(c)
}
func DecodeCapabilities(raw []byte) (windowsaction.Capabilities, error) {
	var c windowsaction.Capabilities
	if decode(raw, &c) != nil || c.Version != windowsaction.CapabilitiesVersion || windowsaction.ValidateCapabilities(c) != nil {
		return c, ErrContract
	}
	return c, nil
}
func EncodeClaim(i windowsaction.Identity) ([]byte, error) {
	if !windowsaction.ValidIdentity(i) {
		return nil, ErrContract
	}
	return encode(i)
}
func DecodeClaim(raw []byte) (windowsaction.Identity, error) {
	var i windowsaction.Identity
	if decode(raw, &i) != nil || !windowsaction.ValidIdentity(i) {
		return i, ErrContract
	}
	return i, nil
}
func validDelivery(d windowsactionjob.Delivery) bool {
	return windowsaction.ValidIdentity(d.Identity) && (d.State == "approved" || d.State == "claimed" || d.State == "needs_intervention") && (!d.StartDeadline.IsZero() && d.StartDeadline.Location() == time.UTC)
}
func EncodeDelivery(d windowsactionjob.Delivery) ([]byte, error) {
	if !validDelivery(d) {
		return nil, ErrContract
	}
	return encode(d)
}
func DecodeDelivery(raw []byte) (windowsactionjob.Delivery, error) {
	var d windowsactionjob.Delivery
	if decode(raw, &d) != nil || !validDelivery(d) {
		return d, ErrContract
	}
	return d, nil
}
func validGrant(g windowsactionjob.Grant) bool {
	p, e := windowsaction.Decode(g.Envelope)
	return e == nil && windowsaction.ValidIdentity(g.Identity) && p.JobID == g.Identity.JobID && p.Sequence == g.Identity.Sequence && windowsaction.Digest(g.Envelope) == g.Identity.EnvelopeDigest
}
func EncodeGrant(g windowsactionjob.Grant) ([]byte, error) {
	if !validGrant(g) {
		return nil, ErrContract
	}
	return encode(g)
}
func DecodeGrant(raw []byte) (windowsactionjob.Grant, error) {
	var g windowsactionjob.Grant
	if decode(raw, &g) != nil || !validGrant(g) {
		return g, ErrContract
	}
	return g, nil
}
func EncodeResult(r windowsaction.Result) ([]byte, error) {
	if windowsaction.ValidateResult(r) != nil {
		return nil, ErrContract
	}
	return encode(r)
}
func DecodeResult(raw []byte) (windowsaction.Result, error) {
	var r windowsaction.Result
	if decode(raw, &r) != nil || windowsaction.ValidateResult(r) != nil {
		return r, ErrContract
	}
	return r, nil
}

// Capability freshness uses the original helper timestamp, never HTTP SignedAt.
func CheckCapabilityTime(c windowsaction.Capabilities, now time.Time) error {
	if windowsaction.ValidateCapabilities(c) != nil || now.IsZero() || c.CapturedAt > now.Unix()+5 || now.Unix()-c.CapturedAt >= 60 {
		return ErrContract
	}
	return nil
}
