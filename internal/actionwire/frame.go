// Package actionwire is the strict purpose-separated service-action transport.
// It does not grant actions, sign manager permits, retain state or run a helper.
package actionwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
)

const MaxBodyBytes = 16 << 10
const MaxCapabilitiesBytesV2 = actionhelper.MaxCapabilitiesBytesV2
const CapabilitiesPathV2 = "/v4/service-actions/capabilities"

var ErrContract = errors.New("action_wire_invalid")

func validPath(path string) bool {
	return path == CapabilitiesPathV2 || path == CapabilitiesPath || path == PeekPath || path == ClaimPath || path == ResultPath
}
func BodyLimit(path string) int64 {
	if path == CapabilitiesPathV2 {
		return MaxCapabilitiesBytesV2
	}
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
func EncodeCapabilities(c actionhelper.Capabilities) ([]byte, error) {
	if c.Version != actionhelper.CapabilitiesVersion || actionhelper.ValidateCapabilities(c) != nil {
		return nil, ErrContract
	}
	return encode(c)
}
func DecodeCapabilities(raw []byte) (actionhelper.Capabilities, error) {
	var c actionhelper.Capabilities
	if decode(raw, &c) != nil || c.Version != actionhelper.CapabilitiesVersion || actionhelper.ValidateCapabilities(c) != nil {
		return c, ErrContract
	}
	return c, nil
}
func EncodeClaim(i actionjob.Identity) ([]byte, error) {
	if !actionjob.ValidIdentity(i) {
		return nil, ErrContract
	}
	return encode(i)
}
func DecodeClaim(raw []byte) (actionjob.Identity, error) {
	var i actionjob.Identity
	if decode(raw, &i) != nil || !actionjob.ValidIdentity(i) {
		return i, ErrContract
	}
	return i, nil
}
func validDelivery(d actionjob.Delivery) bool {
	return actionjob.ValidIdentity(d.Identity) && (d.State == actionjob.Approved || d.State == actionjob.Claimed) && actionjob.ValidTime(d.StartDeadline)
}
func EncodeDelivery(d actionjob.Delivery) ([]byte, error) {
	if !validDelivery(d) {
		return nil, ErrContract
	}
	return encode(d)
}
func DecodeDelivery(raw []byte) (actionjob.Delivery, error) {
	var d actionjob.Delivery
	if decode(raw, &d) != nil || !validDelivery(d) {
		return d, ErrContract
	}
	return d, nil
}
func validGrant(g actionjob.Grant) bool {
	p, e := actionpermit.Decode(g.Envelope)
	return e == nil && actionjob.ValidIdentity(g.Identity) && p.JobID == g.Identity.JobID && p.Sequence == g.Identity.Sequence && actionpermit.Digest(g.Envelope) == g.Identity.EnvelopeDigest
}
func EncodeGrant(g actionjob.Grant) ([]byte, error) {
	if !validGrant(g) {
		return nil, ErrContract
	}
	return encode(g)
}
func DecodeGrant(raw []byte) (actionjob.Grant, error) {
	var g actionjob.Grant
	if decode(raw, &g) != nil || !validGrant(g) {
		return g, ErrContract
	}
	return g, nil
}
func EncodeResult(r actionhelper.Result) ([]byte, error) {
	if actionhelper.ValidateResult(r) != nil {
		return nil, ErrContract
	}
	return encode(r)
}
func DecodeResult(raw []byte) (actionhelper.Result, error) {
	var r actionhelper.Result
	if decode(raw, &r) != nil || actionhelper.ValidateResult(r) != nil {
		return r, ErrContract
	}
	return r, nil
}

// Capability freshness uses the original helper timestamp, never HTTP SignedAt.
func CheckCapabilityTime(c actionhelper.Capabilities, now time.Time) error {
	if actionhelper.ValidateCapabilities(c) != nil || !actionjob.ValidTime(now) || c.CapturedAt > now.Unix()+5 || now.Unix()-c.CapturedAt >= 60 {
		return ErrContract
	}
	return nil
}

// V2 uses an explicitly separate endpoint and byte budget; v1 codecs stay exact.
func EncodeCapabilitiesV2(c actionhelper.Capabilities) ([]byte, error) {
	if c.Version != actionhelper.CapabilitiesVersionV2 || actionhelper.ValidateCapabilities(c) != nil {
		return nil, ErrContract
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > MaxCapabilitiesBytesV2 {
		return nil, ErrContract
	}
	return raw, nil
}
func DecodeCapabilitiesV2(raw []byte) (actionhelper.Capabilities, error) {
	var c actionhelper.Capabilities
	if len(raw) == 0 || len(raw) > MaxCapabilitiesBytesV2 || !utf8.Valid(raw) || json.Unmarshal(raw, &c) != nil {
		return c, ErrContract
	}
	b, e := EncodeCapabilitiesV2(c)
	if e != nil || !bytes.Equal(raw, b) {
		return c, ErrContract
	}
	return c, nil
}
