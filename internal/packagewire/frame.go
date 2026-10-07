// Package packagewire is a separate bounded native package transport. It never
// widens the service wire/permit limits or authenticates native observations alone.
package packagewire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"unicode/utf8"
)

const MaxBodyBytes = 1 << 20

var ErrContract = errors.New("package_wire_invalid")

type Identity struct {
	JobID          string `json:"jobId"`
	Sequence       uint64 `json:"sequence,string"`
	Kind           string `json:"kind"`
	EnvelopeDigest string `json:"envelopeDigest"`
}
type Delivery struct {
	Identity      Identity `json:"identity"`
	State         string   `json:"state"`
	StartDeadline int64    `json:"startDeadline"`
}
type Grant struct {
	Identity Identity `json:"identity"`
	Envelope []byte   `json:"envelope"`
}

func validPath(p string) bool {
	return p == CapabilitiesPath || p == PeekPath || p == ClaimPath || p == ResultPath
}
func BodyLimit(p string) int64 {
	if p == ResultPath {
		return MaxBodyBytes
	}
	return 16384
}
func ValidIdentity(i Identity) bool {
	return enrollmentcrypto.ValidID(i.JobID, "update_") && i.Sequence > 0 && (i.Kind == packagepermit.Prepare || i.Kind == packagepermit.Execute) && actionpermit.ValidDigest(i.EnvelopeDigest)
}
func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > MaxBodyBytes || !utf8.Valid(raw) || json.Unmarshal(raw, out) != nil {
		return ErrContract
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(canonical, raw) {
		return ErrContract
	}
	return nil
}
func encode(v any) ([]byte, error) {
	b, e := json.Marshal(v)
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
func EncodeCapabilities(c packagehelper.Capabilities) ([]byte, error) {
	if packagehelper.ValidateCapabilities(c) != nil {
		return nil, ErrContract
	}
	return encode(c)
}
func DecodeCapabilities(raw []byte) (c packagehelper.Capabilities, e error) {
	e = decode(raw, &c)
	if e == nil {
		e = packagehelper.ValidateCapabilities(c)
	}
	return
}
func EncodeClaim(i Identity) ([]byte, error) {
	if !ValidIdentity(i) {
		return nil, ErrContract
	}
	return encode(i)
}
func DecodeClaim(raw []byte) (i Identity, e error) {
	e = decode(raw, &i)
	if e == nil && !ValidIdentity(i) {
		e = ErrContract
	}
	return
}
func EncodeDelivery(d Delivery) ([]byte, error) {
	if !ValidIdentity(d.Identity) || (d.State != "pending" && d.State != "claimed") || d.StartDeadline <= 0 {
		return nil, ErrContract
	}
	return encode(d)
}
func DecodeDelivery(raw []byte) (d Delivery, e error) {
	e = decode(raw, &d)
	if e == nil {
		_, e = EncodeDelivery(d)
	}
	return
}
func EncodeGrant(g Grant) ([]byte, error) {
	p, _, e := packagepermit.Decode(context.Background(), g.Envelope)
	if e != nil || !ValidIdentity(g.Identity) || p.JobID != g.Identity.JobID || p.Sequence != g.Identity.Sequence || p.Action != g.Identity.Kind || actionpermit.Digest(g.Envelope) != g.Identity.EnvelopeDigest {
		return nil, ErrContract
	}
	return encode(g)
}
func DecodeGrant(raw []byte) (g Grant, e error) {
	e = decode(raw, &g)
	if e == nil {
		_, e = EncodeGrant(g)
	}
	return
}
func EncodeResult(s packagehelper.Snapshot) ([]byte, error) {
	if packagehelper.ValidateSnapshot(s) != nil {
		return nil, ErrContract
	}
	return encode(s)
}
func DecodeResult(raw []byte) (s packagehelper.Snapshot, e error) {
	e = decode(raw, &s)
	if e == nil {
		e = packagehelper.ValidateSnapshot(s)
	}
	return
}
