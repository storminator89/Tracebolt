// Package journalwire is the purpose-separated, bounded journal transport. It
// neither authorizes collection nor retains journal content.
package journalwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"time"
	"unicode/utf8"
)

const MaxBodyBytes = journalview.MaxSnapshotBytes + 4096

var ErrContract = errors.New("journal_wire_invalid")

type Result struct {
	Claim    journalrequest.Claim `json:"claim"`
	Snapshot journalview.Snapshot `json:"snapshot"`
}
type StatusInput struct {
	Identity    journalrequest.Identity `json:"identity"`
	LocalStatus string                  `json:"localStatus"`
}

func (Result) String() string               { return "journalwire.Result{content redacted}" }
func (r Result) GoString() string           { return r.String() }
func (r Result) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }
func validPath(path string) bool {
	return path == PeekPath || path == ClaimPath || path == ResultPath || path == StatusPath || path == GenerationPath
}
func BodyLimit(path string) int64 {
	if path == ResultPath {
		return MaxBodyBytes
	}
	return 4096
}
func ValidIdentity(i journalrequest.Identity) bool {
	return enrollmentcrypto.ValidID(i.ID, "journal_") && i.Sequence > 0 && journalrequest.ValidDigest(i.QueryDigest)
}
func ValidLocalStatus(s string) bool {
	switch s {
	case "", "checking", "disabled", "denied", "helper_unavailable", "result_lost":
		return true
	}
	return false
}

// Canonical JSON is required at this private agent protocol seam. Re-encoding
// rejects duplicate, missing, unknown, case-folded keys, noncanonical numbers,
// trailing objects and nulls without printing body-derived diagnostics.
func decode(raw []byte, max int, out any) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrContract
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrContract
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrContract
	}
	return nil
}
func encode(v any, max int) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > max {
		return nil, ErrContract
	}
	return b, nil
}
func EncodePeek() ([]byte, error) { return []byte("{}"), nil }
func DecodePeek(b []byte) error {
	if !bytes.Equal(b, []byte("{}")) {
		return ErrContract
	}
	return nil
}
func EncodeClaim(c journalrequest.Claim) ([]byte, error) {
	if !ValidIdentity(c.Identity) || !journalrequest.ValidDigest(c.PolicyDigest) {
		return nil, ErrContract
	}
	return encode(c, 4096)
}
func DecodeClaim(b []byte) (journalrequest.Claim, error) {
	var v journalrequest.Claim
	e := decode(b, 4096, &v)
	if e == nil {
		_, e = EncodeClaim(v)
	}
	if e != nil {
		return journalrequest.Claim{}, ErrContract
	}
	return v, nil
}
func EncodeResult(v Result) ([]byte, error) {
	if _, e := EncodeClaim(v.Claim); e != nil {
		return nil, e
	}
	if _, e := journalview.Encode(v.Snapshot); e != nil {
		return nil, ErrContract
	}
	return encode(v, MaxBodyBytes)
}
func DecodeResult(b []byte) (Result, error) {
	var v Result
	e := decode(b, MaxBodyBytes, &v)
	if e == nil {
		_, e = EncodeResult(v)
	}
	if e != nil {
		return Result{}, ErrContract
	}
	return v, nil
}
func EncodeStatus(v StatusInput) ([]byte, error) {
	if !ValidIdentity(v.Identity) || !ValidLocalStatus(v.LocalStatus) {
		return nil, ErrContract
	}
	return encode(v, 4096)
}
func DecodeStatusInput(b []byte) (StatusInput, error) {
	var v StatusInput
	e := decode(b, 4096, &v)
	if e == nil {
		_, e = EncodeStatus(v)
	}
	if e != nil {
		return StatusInput{}, ErrContract
	}
	return v, nil
}
func DecodeDescription(b []byte) (journalrequest.Description, error) {
	var v journalrequest.Description
	e := decode(b, 4096, &v)
	if e == nil {
		e = journalrequest.Validate(journalrequest.Record{Description: v, State: journalrequest.Pending})
	}
	if e != nil {
		return journalrequest.Description{}, ErrContract
	}
	return v, nil
}
func DecodeGrant(b []byte) (journalrequest.Grant, error) {
	var v journalrequest.Grant
	e := decode(b, 4096, &v)
	if e == nil {
		e = journalrequest.Validate(journalrequest.Record{Description: v.Description, State: journalrequest.Claimed, PolicyDigest: v.PolicyDigest, ClaimedAt: &v.ClaimedAt})
	}
	if e != nil {
		return journalrequest.Grant{}, ErrContract
	}
	return v, nil
}
func DecodeReceipt(b []byte) (journalrequest.Receipt, error) {
	var v journalrequest.Receipt
	e := decode(b, 4096, &v)
	if e != nil || !ValidIdentity(v.Identity) || !journalrequest.ValidDigest(v.PolicyDigest) || !journalrequest.ValidDigest(v.ResultDigest) || v.AcceptedAt.Location() != time.UTC || !v.AcceptedAt.Before(v.ExpiresAt) {
		return journalrequest.Receipt{}, ErrContract
	}
	return v, nil
}
func DecodeStatus(b []byte) (journalrequest.Status, error) {
	var v journalrequest.Status
	e := decode(b, 4096, &v)
	if e != nil {
		return journalrequest.Status{}, ErrContract
	}
	if _, e = validateDescription(v.Description); e != nil {
		return journalrequest.Status{}, ErrContract
	}
	switch v.State {
	case journalrequest.Pending, journalrequest.Claimed, journalrequest.Accepted, journalrequest.Canceled, journalrequest.Expired:
	default:
		return journalrequest.Status{}, ErrContract
	}
	if v.ContentStatus != "unavailable" && v.ContentStatus != "available" {
		return journalrequest.Status{}, ErrContract
	}
	if v.State == journalrequest.Accepted {
		if v.Receipt == nil || v.Receipt.Identity != v.Description.Identity || !v.Receipt.ExpiresAt.Equal(v.Description.ExpiresAt) {
			return journalrequest.Status{}, ErrContract
		}
		b, _ := json.Marshal(v.Receipt)
		if _, e = DecodeReceipt(b); e != nil {
			return journalrequest.Status{}, ErrContract
		}
	} else if v.Receipt != nil {
		return journalrequest.Status{}, ErrContract
	}
	return v, nil
}
func validateDescription(v journalrequest.Description) (journalrequest.Description, error) {
	if journalrequest.Validate(journalrequest.Record{Description: v, State: journalrequest.Pending}) != nil {
		return journalrequest.Description{}, ErrContract
	}
	return v, nil
}

func (Verified) String() string               { return "journalwire.Verified{content redacted}" }
func (v Verified) GoString() string           { return v.String() }
func (v Verified) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }

// Generation reports are public metadata only, with an independent monotonic
// sequence. They do not grant permission to read any service or journal source.
func EncodeGenerationReport(r journalgeneration.Report) ([]byte, error) {
	b, err := journalgeneration.EncodeReport(r)
	if err != nil {
		return nil, ErrContract
	}
	return b, nil
}
func DecodeGenerationReport(b []byte) (journalgeneration.Report, error) {
	r, err := journalgeneration.DecodeReport(b)
	if err != nil {
		return journalgeneration.Report{}, ErrContract
	}
	return r, nil
}
