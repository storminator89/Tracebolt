// Package journalactivation reads the local administrator's fixed activation
// gate. It never grants access, creates state, or performs collection.
package journalactivation

import (
	"bytes"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalgeneration"
)

const Version = "tracebolt.journal-activation.v1"
const Path = "/etc/tracebolt/journal-activation.json"
const TempName = ".journal-activation.tmp"
const MaxBytes = 4096

var ErrInvalid = errors.New("journal_activation_invalid")

type Record struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	Phase            string                  `json:"phase"`
	SenderBinding    string                  `json:"senderBinding"`
	DeviceID         string                  `json:"deviceId"`
	CertificateHash  string                  `json:"certificateHash"`
	PolicyGeneration journalgeneration.Tuple `json:"policyGeneration"`
}

func Validate(r Record) error {
	if r.SchemaVersion != Version || r.Phase != "pending" && r.Phase != "committed" || !enrollmentcrypto.ValidHash(r.SenderBinding) || !enrollmentcrypto.ValidID(r.DeviceID, "agent_") || !enrollmentcrypto.ValidHash(r.CertificateHash) || journalgeneration.Validate(r.PolicyGeneration) != nil {
		return ErrInvalid
	}
	return nil
}
func Encode(r Record) ([]byte, error) {
	if Validate(r) != nil {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func Decode(raw []byte) (Record, error) {
	var r Record
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal(raw, &r) != nil {
		return Record{}, ErrInvalid
	}
	b, e := Encode(r)
	if e != nil || !bytes.Equal(raw, b) {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func Matches(r Record, binding, device, leaf string, g journalgeneration.Tuple) bool {
	return Validate(r) == nil && r.Phase == "committed" && r.SenderBinding == binding && r.DeviceID == device && r.CertificateHash == leaf && r.PolicyGeneration == g
}

// Gate admits legacy absence only for ordinary reads. Administrative acceptance
// must see the explicit pending phase, never an already committed record.
func Gate(r Record, present, pending bool) bool {
	if !present {
		return !pending
	}
	if Validate(r) != nil {
		return false
	}
	if pending {
		return r.Phase == "pending"
	}
	return r.Phase == "committed"
}
