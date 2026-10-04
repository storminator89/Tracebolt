// Package systemwire defines the bounded, profile3 service/socket transport.
// It never collects, persists, authorizes or authenticates server responses.
package systemwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/systeminventory"
	"strconv"
	"time"
)

const FrameVersion = "tracebolt.agent-system-inventory.v1"
const EndpointFrameVersion = "tracebolt.agent-system-inventory.v2"
const ReceiptVersion = "tracebolt.system-inventory-receipt.v1"
const MaxBodyBytes = systeminventory.MaxSnapshotBytes + 4096
const MaxReceiptBytes = 4096

type Frame struct {
	SchemaVersion    string                     `json:"schemaVersion"`
	Sequence         uint64                     `json:"sequence,string"`
	Snapshot         systeminventory.Snapshot   `json:"snapshot"`
	EndpointIdentity *endpointidentity.Snapshot `json:"endpointIdentity,omitempty"`
	ConsentScope     string                     `json:"consentScope,omitempty"`
}
type Receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	DeviceID      string    `json:"deviceId"`
	Sequence      uint64    `json:"sequence,string"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	BodyHash      string    `json:"bodyHash"`
}

func Decode(raw []byte) (Frame, error) {
	bad := func() (Frame, error) { return Frame{}, ErrContract }
	if len(raw) == 0 || len(raw) > MaxBodyBytes {
		return bad()
	}
	fields, e := object(raw, "schemaVersion", "sequence", "snapshot")
	extended := false
	if e != nil {
		fields, e = object(raw, "schemaVersion", "sequence", "snapshot", "endpointIdentity", "consentScope")
		extended = true
	}
	if e != nil {
		return bad()
	}
	var version, seq string
	if json.Unmarshal(fields["schemaVersion"], &version) != nil || (version != FrameVersion && !extended || version != EndpointFrameVersion && extended) || json.Unmarshal(fields["sequence"], &seq) != nil {
		return bad()
	}
	sequence, ok := canonicalSequence(seq)
	if !ok {
		return bad()
	}
	snapshot, e := systeminventory.DecodeStrict(fields["snapshot"])
	if e != nil {
		return bad()
	}
	out := Frame{SchemaVersion: version, Sequence: sequence, Snapshot: snapshot}
	if extended {
		var scope string
		if json.Unmarshal(fields["consentScope"], &scope) != nil || scope != endpointidentity.Scope {
			return bad()
		}
		identity, err := endpointidentity.DecodeStrict(fields["endpointIdentity"])
		if err != nil || identity.GenerationID != snapshot.GenerationID || !identity.CollectedAt.Equal(snapshot.CollectedAt) {
			return bad()
		}
		out.EndpointIdentity = &identity
		out.ConsentScope = scope
	}
	return out, nil
}
func Encode(sequence uint64, snapshot systeminventory.Snapshot) ([]byte, error) {
	if systeminventory.Validate(snapshot) != nil {
		return nil, ErrContract
	}
	raw, e := json.Marshal(Frame{SchemaVersion: FrameVersion, Sequence: sequence, Snapshot: snapshot})
	if e != nil {
		return nil, ErrContract
	}
	if _, e = Decode(raw); e != nil {
		return nil, e
	}
	return raw, nil
}

// DecodeReceipt checks strict structure and exact originating request. TLS
// authentication is the caller's responsibility; HTTP-test remains plaintext.
func DecodeReceipt(raw []byte, deviceID string, request []byte) (Receipt, error) {
	bad := func() (Receipt, error) { return Receipt{}, ErrContract }
	if len(raw) == 0 || len(raw) > MaxReceiptBytes || !enrollmentcrypto.ValidID(deviceID, "agent_") {
		return bad()
	}
	frame, e := Decode(request)
	if e != nil {
		return bad()
	}
	fields, e := object(raw, "schemaVersion", "deviceId", "sequence", "generationId", "collectedAt", "receivedAt", "bodyHash")
	if e != nil {
		return bad()
	}
	var out Receipt
	read := func(k string) (string, bool) { var v string; e := json.Unmarshal(fields[k], &v); return v, e == nil }
	version, ok := read("schemaVersion")
	if !ok || version != ReceiptVersion {
		return bad()
	}
	out.SchemaVersion = version
	id, ok := read("deviceId")
	if !ok || id != deviceID {
		return bad()
	}
	out.DeviceID = id
	seq, ok := read("sequence")
	if !ok || seq != strconv.FormatUint(frame.Sequence, 10) {
		return bad()
	}
	out.Sequence = frame.Sequence
	generation, ok := read("generationId")
	expected, e := GenerationID(deviceID, frame.Sequence)
	if !ok || e != nil || generation != frame.Snapshot.GenerationID || generation != expected {
		return bad()
	}
	out.GenerationID = generation
	hash, ok := read("bodyHash")
	sum := sha256.Sum256(request)
	if !ok || hash != hex.EncodeToString(sum[:]) {
		return bad()
	}
	out.BodyHash = hash
	at, ok := read("collectedAt")
	if !ok {
		return bad()
	}
	out.CollectedAt, e = time.Parse(time.RFC3339Nano, at)
	if e != nil || out.CollectedAt.UTC().Format(time.RFC3339Nano) != at || !out.CollectedAt.Equal(frame.Snapshot.CollectedAt) {
		return bad()
	}
	at, ok = read("receivedAt")
	if !ok {
		return bad()
	}
	out.ReceivedAt, e = time.Parse(time.RFC3339Nano, at)
	if e != nil || out.ReceivedAt.IsZero() || out.ReceivedAt.UTC().Format(time.RFC3339Nano) != at || out.ReceivedAt.Before(out.CollectedAt) {
		return bad()
	}
	return out, nil
}

// EncodeEndpoint adds only the explicitly acknowledged endpoint scope. It keeps
// the existing total body ceiling, sequence and exact-byte receipt domain.
func EncodeEndpoint(sequence uint64, snapshot systeminventory.Snapshot, identity endpointidentity.Snapshot) ([]byte, error) {
	if systeminventory.Validate(snapshot) != nil || endpointidentity.Validate(identity) != nil {
		return nil, ErrContract
	}
	raw, e := json.Marshal(Frame{SchemaVersion: EndpointFrameVersion, Sequence: sequence, Snapshot: snapshot, EndpointIdentity: &identity, ConsentScope: endpointidentity.Scope})
	if e != nil {
		return nil, ErrContract
	}
	if _, e = Decode(raw); e != nil {
		return nil, e
	}
	return raw, nil
}
