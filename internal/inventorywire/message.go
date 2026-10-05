package inventorywire

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/fullinventory"
	"localrmm/internal/updategeneration"
	"strconv"
	"time"
	"unicode/utf8"
)

const MessageVersion = "tracebolt.inventory-request.v1"

type Message struct {
	Operation                  string
	Sequence                   uint64
	GenerationID, ManifestHash string
	Manifest                   *fullinventory.Manifest
	Chunk                      *fullinventory.Chunk
	UpdateManifest             *updategeneration.Manifest
	UpdateChunk                *updategeneration.Chunk
	FailureAt                  time.Time
	FailureReason              string
}
type wireMessage struct {
	SchemaVersion string          `json:"schemaVersion"`
	Sequence      string          `json:"sequence"`
	GenerationID  string          `json:"generationId"`
	ManifestHash  string          `json:"manifestHash"`
	Payload       json.RawMessage `json:"payload"`
}

func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return nil, ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, ErrContract
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] || out[k] != nil {
			return nil, ErrContract
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrContract
		}
		out[k] = value
	}
	if _, e = d.Token(); e != nil {
		return nil, ErrContract
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrContract
	}
	if len(out) != len(keys) {
		return nil, ErrContract
	}
	return out, nil
}
func DecodeMessage(operation string, raw []byte) (Message, error) {
	return decodeMessage(packageTransfer, operation, raw)
}
func decodeMessage(kind transferKind, operation string, raw []byte) (Message, error) {
	bad := func() (Message, error) { return Message{}, ErrContract }
	if !ValidOperation(operation) || len(raw) == 0 || len(raw) > MaxBodyBytes {
		return bad()
	}
	fields, e := object(raw, "schemaVersion", "sequence", "generationId", "manifestHash", "payload")
	if e != nil {
		return bad()
	}
	var wire wireMessage
	if json.Unmarshal(fields["schemaVersion"], &wire.SchemaVersion) != nil || json.Unmarshal(fields["sequence"], &wire.Sequence) != nil || json.Unmarshal(fields["generationId"], &wire.GenerationID) != nil || json.Unmarshal(fields["manifestHash"], &wire.ManifestHash) != nil {
		return bad()
	}
	if wire.SchemaVersion != kind.messageVersion() || !enrollmentcrypto.ValidID(wire.GenerationID, "sample_") {
		return bad()
	}
	sequence, ok := canonicalSequence(wire.Sequence)
	if !ok {
		return bad()
	}
	if operation == "failure" {
		if wire.ManifestHash != "" {
			return bad()
		}
	} else if !enrollmentcrypto.ValidHash(wire.ManifestHash) {
		return bad()
	}
	out := Message{Operation: operation, Sequence: sequence, GenerationID: wire.GenerationID, ManifestHash: wire.ManifestHash}
	payload := fields["payload"]
	switch operation {
	case "begin":
		if kind == cachedUpdatesTransfer {
			m, e := updategeneration.DecodeManifest(payload)
			if e != nil || m.GenerationID != out.GenerationID {
				return bad()
			}
			hash, e := updategeneration.ManifestDigest(m)
			if e != nil || hash != out.ManifestHash {
				return bad()
			}
			out.UpdateManifest = &m
			break
		}
		m, e := fullinventory.DecodeManifest(payload)
		if e != nil || m.GenerationID != out.GenerationID {
			return bad()
		}
		hash, e := fullinventory.ManifestDigest(m)
		if e != nil || hash != out.ManifestHash {
			return bad()
		}
		out.Manifest = &m
	case "append":
		if kind == cachedUpdatesTransfer {
			c, e := updategeneration.DecodeChunk(payload)
			if e != nil || c.GenerationID != out.GenerationID || c.ManifestSHA256 != out.ManifestHash {
				return bad()
			}
			out.UpdateChunk = &c
			break
		}
		c, e := fullinventory.DecodeChunk(payload)
		if e != nil || c.GenerationID != out.GenerationID || c.ManifestSHA256 != out.ManifestHash {
			return bad()
		}
		out.Chunk = &c
	case "failure":
		f, e := object(payload, "attemptedAt", "reason")
		if e != nil {
			return bad()
		}
		var at string
		if json.Unmarshal(f["attemptedAt"], &at) != nil || json.Unmarshal(f["reason"], &out.FailureReason) != nil {
			return bad()
		}
		out.FailureAt, e = time.Parse(time.RFC3339Nano, at)
		if e != nil || out.FailureAt.IsZero() || out.FailureAt.UTC().Format(time.RFC3339Nano) != at {
			return bad()
		}
		switch out.FailureReason {
		case "source_missing", "source_invalid", "source_changed", "resource_limit", "collection_failed":
		case "not_supported":
			if kind != cachedUpdatesTransfer {
				return bad()
			}
		default:
			return bad()
		}
	default:
		if _, e := object(payload); e != nil {
			return bad()
		}
	}
	return out, nil
}
func EncodeMessage(operation string, sequence uint64, generation, manifestHash string, payload any) ([]byte, error) {
	return encodeMessage(packageTransfer, operation, sequence, generation, manifestHash, payload)
}
func encodeMessage(kind transferKind, operation string, sequence uint64, generation, manifestHash string, payload any) ([]byte, error) {
	data, e := json.Marshal(payload)
	if e != nil {
		return nil, ErrContract
	}
	raw, e := json.Marshal(wireMessage{kind.messageVersion(), strconv.FormatUint(sequence, 10), generation, manifestHash, data})
	if e != nil {
		return nil, ErrContract
	}
	if _, e = decodeMessage(kind, operation, raw); e != nil {
		return nil, e
	}
	return raw, nil
}
