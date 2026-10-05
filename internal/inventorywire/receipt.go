package inventorywire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/fullinventory"
	"localrmm/internal/updategeneration"
	"strconv"
	"time"
)

const ReceiptVersion = "tracebolt.inventory-response.v1"
const MaxReceiptBytes = 4 << 10

// Receipt describes a strictly decoded response bound to one exact request.
// It does not authenticate a server: HTTP-test responses remain unauthenticated.
// Historical receipt times are retained, never replaced with delivery time.
type Receipt struct {
	Operation, GenerationID, ManifestHash, RequestSHA256                    string
	Sequence                                                                uint64
	StartedAt, ExpiresAt, ReceivedAt, CollectedAt, CompletedAt, AttemptedAt time.Time
	Ordinal                                                                 uint32
	Rows                                                                    uint64
	State, Reason                                                           string
	AcceptedChunks, ExpectedChunks                                          uint32
	AcceptedRows                                                            uint64
	Aborted                                                                 bool
}

// DecodeReceipt checks all required fields, their types and purpose, and the
// exact request digest. The caller additionally checks retained manifest facts
// (especially final collection time and status counts) before changing state.
func DecodeReceipt(raw []byte, operation string, exactRequestBody []byte) (Receipt, error) {
	return decodeReceipt(packageTransfer, raw, operation, exactRequestBody)
}
func decodeReceipt(kind transferKind, raw []byte, operation string, exactRequestBody []byte) (Receipt, error) {
	bad := func() (Receipt, error) { return Receipt{}, ErrContract }
	if len(raw) == 0 || len(raw) > MaxReceiptBytes {
		return bad()
	}
	m, e := decodeMessage(kind, operation, exactRequestBody)
	if e != nil {
		return bad()
	}
	f, e := object(raw, "schemaVersion", "operation", "sequence", "generationId", "manifestHash", "requestSha256", "result")
	if e != nil {
		return bad()
	}
	get := func(k string) (string, bool) { var s string; e := json.Unmarshal(f[k], &s); return s, e == nil }
	version, ok := get("schemaVersion")
	if !ok || version != kind.receiptVersion() {
		return bad()
	}
	op, ok := get("operation")
	if !ok || op != operation {
		return bad()
	}
	seq, ok := get("sequence")
	if !ok || seq != strconv.FormatUint(m.Sequence, 10) {
		return bad()
	}
	gen, ok := get("generationId")
	if !ok || gen != m.GenerationID {
		return bad()
	}
	hash, ok := get("manifestHash")
	if !ok || hash != m.ManifestHash {
		return bad()
	}
	digest, ok := get("requestSha256")
	sum := sha256.Sum256(exactRequestBody)
	if !ok || digest != hex.EncodeToString(sum[:]) {
		return bad()
	}
	maxChunks, maxChunkRows, maxRows := uint64(fullinventory.MaxGenerationChunks), uint64(fullinventory.MaxChunkRows), uint64(fullinventory.MaxGenerationRows)
	if kind == cachedUpdatesTransfer {
		maxChunks, maxChunkRows, maxRows = updategeneration.MaxGenerationChunks, updategeneration.MaxChunkRows, updategeneration.MaxGenerationRows
	}
	collectedAt, _, _, _ := m.ManifestFacts()
	ordinal, chunkRows, _ := m.ChunkFacts()
	r := Receipt{Operation: op, Sequence: m.Sequence, GenerationID: gen, ManifestHash: hash, RequestSHA256: digest}
	var fields map[string]json.RawMessage
	switch op {
	case "begin":
		fields, e = object(f["result"], "startedAt", "expiresAt")
	case "append":
		fields, e = object(f["result"], "ordinal", "rows", "receivedAt")
	case "finalize":
		fields, e = object(f["result"], "collectedAt", "completedAt")
	case "abort":
		fields, e = object(f["result"], "aborted")
	case "failure":
		fields, e = object(f["result"], "attemptedAt", "receivedAt", "reason")
	case "status":
		fields, e = object(f["result"], "state", "acceptedChunks", "expectedChunks", "acceptedRows", "startedAt", "expiresAt", "completedAt")
	}
	if e != nil {
		return bad()
	}
	timestamp := func(k string, allowEmpty bool) (time.Time, bool) {
		var s string
		if json.Unmarshal(fields[k], &s) != nil {
			return time.Time{}, false
		}
		if allowEmpty && s == "" {
			return time.Time{}, true
		}
		v, e := time.Parse(time.RFC3339Nano, s)
		return v, e == nil && !v.IsZero() && v.UTC().Format(time.RFC3339Nano) == s
	}
	integer := func(k string, max uint64) (uint64, bool) {
		var v uint64
		if json.Unmarshal(fields[k], &v) != nil || v > max {
			return 0, false
		}
		return v, string(fields[k]) == strconv.FormatUint(v, 10)
	}
	switch op {
	case "begin":
		r.StartedAt, ok = timestamp("startedAt", false)
		if !ok {
			return bad()
		}
		r.ExpiresAt, ok = timestamp("expiresAt", false)
		if !ok || r.ExpiresAt.Sub(r.StartedAt) != 15*time.Minute || r.StartedAt.Before(collectedAt) {
			return bad()
		}
	case "append":
		v, valid := integer("ordinal", maxChunks-1)
		if !valid || uint32(v) != ordinal {
			return bad()
		}
		r.Ordinal = uint32(v)
		r.Rows, ok = integer("rows", maxChunkRows)
		if !ok || r.Rows != chunkRows {
			return bad()
		}
		r.ReceivedAt, ok = timestamp("receivedAt", false)
		if !ok {
			return bad()
		}
	case "finalize":
		r.CollectedAt, ok = timestamp("collectedAt", false)
		if !ok {
			return bad()
		}
		r.CompletedAt, ok = timestamp("completedAt", false)
		if !ok || r.CompletedAt.Before(r.CollectedAt) {
			return bad()
		}
	case "abort":
		if json.Unmarshal(fields["aborted"], &r.Aborted) != nil || !r.Aborted {
			return bad()
		}
	case "failure":
		r.AttemptedAt, ok = timestamp("attemptedAt", false)
		if !ok || !r.AttemptedAt.Equal(m.FailureAt) {
			return bad()
		}
		r.ReceivedAt, ok = timestamp("receivedAt", false)
		if !ok || r.ReceivedAt.Before(r.AttemptedAt) {
			return bad()
		}
		if json.Unmarshal(fields["reason"], &r.Reason) != nil || r.Reason != m.FailureReason {
			return bad()
		}
	case "status":
		if json.Unmarshal(fields["state"], &r.State) != nil {
			return bad()
		}
		switch r.State {
		case "pending", "complete", "expired", "failed":
		default:
			return bad()
		}
		v, valid := integer("acceptedChunks", maxChunks)
		if !valid {
			return bad()
		}
		r.AcceptedChunks = uint32(v)
		v, valid = integer("expectedChunks", maxChunks)
		if !valid {
			return bad()
		}
		r.ExpectedChunks = uint32(v)
		r.AcceptedRows, ok = integer("acceptedRows", maxRows)
		if !ok || r.AcceptedChunks > r.ExpectedChunks {
			return bad()
		}
		r.StartedAt, ok = timestamp("startedAt", false)
		if !ok {
			return bad()
		}
		r.ExpiresAt, ok = timestamp("expiresAt", false)
		if !ok {
			return bad()
		}
		r.CompletedAt, ok = timestamp("completedAt", true)
		if !ok || !r.CompletedAt.IsZero() && r.CompletedAt.Before(r.StartedAt) {
			return bad()
		}
		if r.State == "pending" && r.ExpiresAt.Sub(r.StartedAt) != 15*time.Minute {
			return bad()
		}
		if r.State == "complete" && (r.CompletedAt.IsZero() || r.AcceptedChunks != r.ExpectedChunks) || r.State == "pending" && !r.CompletedAt.IsZero() {
			return bad()
		}
	}
	return r, nil
}
