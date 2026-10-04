package inventorystate

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/inventorywire"
	"time"
)

type diskRecord struct {
	Version      int      `json:"version"`
	Binding      string   `json:"binding"`
	AgentID      string   `json:"agentId"`
	Floor        uint64   `json:"floor"`
	Phase        string   `json:"phase"`
	Generation   string   `json:"generation"`
	AttemptedAt  string   `json:"attemptedAt"`
	Failure      []byte   `json:"failure"`
	ManifestHash string   `json:"manifestHash"`
	Count        uint32   `json:"count"`
	PackSHA256   string   `json:"packSha256"`
	PackBytes    int64    `json:"packBytes"`
	Next         uint32   `json:"next"`
	StartedAt    string   `json:"startedAt"`
	ExpiresAt    string   `json:"expiresAt"`
	ReceiptAt    string   `json:"receiptAt"`
	Last         *diskAck `json:"last"`
}
type diskAck struct {
	Operation    string `json:"operation"`
	Sequence     uint64 `json:"sequence"`
	GenerationID string `json:"generationId"`
	ManifestHash string `json:"manifestHash"`
	Ordinal      int    `json:"ordinal"`
	Digest       string `json:"digest"`
	Receipt      []byte `json:"receipt"`
	Request      []byte `json:"request"`
}

func ackFor(w Work, receipt []byte) *diskAck {
	a := &diskAck{Operation: w.Operation, Sequence: w.Sequence, GenerationID: w.GenerationID, ManifestHash: w.ManifestHash, Ordinal: w.Ordinal, Digest: w.Digest, Receipt: bytes.Clone(receipt)}
	if w.Operation == "failure" || w.Operation == "finalize" || w.Operation == "abort" {
		a.Request = w.Body()
	}
	return a
}
func (a diskAck) matches(w Work) bool {
	return a.Operation == w.Operation && a.Sequence == w.Sequence && a.GenerationID == w.GenerationID && a.ManifestHash == w.ManifestHash && a.Ordinal == w.Ordinal && a.Digest == w.Digest && w.body != nil && digest(w.body.raw) == a.Digest
}
func (a diskAck) valid(agent string, floor uint64) bool {
	gid, e := inventorywire.GenerationID(agent, a.Sequence)
	if e != nil || a.Sequence > floor || gid != a.GenerationID || !validDigest(a.Digest) || len(a.Receipt) == 0 || len(a.Receipt) > MaxReceiptBytes || !json.Valid(a.Receipt) || bytes.Equal(bytes.TrimSpace(a.Receipt), []byte("null")) {
		return false
	}
	if a.Operation == "failure" || a.Operation == "finalize" || a.Operation == "abort" {
		if len(a.Request) == 0 || len(a.Request) > 2048 {
			return false
		}
		r, e := inventorywire.DecodeReceipt(a.Receipt, a.Operation, a.Request)
		if e != nil || r.Sequence != a.Sequence || r.GenerationID != a.GenerationID || r.ManifestHash != a.ManifestHash || r.RequestSHA256 != a.Digest {
			return false
		}
	} else if a.Request != nil {
		return false
	}
	switch a.Operation {
	case "begin", "finalize", "abort":
		return validDigest(a.ManifestHash) && a.Ordinal == -1
	case "append":
		return validDigest(a.ManifestHash) && a.Ordinal >= 0 && a.Ordinal < 1024
	case "failure":
		return a.ManifestHash == "" && a.Ordinal == -1
	}
	return false
}
func encodeRecord(r diskRecord) ([]byte, error) {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	return raw, nil
}
func decodeRecord(raw []byte) (diskRecord, error) {
	var r diskRecord
	if len(raw) == 0 || len(raw) > MaxStateBytes || json.Unmarshal(raw, &r) != nil {
		return r, ErrCorrupt
	}
	// This is our own canonical schema, not permissive ingress. Re-encoding rejects
	// unknown/duplicate/case-folded/missing fields, null scalars, noncanonical numbers,
	// base64 aliases, invalid UTF-8, whitespace and trailing data.
	canonical, e := encodeRecord(r)
	if e != nil || !bytes.Equal(canonical, raw) {
		return r, ErrCorrupt
	}
	if r.Version != stateVersion || !validDigest(r.Binding) || r.Floor > MaxSequence {
		return r, ErrCorrupt
	}
	if _, e = inventorywire.GenerationID(r.AgentID, 1); e != nil {
		return r, ErrCorrupt
	}
	if r.Last != nil && !r.Last.valid(r.AgentID, r.Floor) {
		return r, ErrCorrupt
	}
	if r.Phase != "idle" {
		if e := validateReceiptContext(r); e != nil {
			return r, e
		}
	}
	if r.Phase == "idle" {
		if r.Floor == 0 && r.AttemptedAt != "" {
			return r, ErrCorrupt
		}
		if r.Floor > 0 {
			if _, ok := parseTime(r.AttemptedAt); !ok {
				return r, ErrCorrupt
			}
		}
		if r.Generation != "" || r.Failure != nil || r.ManifestHash != "" || r.Count != 0 || r.PackSHA256 != "" || r.PackBytes != 0 || r.Next != 0 || r.StartedAt != "" || r.ExpiresAt != "" || r.ReceiptAt != "" || r.Floor == 0 && r.Last != nil || r.Floor != 0 && (r.Last == nil || r.Last.Sequence != r.Floor || (r.Last.Operation != "finalize" && r.Last.Operation != "failure" && r.Last.Operation != "abort")) {
			return r, ErrCorrupt
		}
		return r, nil
	}
	gid, e := inventorywire.GenerationID(r.AgentID, r.Floor)
	if e != nil || r.Generation != gid {
		return r, ErrCorrupt
	}
	at, e := time.Parse(time.RFC3339Nano, r.AttemptedAt)
	if e != nil || !validTime(at) || at.Format(time.RFC3339Nano) != r.AttemptedAt {
		return r, ErrCorrupt
	}
	switch r.Phase {
	case "allocated", "failure":
		m, e := inventorywire.DecodeMessage("failure", r.Failure)
		if e != nil || m.Sequence != r.Floor || m.GenerationID != r.Generation || m.FailureAt.Format(time.RFC3339Nano) != r.AttemptedAt || r.ManifestHash != "" || r.Count != 0 || r.PackSHA256 != "" || r.PackBytes != 0 || r.Next != 0 {
			return r, ErrCorrupt
		}
		if r.Phase == "allocated" && m.FailureReason != "collection_failed" {
			return r, ErrCorrupt
		}
	case "ready", "abort", "retiring":
		if r.Failure != nil || !validDigest(r.ManifestHash) || !validDigest(r.PackSHA256) || r.Count > 1024 || r.PackBytes <= 0 || r.PackBytes > MaxPackBytes {
			return r, ErrCorrupt
		}
		if (r.Phase == "ready" || r.Phase == "abort") && r.Next > r.Count+1 {
			return r, ErrCorrupt
		}
		if r.Phase == "retiring" && (r.Next != r.Count+2 || r.Last == nil || r.Last.Sequence != r.Floor || (r.Last.Operation != "finalize" && r.Last.Operation != "abort") || r.Last.GenerationID != r.Generation || r.Last.ManifestHash != r.ManifestHash) {
			return r, ErrCorrupt
		}
		if (r.Phase == "ready" || r.Phase == "abort") && r.Next > 0 {
			if r.Last == nil || r.Last.Sequence != r.Floor || r.Last.GenerationID != r.Generation || r.Last.ManifestHash != r.ManifestHash {
				return r, ErrCorrupt
			}
			if r.Next == 1 && r.Last.Operation != "begin" || r.Next > 1 && (r.Last.Operation != "append" || r.Last.Ordinal != int(r.Next)-2) {
				return r, ErrCorrupt
			}
		}
	default:
		return r, ErrCorrupt
	}
	if r.Phase == "retiring" {
		receipt, e := inventorywire.DecodeReceipt(r.Last.Receipt, r.Last.Operation, r.Last.Request)
		if e != nil || !receiptContext(r, receipt) {
			return r, ErrCorrupt
		}
	}
	if r.Phase == "allocated" || r.Phase == "failure" || (r.Phase == "ready" || r.Phase == "abort") && r.Next == 0 {
		if r.Floor == 1 && r.Last != nil || r.Floor > 1 && (r.Last == nil || r.Last.Sequence != r.Floor-1 || (r.Last.Operation != "failure" && r.Last.Operation != "finalize" && r.Last.Operation != "abort")) {
			return r, ErrCorrupt
		}
	}
	return r, nil
}

func parseTime(s string) (time.Time, bool) {
	t, e := time.Parse(time.RFC3339Nano, s)
	return t, e == nil && validTime(t) && t.Format(time.RFC3339Nano) == s
}
func validateReceiptContext(r diskRecord) error {
	if r.StartedAt == "" && r.ExpiresAt == "" && r.ReceiptAt == "" {
		if r.Phase == "ready" && r.Next > 0 || r.Phase == "abort" && r.Next > 0 || r.Phase == "retiring" && r.Last != nil && r.Last.Operation == "finalize" {
			return ErrCorrupt
		}
		return nil
	}
	if r.Phase != "ready" && r.Phase != "abort" && r.Phase != "retiring" {
		return ErrCorrupt
	}
	if (r.Phase == "ready" || r.Phase == "abort") && r.Next == 0 {
		return ErrCorrupt
	}
	started, a := parseTime(r.StartedAt)
	expires, b := parseTime(r.ExpiresAt)
	receipt, c := parseTime(r.ReceiptAt)
	attempt, d := parseTime(r.AttemptedAt)
	if !a || !b || !c || !d || started.Before(attempt) || expires.Sub(started) != 15*time.Minute || receipt.Before(started) || !receipt.Before(expires) {
		return ErrCorrupt
	}
	return nil
}
func receiptContext(r diskRecord, receipt inventorywire.Receipt) bool {
	switch receipt.Operation {
	case "begin":
		return receipt.StartedAt.Format(time.RFC3339Nano) == r.StartedAt && receipt.ExpiresAt.Format(time.RFC3339Nano) == r.ExpiresAt && r.ReceiptAt == r.StartedAt
	case "append":
		return receipt.ReceivedAt.Format(time.RFC3339Nano) == r.ReceiptAt
	case "finalize":
		return receipt.CollectedAt.Format(time.RFC3339Nano) == r.AttemptedAt && receipt.CompletedAt.Format(time.RFC3339Nano) == r.ReceiptAt
	}
	return true
}
