package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
)

// No native APIs: the state observation decision can be tested with invented
// records. The Windows caller separately validates the protected store/handoff.
type senderContinuity struct {
	seen            bool
	binding         string
	floor           uint64
	pendingSeen     bool
	pendingSequence uint64
	pendingHash     [32]byte
}
type senderObservation struct {
	Version      int                 `json:"version"`
	Binding      string              `json:"binding"`
	LastSequence uint64              `json:"lastSequence"`
	Pending      *pendingObservation `json:"pending"`
}
type pendingObservation struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
	Body     []byte `json:"body"`
}

func observeSender(previous senderContinuity, raw []byte) (senderContinuity, bool, bool, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return previous, false, false, ErrAcceptance
	}
	var record senderObservation
	if json.Unmarshal(raw, &record) != nil {
		return previous, false, false, ErrAcceptance
	}
	if record.Pending != nil {
		defer clear(record.Pending.Body)
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return previous, false, false, ErrAcceptance
	}
	defer clear(canonical)
	// The ordinary sender writes canonical JSON. Reject duplicate/missing fields,
	// null scalars, unknown keys, alternate encodings and unbounded sequence data.
	if !bytes.Equal(raw, canonical) || record.Version != 1 || !validDigest(record.Binding) || record.LastSequence == 0 || record.LastSequence > math.MaxInt64 {
		return previous, false, false, ErrAcceptance
	}
	if previous.seen && (record.Binding != previous.binding || record.LastSequence < previous.floor) {
		return previous, false, false, ErrAcceptance
	}
	next := previous
	retained := false
	if p := record.Pending; p != nil {
		if p.Sequence == 0 || p.Sequence != record.LastSequence || !validDigest(p.Digest) || len(p.Body) == 0 || len(p.Body) > 72<<10 {
			return previous, false, false, ErrAcceptance
		}
		hash := sha256.Sum256(p.Body)
		if hex.EncodeToString(hash[:]) != p.Digest {
			return previous, false, false, ErrAcceptance
		}
		if previous.pendingSeen && p.Sequence == previous.pendingSequence {
			if hash != previous.pendingHash {
				return previous, false, false, ErrAcceptance
			}
			retained = true
		}
		next.pendingSeen = true
		next.pendingSequence = p.Sequence
		next.pendingHash = hash
	}
	next.seen = true
	next.binding = record.Binding
	next.floor = record.LastSequence
	return next, record.Pending != nil, retained, nil
}
