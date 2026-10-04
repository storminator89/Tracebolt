// Package overviewwire holds the new, separately scoped complete-overview
// protocol contract. This identifier helper alone enables no transport route.
package overviewwire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"math"
)

var ErrContract = errors.New("overview_wire_invalid")

const MaxSequence uint64 = math.MaxInt64

// GenerationID binds an overview generation label to the authoritative device
// ID, fixed section and its independent durable overview sequence. It is public, not a token
// or an authority proof. Domain separation and fixed-width sequence encoding
// prevent counter concatenation ambiguity; current profile/credential and floor
// checks remain required at every store operation.
func GenerationID(agentID, section string, sequence uint64) (string, error) {
	if !ValidSection(section) || !enrollmentcrypto.ValidID(agentID, "agent_") || sequence == 0 || sequence > MaxSequence {
		return "", ErrContract
	}
	h := sha256.New()
	h.Write([]byte("tracebolt.complete-overview.generation.v1\x00"))
	h.Write([]byte(section))
	h.Write([]byte{0})
	h.Write([]byte(agentID))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], sequence)
	h.Write(counter[:])
	digest := h.Sum(nil)
	return "sample_" + hex.EncodeToString(digest[:16]), nil
}
