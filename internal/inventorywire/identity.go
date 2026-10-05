// Package inventorywire holds the new, separately scoped complete-inventory
// protocol contract. This identifier helper alone enables no transport route.
package inventorywire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"math"
)

var ErrContract = errors.New("inventory_wire_invalid")

const MaxSequence uint64 = math.MaxInt64

// GenerationID binds an inventory generation label to the authoritative device
// ID and its independent durable inventory sequence. It is public, not a token
// or an authority proof. Domain separation and fixed-width sequence encoding
// prevent counter concatenation ambiguity; current profile/credential and floor
// checks remain required at every store operation.
func GenerationID(agentID string, sequence uint64) (string, error) {
	return generationID("tracebolt.complete-inventory.generation.v1\x00", agentID, sequence)
}
func generationID(domain string, agentID string, sequence uint64) (string, error) {
	if !enrollmentcrypto.ValidID(agentID, "agent_") || sequence == 0 || sequence > MaxSequence {
		return "", ErrContract
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte(agentID))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], sequence)
	h.Write(counter[:])
	digest := h.Sum(nil)
	return "sample_" + hex.EncodeToString(digest[:16]), nil
}
