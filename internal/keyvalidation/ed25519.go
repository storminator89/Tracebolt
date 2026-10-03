// Package keyvalidation rejects unusable public-key encodings before they enter
// a trust or proof-of-possession boundary. It performs no signing or network I/O.
package keyvalidation

import (
	"bytes"
	"crypto/ed25519"
	"filippo.io/edwards25519"
)

var inverseCofactor = func() *edwards25519.Scalar {
	var encoded [32]byte
	encoded[0] = 8
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(encoded[:])
	if err != nil {
		return nil
	}
	return new(edwards25519.Scalar).Invert(eight)
}()

// Ed25519 requires a canonical nonidentity point in the prime-order subgroup.
// SetBytes alone is insufficient: it also accepts noncanonical encodings. The
// cofactor projection removes torsion; inverse8 recovers exactly the original
// point iff it had no torsion component. All curve arithmetic is delegated to
// the pinned upstream-derived edwards25519 implementation, not reimplemented.
func Ed25519(publicKey ed25519.PublicKey) bool {
	if len(publicKey) != ed25519.PublicKeySize || inverseCofactor == nil {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil || !bytes.Equal(point.Bytes(), publicKey) {
		return false
	}
	identity := edwards25519.NewIdentityPoint()
	if point.Equal(identity) == 1 {
		return false
	}
	cleared := new(edwards25519.Point).MultByCofactor(point)
	if cleared.Equal(identity) == 1 {
		return false
	}
	recovered := new(edwards25519.Point).ScalarMult(inverseCofactor, cleared)
	return recovered.Equal(point) == 1
}
