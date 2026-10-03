package keyvalidation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/edwards25519"
	"testing"
)

// These are pure key-classification contracts. They do not construct signatures,
// certificate requests or requests to any authentication/network surface.
func TestGeneratedEd25519KeysAreAccepted(t *testing.T) {
	for i := 0; i < 100; i++ {
		pub, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil || !Ed25519(pub) {
			t.Fatal("ordinary generated key rejected")
		}
	}
}
func TestInvalidAndNonPrimeOrderKeysAreRejected(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{255}, 32), edwards25519.NewIdentityPoint().Bytes(), make([]byte, 32)} {
		if Ed25519(raw) {
			t.Fatal("invalid key accepted")
		}
	}
	noncanonical := edwards25519.NewIdentityPoint().Bytes()
	noncanonical[31] |= 0x80
	if Ed25519(noncanonical) {
		t.Fatal("noncanonical encoding accepted")
	}
	torsion, e := new(edwards25519.Point).SetBytes(make([]byte, 32))
	if e != nil {
		t.Fatal("classification fixture")
	}
	mixed := new(edwards25519.Point).Add(edwards25519.NewGeneratorPoint(), torsion)
	if Ed25519(mixed.Bytes()) {
		t.Fatal("mixed-order point accepted")
	}
	if !Ed25519(edwards25519.NewGeneratorPoint().Bytes()) {
		t.Fatal("prime-order generator rejected")
	}
}
func FuzzEd25519Classification(f *testing.F) {
	f.Add(edwards25519.NewGeneratorPoint().Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64 {
			return
		}
		_ = Ed25519(b)
	})
}
