package inventorywire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Values were captured from the unmodified bdb84f4 transcript implementation.
// Together with inventorystate's original-body fixtures this pins the complete
// old signature input bytes and deterministic Ed25519 proof.
func TestOriginalPackageSignatureTranscriptBytes(t *testing.T) {
	raw := transcript("http://127.0.0.1:8788", "/v3/agent/inventory/begin", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "17", "2026-10-04T09:00:00.000000123Z", []byte(`{"synthetic":"exact-body"}`))
	sum := sha256.Sum256(raw)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize)), raw)
	got := hex.EncodeToString(sum[:]) + ":" + hex.EncodeToString(signature)
	const want = "0c694df1955ffabc30c43cb0d809d9b360748bac27c686f748a6b0c758d51a01:05a7b84badcf08b04055a401cc2812e89740d330aa6ea3ae2cd7029fc10e1d62f9c6435251592225e88fe464ae1e445f69f73c3f17ea3b6d707d9a2af09dbd0b"
	if got != want {
		t.Fatalf("original transcript changed: %s", got)
	}
}
