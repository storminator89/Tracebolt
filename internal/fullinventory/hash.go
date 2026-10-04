package fullinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"localrmm/internal/linuxpackages"
)

func newRowsHash() hash.Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(rowDomain))
	return h
}
func hashHex(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
func canonicalRow(p linuxpackages.PackageRow) []byte {
	// All retained strings are bounded ASCII under the existing row validator.
	b, _ := json.Marshal(p)
	return append(b, '\n')
}
func digest(domain string, v any) string {
	b, _ := json.Marshal(v)
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(b)
	return hashHex(h)
}

// ManifestDigest uses the domain-prefixed canonical encoding documented in
// contract.md. It validates metadata but does not prove the rows were received.
func ManifestDigest(m Manifest) (string, error) {
	if err := ValidateManifest(m); err != nil {
		return "", err
	}
	return digest(manifestDomain, m), nil
}

// The explicit ordered payload excludes only SHA256 itself. Never replace this
// with a map or omit fields when values are zero.
type chunkPayload struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	GenerationID   string                     `json:"generationId"`
	ManifestSHA256 string                     `json:"manifestSha256"`
	Ordinal        uint32                     `json:"ordinal"`
	ChunkCount     uint32                     `json:"chunkCount"`
	RowOffset      uint64                     `json:"rowOffset"`
	PreviousSHA256 string                     `json:"previousSha256"`
	Items          []linuxpackages.PackageRow `json:"items"`
}

func payload(c Chunk) chunkPayload {
	return chunkPayload{c.SchemaVersion, c.GenerationID, c.ManifestSHA256, c.Ordinal,
		c.ChunkCount, c.RowOffset, c.PreviousSHA256, c.Items}
}
func chunkDigest(c Chunk) string { return digest(chunkDomain, payload(c)) }
func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
