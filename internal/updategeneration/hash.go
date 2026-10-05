package updategeneration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"localrmm/internal/bulkrows"
	"localrmm/internal/cachedupdates"
)

func newRowsHash() hash.Hash     { h := sha256.New(); _, _ = h.Write([]byte(rowDomain)); return h }
func hashHex(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
func canonicalRow(row cachedupdates.Candidate) []byte {
	raw, _ := json.Marshal(row)
	return append(raw, '\n')
}
func digest(domain string, value any) string {
	raw, _ := json.Marshal(value)
	return bulkrows.Digest(domain, raw)
}

// ManifestDigest authenticates no source. It identifies validated, canonical
// metadata for linkage; only Validator.Finish establishes row consistency.
func ManifestDigest(m Manifest) (string, error) {
	if err := ValidateManifest(m); err != nil {
		return "", err
	}
	return digest(manifestDomain, m), nil
}

type chunkPayload struct {
	SchemaVersion  string                    `json:"schemaVersion"`
	GenerationID   string                    `json:"generationId"`
	ManifestSHA256 string                    `json:"manifestSha256"`
	Ordinal        uint32                    `json:"ordinal"`
	ChunkCount     uint32                    `json:"chunkCount"`
	RowOffset      uint64                    `json:"rowOffset"`
	PreviousSHA256 string                    `json:"previousSha256"`
	Items          []cachedupdates.Candidate `json:"items"`
}

func payload(c Chunk) chunkPayload {
	return chunkPayload{c.SchemaVersion, c.GenerationID, c.ManifestSHA256, c.Ordinal, c.ChunkCount, c.RowOffset, c.PreviousSHA256, c.Items}
}
func chunkDigest(c Chunk) string { return digest(chunkDomain, payload(c)) }
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
