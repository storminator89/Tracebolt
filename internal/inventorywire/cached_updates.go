package inventorywire

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

const (
	CachedUpdatesMessageVersion  = "tracebolt.cached-updates-request.v1"
	CachedUpdatesReceiptVersion  = "tracebolt.cached-updates-response.v1"
	CachedUpdatesPathPrefix      = "/v3/agent/cached-updates/"
	cachedUpdatesSignatureDomain = "Tracebolt complete cached APT updates insecure HTTP requests; Ed25519; v1"
)

// transferKind is chosen only by fixed public entry points, never by wire data.
type transferKind uint8

const (
	packageTransfer transferKind = iota
	cachedUpdatesTransfer
)

func (k transferKind) messageVersion() string {
	if k == cachedUpdatesTransfer {
		return CachedUpdatesMessageVersion
	}
	return MessageVersion
}
func (k transferKind) receiptVersion() string {
	if k == cachedUpdatesTransfer {
		return CachedUpdatesReceiptVersion
	}
	return ReceiptVersion
}
func (k transferKind) pathPrefix() string {
	if k == cachedUpdatesTransfer {
		return CachedUpdatesPathPrefix
	}
	return PathPrefix
}
func (k transferKind) signatureDomain() string {
	if k == cachedUpdatesTransfer {
		return cachedUpdatesSignatureDomain
	}
	return domain
}
func (k transferKind) validPath(path string) bool {
	prefix := k.pathPrefix()
	return strings.HasPrefix(path, prefix) && ValidOperation(strings.TrimPrefix(path, prefix))
}

// CachedUpdatesGenerationID uses a separate sequence domain. It grants no
// collection consent, identity authority, or package-inventory permission.
func CachedUpdatesGenerationID(agentID string, sequence uint64) (string, error) {
	return generationID("tracebolt.complete-cached-apt-updates.generation.v1\x00", agentID, sequence)
}
func EncodeCachedUpdatesMessage(operation string, sequence uint64, generation, manifestHash string, payload any) ([]byte, error) {
	return encodeMessage(cachedUpdatesTransfer, operation, sequence, generation, manifestHash, payload)
}
func DecodeCachedUpdatesMessage(operation string, raw []byte) (Message, error) {
	return decodeMessage(cachedUpdatesTransfer, operation, raw)
}
func DecodeCachedUpdatesReceipt(raw []byte, operation string, exactRequestBody []byte) (Receipt, error) {
	return decodeReceipt(cachedUpdatesTransfer, raw, operation, exactRequestBody)
}
func NewCachedUpdatesSignedRequest(ctx context.Context, origin string, certificate tls.Certificate, operation string, sequence uint64, signedAt time.Time, body []byte) (*http.Request, error) {
	return newSignedRequest(cachedUpdatesTransfer, ctx, origin, certificate, operation, sequence, signedAt, body)
}
func NewCachedUpdatesVerifier(config Config) (*Verifier, error) {
	return newVerifier(cachedUpdatesTransfer, config)
}
func ValidateCachedUpdatesShape(r *http.Request, authority, profile string) error {
	return validateShape(cachedUpdatesTransfer, r, authority, profile)
}

// ManifestFacts returns only common transfer scalars. Update rows are never
// converted into or represented as installed-package rows.
func (m Message) ManifestFacts() (collectedAt time.Time, chunks uint32, rows uint64, ok bool) {
	if m.Manifest != nil && m.UpdateManifest == nil {
		return m.Manifest.CollectedAt, m.Manifest.ChunkCount, m.Manifest.ObservedCount, true
	}
	if m.UpdateManifest != nil && m.Manifest == nil {
		return m.UpdateManifest.CollectedAt, m.UpdateManifest.ChunkCount, uint64(m.UpdateManifest.CandidateCount), true
	}
	return time.Time{}, 0, 0, false
}
func (m Message) ChunkFacts() (ordinal uint32, rows uint64, ok bool) {
	if m.Chunk != nil && m.UpdateChunk == nil {
		return m.Chunk.Ordinal, uint64(len(m.Chunk.Items)), true
	}
	if m.UpdateChunk != nil && m.Chunk == nil {
		return m.UpdateChunk.Ordinal, uint64(len(m.UpdateChunk.Items)), true
	}
	return 0, 0, false
}
