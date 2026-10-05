package inventorystate

import (
	"context"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/updategeneration"
)

// These fixed entry points select the cached-update codec. They neither enable
// collection nor accept the preview grant as complete-row consent. The caller
// must supply its separately domain-bound configuration hash and private path.
func InitializeCachedUpdatesNew(dir, binding, agentID string) (*State, error) {
	return openKind(cachedUpdatesTransfer, dir, binding, agentID, true, false)
}
func OpenCachedUpdatesExisting(dir, binding, agentID string) (*State, error) {
	return openKind(cachedUpdatesTransfer, dir, binding, agentID, false, true)
}
func ValidateCachedUpdatesExisting(dir, binding, agentID string) error {
	s, err := openKind(cachedUpdatesTransfer, dir, binding, agentID, false, false)
	if err != nil {
		return err
	}
	return s.Close()
}

// The kind is never unmarshaled or inferred from a record. Its fixed state
// version rejects a different domain even for an idle, zero-floor spool. The
// package ledger's serialized fields, order and version remain unchanged.
type transferKind uint8

const (
	packageTransfer transferKind = iota
	cachedUpdatesTransfer
	cachedUpdatesStateVersion = 2
	cachedUpdatesPackMagic    = "tracebolt.cached-updates-spool.pack.v1\n"
)

func (k transferKind) stateVersion() int {
	if k == cachedUpdatesTransfer {
		return cachedUpdatesStateVersion
	}
	return stateVersion
}
func (k transferKind) packMagic() string {
	if k == cachedUpdatesTransfer {
		return cachedUpdatesPackMagic
	}
	return packMagic
}
func (k transferKind) messageVersion() string {
	if k == cachedUpdatesTransfer {
		return inventorywire.CachedUpdatesMessageVersion
	}
	return inventorywire.MessageVersion
}
func (k transferKind) generationID(agent string, sequence uint64) (string, error) {
	if k == cachedUpdatesTransfer {
		return inventorywire.CachedUpdatesGenerationID(agent, sequence)
	}
	return inventorywire.GenerationID(agent, sequence)
}
func (k transferKind) encodeMessage(operation string, sequence uint64, generation, hash string, payload any) ([]byte, error) {
	if k == cachedUpdatesTransfer {
		return inventorywire.EncodeCachedUpdatesMessage(operation, sequence, generation, hash, payload)
	}
	return inventorywire.EncodeMessage(operation, sequence, generation, hash, payload)
}
func (k transferKind) decodeMessage(operation string, raw []byte) (inventorywire.Message, error) {
	if k == cachedUpdatesTransfer {
		return inventorywire.DecodeCachedUpdatesMessage(operation, raw)
	}
	return inventorywire.DecodeMessage(operation, raw)
}
func (k transferKind) decodeReceipt(raw []byte, operation string, body []byte) (inventorywire.Receipt, error) {
	if k == cachedUpdatesTransfer {
		return inventorywire.DecodeCachedUpdatesReceipt(raw, operation, body)
	}
	return inventorywire.DecodeReceipt(raw, operation, body)
}
func (k transferKind) maxManifestBytes() int {
	if k == cachedUpdatesTransfer {
		return updategeneration.MaxManifestBytes
	}
	return fullinventory.MaxManifestBytes
}
func (k transferKind) maxChunkBytes() int {
	if k == cachedUpdatesTransfer {
		return updategeneration.MaxChunkBytes
	}
	return fullinventory.MaxChunkBytes
}
func (k transferKind) maxChunks() int {
	if k == cachedUpdatesTransfer {
		return updategeneration.MaxGenerationChunks
	}
	return fullinventory.MaxGenerationChunks
}
func (k transferKind) decodeManifest(raw []byte) (inventorywire.Message, string, error) {
	if k == cachedUpdatesTransfer {
		m, err := updategeneration.DecodeManifest(raw)
		if err != nil {
			return inventorywire.Message{}, "", err
		}
		hash, err := updategeneration.ManifestDigest(m)
		return inventorywire.Message{GenerationID: m.GenerationID, UpdateManifest: &m}, hash, err
	}
	m, err := fullinventory.DecodeManifest(raw)
	if err != nil {
		return inventorywire.Message{}, "", err
	}
	hash, err := fullinventory.ManifestDigest(m)
	return inventorywire.Message{GenerationID: m.GenerationID, Manifest: &m}, hash, err
}

// Only streaming row validation differs. Publication, exact retry, floor,
// receipt admission, abort and retirement all use the original shared engine.
type transferValidator struct {
	packages *fullinventory.Validator
	updates  *updategeneration.Validator
}

func newTransferValidator(ctx context.Context, m inventorywire.Message) (*transferValidator, error) {
	if m.UpdateManifest != nil && m.Manifest == nil {
		v, err := updategeneration.NewValidator(ctx, *m.UpdateManifest)
		return &transferValidator{updates: v}, err
	}
	if m.Manifest != nil && m.UpdateManifest == nil {
		v, err := fullinventory.NewValidator(ctx, *m.Manifest)
		return &transferValidator{packages: v}, err
	}
	return nil, ErrBody
}
func (v *transferValidator) addRaw(kind transferKind, raw []byte) error {
	if kind == cachedUpdatesTransfer {
		c, err := updategeneration.DecodeChunk(raw)
		if err != nil {
			return err
		}
		return v.add(inventorywire.Message{UpdateChunk: &c})
	}
	c, err := fullinventory.DecodeChunk(raw)
	if err != nil {
		return err
	}
	return v.add(inventorywire.Message{Chunk: &c})
}
func (v *transferValidator) add(m inventorywire.Message) error {
	if v == nil {
		return ErrBody
	}
	if v.updates != nil && m.UpdateChunk != nil && m.Chunk == nil {
		return v.updates.Add(*m.UpdateChunk)
	}
	if v.packages != nil && m.Chunk != nil && m.UpdateChunk == nil {
		return v.packages.Add(*m.Chunk)
	}
	return ErrBody
}
func (v *transferValidator) finish() error {
	if v == nil {
		return ErrBody
	}
	if v.updates != nil {
		_, err := v.updates.Finish()
		return err
	}
	if v.packages != nil {
		_, err := v.packages.Finish()
		return err
	}
	return ErrBody
}
