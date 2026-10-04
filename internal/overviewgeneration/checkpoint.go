package overviewgeneration

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"localrmm/internal/completeoverview"
)

const (
	MaxCheckpointBytes = 4096
	checkpointVersion  = "tracebolt.complete-overview.checkpoint.sha256-go1.v1"
	sha256StateSize    = 108
)

// Progress is manager-private staging progress, never proof of completeness.
type Progress struct {
	AcceptedChunks        uint32
	ObservedCount         uint64
	CanonicalRowBytes     uint64
	CanonicalWireBytes    uint64
	CanonicalSectionBytes uint64
	LastChunkSHA256       string
}

func (v *Validator) Progress() (Progress, error) {
	if err := v.ready(); err != nil {
		return Progress{}, err
	}
	return Progress{v.next, v.observed, v.rowBytes, v.wireBytes, v.sectionBytes(), v.previous}, nil
}

type checkpoint struct {
	Version            string                         `json:"version"`
	ManifestSHA256     string                         `json:"manifestSha256"`
	NextOrdinal        uint32                         `json:"nextOrdinal"`
	ObservedCount      uint64                         `json:"observedCount"`
	CanonicalRowBytes  uint64                         `json:"canonicalRowBytes"`
	CanonicalWireBytes uint64                         `json:"canonicalWireBytes"`
	SectionRowBytes    uint64                         `json:"sectionRowBytes"`
	FieldCoverage      completeoverview.FieldCoverage `json:"fieldCoverage"`
	PreviousSHA256     string                         `json:"previousSha256"`
	LastIdentity       uint32                         `json:"lastIdentity"`
	SHA256State        []byte                         `json:"sha256State"`
}

// Checkpoint includes partial canonical row bytes inside SHA state. It is private
// trusted-manager state, persisted transactionally with accepted chunks and rows.
func (v *Validator) Checkpoint() ([]byte, error) {
	if err := v.ready(); err != nil {
		return nil, err
	}
	marshaler, ok := v.rows.(encoding.BinaryMarshaler)
	if !ok {
		return nil, v.fail(ErrInvalid)
	}
	state, err := marshaler.MarshalBinary()
	if err != nil || !validHashState(state, v.rowBytes) {
		return nil, v.fail(ErrInvalid)
	}
	s := checkpoint{checkpointVersion, v.manifestSHA256, v.next, v.observed, v.rowBytes, v.wireBytes, v.sectionRowBytes, v.coverage, v.previous, v.last, state}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, v.fail(ErrInvalid)
	}
	if len(raw) > MaxCheckpointBytes {
		return nil, v.fail(ErrLimit)
	}
	return raw, nil
}

// RestoreValidatorFromTrustedCheckpoint accepts ONLY bytes the manager persisted
// transactionally. It checks corruption/consistency, not authenticity against a
// database attacker; never route a request body here. Compare Progress to rows.
func RestoreValidatorFromTrustedCheckpoint(ctx context.Context, m Manifest, raw []byte) (*Validator, error) {
	v, err := NewValidator(ctx, m)
	if err != nil {
		return nil, err
	}
	var s checkpoint
	if err = decodeTyped(raw, MaxCheckpointBytes, &s); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalid
	}
	if s.Version != checkpointVersion || s.ManifestSHA256 != v.manifestSHA256 || !validHashState(s.SHA256State, s.CanonicalRowBytes) {
		return nil, ErrInvalid
	}
	if s.NextOrdinal > m.ChunkCount || s.ObservedCount > m.ObservedCount || s.CanonicalRowBytes > m.CanonicalRowBytes || s.CanonicalWireBytes > MaxCanonicalWireBytes || s.CanonicalWireBytes < v.wireBytes || s.CanonicalWireBytes-v.wireBytes > uint64(s.NextOrdinal)*MaxChunkBytes || s.CanonicalRowBytes > s.CanonicalWireBytes-v.wireBytes || s.SectionRowBytes > s.CanonicalRowBytes || s.CanonicalRowBytes != s.SectionRowBytes+rowEnvelopeBytes*s.ObservedCount || !coverageWithin(s.FieldCoverage, m.SelectedMeta().FieldCoverage) || coverageCount(s.FieldCoverage) != s.ObservedCount {
		return nil, ErrInvalid
	}
	remainingChunks := uint64(m.ChunkCount - s.NextOrdinal)
	remainingRows := m.ObservedCount - s.ObservedCount
	if remainingRows < remainingChunks || remainingRows > remainingChunks*MaxChunkRows {
		return nil, ErrInvalid
	}
	if s.NextOrdinal == 0 {
		initial, _ := v.rows.(encoding.BinaryMarshaler).MarshalBinary()
		if s.ObservedCount != 0 || s.CanonicalRowBytes != 0 || s.CanonicalWireBytes != v.wireBytes || s.SectionRowBytes != 0 || s.PreviousSHA256 != "" || s.LastIdentity != 0 || !bytes.Equal(initial, s.SHA256State) {
			return nil, ErrInvalid
		}
	} else if s.ObservedCount < uint64(s.NextOrdinal) || s.ObservedCount > uint64(s.NextOrdinal)*MaxChunkRows || s.CanonicalRowBytes < s.ObservedCount || s.SectionRowBytes < s.ObservedCount || !validDigest(s.PreviousSHA256) || s.LastIdentity == 0 || uint64(s.LastIdentity) < s.ObservedCount || m.Section == "processes" && s.LastIdentity > 2147483647 {
		return nil, ErrInvalid
	}
	unmarshal, ok := v.rows.(encoding.BinaryUnmarshaler)
	if !ok || unmarshal.UnmarshalBinary(s.SHA256State) != nil {
		return nil, ErrInvalid
	}
	roundtrip, err := v.rows.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || !bytes.Equal(roundtrip, s.SHA256State) {
		return nil, ErrInvalid
	}
	v.next, v.observed, v.rowBytes, v.wireBytes, v.sectionRowBytes, v.coverage, v.previous, v.last = s.NextOrdinal, s.ObservedCount, s.CanonicalRowBytes, s.CanonicalWireBytes, s.SectionRowBytes, s.FieldCoverage, s.PreviousSHA256, s.LastIdentity
	if v.sectionBytes() > m.CanonicalSectionBytes {
		return nil, ErrInvalid
	}
	if s.NextOrdinal == m.ChunkCount && (s.ObservedCount != m.ObservedCount || s.CanonicalRowBytes != m.CanonicalRowBytes || v.sectionBytes() != m.CanonicalSectionBytes || s.FieldCoverage != m.SelectedMeta().FieldCoverage || hashHex(v.rows) != m.RowsSHA256) {
		return nil, ErrInvalid
	}
	return v, nil
}
func validHashState(state []byte, rowBytes uint64) bool {
	return rowBytes <= MaxCanonicalRowBytes && len(state) == sha256StateSize && string(state[:4]) == "sha\x03" && binary.BigEndian.Uint64(state[sha256StateSize-8:]) == uint64(len(rowDomain))+rowBytes
}
