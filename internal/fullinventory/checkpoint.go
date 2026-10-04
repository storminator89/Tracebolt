package fullinventory

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"localrmm/internal/linuxpackages"
)

const (
	MaxCheckpointBytes = 2048
	checkpointVersion  = "tracebolt.full-inventory.checkpoint.sha256-go1.v1"
	sha256StateSize    = 108
)

// Progress is detached trusted-manager staging progress, never completeness or
// client authority. Compare it to transactionally persisted accepted row/chunk
// byte counters when restoring a checkpoint.
type Progress struct {
	AcceptedChunks     uint32
	ObservedCount      uint64
	InstalledCount     uint64
	CanonicalRowBytes  uint64
	CanonicalWireBytes uint64
	LastChunkSHA256    string
}

func (v *Validator) Progress() (Progress, error) {
	if err := v.ready(); err != nil {
		return Progress{}, err
	}
	return Progress{v.next, v.observed, v.installed, v.rowBytes, v.wireBytes, v.previous}, nil
}

type checkpoint struct {
	Version            string `json:"version"`
	ManifestSHA256     string `json:"manifestSha256"`
	NextOrdinal        uint32 `json:"nextOrdinal"`
	ObservedCount      uint64 `json:"observedCount"`
	InstalledCount     uint64 `json:"installedCount"`
	CanonicalRowBytes  uint64 `json:"canonicalRowBytes"`
	CanonicalWireBytes uint64 `json:"canonicalWireBytes"`
	PreviousSHA256     string `json:"previousSha256"`
	LastName           string `json:"lastName"`
	LastArchitecture   string `json:"lastArchitecture"`
	SHA256State        []byte `json:"sha256State"`
}

// Checkpoint is manager-private continuity state, potentially containing a hash
// block's partial row bytes. Never send it to clients or logs. Persist it in the
// same transaction as accepted canonical chunks/rows and progress counters.
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
	s := checkpoint{checkpointVersion, v.manifestSHA256, v.next, v.observed, v.installed, v.rowBytes, v.wireBytes,
		v.previous, v.last.Name, v.last.Architecture, state}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, v.fail(ErrInvalid)
	}
	if len(b) > MaxCheckpointBytes {
		return nil, v.fail(ErrLimit)
	}
	return b, nil
}

// RestoreValidatorFromTrustedCheckpoint accepts ONLY bytes the manager previously
// persisted transactionally. It must never be a request-body decoder. Validation
// rejects corrupt structure and inconsistent counters, but cannot establish
// authentic past rows from an arbitrarily tampered hash state. Use an independent
// rescan or authenticated state if the database itself is outside the trust boundary.
func RestoreValidatorFromTrustedCheckpoint(ctx context.Context, m Manifest, raw []byte) (*Validator, error) {
	v, err := NewValidator(ctx, m)
	if err != nil {
		return nil, err
	}
	value, err := strictValue(raw, MaxCheckpointBytes)
	if err != nil {
		return nil, err
	}
	if !checkpointShape(value) {
		return nil, ErrInvalid
	}
	var s checkpoint
	if json.Unmarshal(raw, &s) != nil {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalid
	}
	if s.Version != checkpointVersion || s.ManifestSHA256 != v.manifestSHA256 || !validHashState(s.SHA256State, s.CanonicalRowBytes) {
		return nil, ErrInvalid
	}
	if s.NextOrdinal > m.ChunkCount || s.ObservedCount > m.ObservedCount || s.InstalledCount > m.InstalledCount ||
		s.InstalledCount > s.ObservedCount || s.CanonicalRowBytes > m.CanonicalRowBytes ||
		s.CanonicalWireBytes > MaxCanonicalWireBytes || s.CanonicalWireBytes < v.wireBytes ||
		s.CanonicalWireBytes-v.wireBytes > uint64(s.NextOrdinal)*MaxChunkBytes ||
		s.CanonicalRowBytes > s.CanonicalWireBytes-v.wireBytes ||
		m.InstalledCount-s.InstalledCount > m.ObservedCount-s.ObservedCount {
		return nil, ErrInvalid
	}
	remainingChunks := uint64(m.ChunkCount - s.NextOrdinal)
	remainingRows := m.ObservedCount - s.ObservedCount
	if remainingRows < remainingChunks || remainingRows > remainingChunks*MaxChunkRows {
		return nil, ErrInvalid
	}
	if s.NextOrdinal == 0 {
		initial, _ := v.rows.(encoding.BinaryMarshaler).MarshalBinary()
		if s.ObservedCount != 0 || s.InstalledCount != 0 || s.CanonicalRowBytes != 0 || s.CanonicalWireBytes != v.wireBytes ||
			s.PreviousSHA256 != "" || s.LastName != "" || s.LastArchitecture != "" || !bytes.Equal(initial, s.SHA256State) {
			return nil, ErrInvalid
		}
	} else {
		if s.ObservedCount < uint64(s.NextOrdinal) || s.ObservedCount > uint64(s.NextOrdinal)*MaxChunkRows ||
			s.CanonicalRowBytes < s.ObservedCount || !validDigest(s.PreviousSHA256) {
			return nil, ErrInvalid
		}
		p := linuxpackages.PackageRow{Name: s.LastName, Architecture: s.LastArchitecture, Version: "0", SourcePackage: s.LastName,
			SourceVersion: "0", SourceMapping: "binary-default", InstallState: "installed"}
		if ValidateRow(p) != nil {
			return nil, ErrInvalid
		}
	}
	unmarshaler, ok := v.rows.(encoding.BinaryUnmarshaler)
	if !ok || unmarshaler.UnmarshalBinary(s.SHA256State) != nil {
		return nil, ErrInvalid
	}
	// Reject nonzero unused SHA block padding or unsupported serialization forms.
	roundtrip, err := v.rows.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil || !bytes.Equal(roundtrip, s.SHA256State) {
		return nil, ErrInvalid
	}
	if s.NextOrdinal == m.ChunkCount && (s.ObservedCount != m.ObservedCount || s.InstalledCount != m.InstalledCount ||
		s.CanonicalRowBytes != m.CanonicalRowBytes || hashHex(v.rows) != m.RowsSHA256) {
		return nil, ErrInvalid
	}
	v.next, v.observed, v.installed, v.rowBytes, v.wireBytes, v.previous = s.NextOrdinal, s.ObservedCount, s.InstalledCount, s.CanonicalRowBytes, s.CanonicalWireBytes, s.PreviousSHA256
	v.last = linuxpackages.PackageRow{Name: s.LastName, Architecture: s.LastArchitecture}
	return v, nil
}
func validHashState(state []byte, rowBytes uint64) bool {
	return rowBytes <= MaxCanonicalRowBytes && len(state) == sha256StateSize && string(state[:4]) == "sha\x03" &&
		binary.BigEndian.Uint64(state[sha256StateSize-8:]) == uint64(len(rowDomain))+rowBytes
}
func checkpointShape(value any) bool {
	m, ok := object(value, "version", "manifestSha256", "nextOrdinal", "observedCount", "installedCount", "canonicalRowBytes", "canonicalWireBytes", "previousSha256", "lastName", "lastArchitecture", "sha256State")
	return ok && stringsOnly(m, "version", "manifestSha256", "previousSha256", "lastName", "lastArchitecture", "sha256State") &&
		integersOnly(m, "nextOrdinal", "observedCount", "installedCount", "canonicalRowBytes", "canonicalWireBytes")
}
