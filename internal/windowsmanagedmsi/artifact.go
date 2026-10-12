package windowsmanagedmsi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const ArtifactRecordVersion = "tracebolt.windows-managed-msi-artifact-record.v2"
const MaxDevices = 25

// ArtifactRecord is manager-owned custody metadata, independent of any endpoint
// grant or leaf. It never contains package bytes or authorizes delivery/install.
type ArtifactRecord struct {
	Version    string    `json:"version"`
	Artifact   *Artifact `json:"artifact"`
	ClockFloor int64     `json:"clockFloor"`
}

func (a *Artifact) Validate(floor int64) error {
	if a == nil {
		return nil
	}
	if !ValidSelection(a.Package) || !ValidDigest(a.NativeAcceptanceDigest) || !ValidTime(a.IntentAt) || a.IntentAt > floor || a.CompletedAt != 0 && (a.CompletedAt < a.IntentAt || a.CompletedAt > floor) {
		return ErrIntegrity
	}
	if a.Offset < 0 || a.Offset > a.Package.Size || a.Offset != a.Package.Size && a.Offset%MaxChunkBytes != 0 || !ValidDigest(a.PrefixDigest) || a.Offset == 0 && a.PrefixDigest != Digest(nil) || a.Offset > 0 && !ValidDigest(a.LastChunkDigest) || a.Offset == 0 && a.LastChunkDigest != "" || a.PendingDigest == "" && (a.PendingIndex != 0 || a.PendingSize != 0) || a.PendingDigest != "" && (!ValidDigest(a.PendingDigest) || a.PendingIndex >= MaxChunks || int64(a.PendingIndex)*MaxChunkBytes != a.Offset || a.PendingSize != int(min(int64(MaxChunkBytes), a.Package.Size-a.Offset)) || a.PendingSize <= 0) || a.CompletedAt != 0 && (a.Offset != a.Package.Size || a.PrefixDigest != a.Package.SHA256 || a.PendingDigest != "") {
		return ErrIntegrity
	}
	return nil
}
func ArtifactTransition(before, after *Artifact) error {
	if before != nil {
		if after == nil {
			return ErrConsumed
		}
		a, b := *before, *after
		if a.Package != b.Package || a.NativeAcceptanceDigest != b.NativeAcceptanceDigest || a.IntentAt != b.IntentAt || a.CompletedAt != 0 && a != b {
			return ErrConsumed
		}
		if a.Offset == b.Offset {
			if a.PrefixDigest != b.PrefixDigest || a.LastChunkDigest != b.LastChunkDigest || a.PendingDigest != "" && (a.PendingIndex != b.PendingIndex || a.PendingDigest != b.PendingDigest || a.PendingSize != b.PendingSize) {
				return ErrConsumed
			}
		} else {
			if a.PendingDigest == "" || b.Offset != a.Offset+int64(a.PendingSize) || b.LastChunkDigest != a.PendingDigest || b.PendingDigest != "" {
				return ErrConsumed
			}
		}
	}
	return nil
}
func (r ArtifactRecord) Validate() error {
	if r.Version != ArtifactRecordVersion || !ValidTime(r.ClockFloor) || r.Artifact.Validate(r.ClockFloor) != nil {
		return ErrIntegrity
	}
	return nil
}
func ArtifactIdentity(a Artifact) string {
	raw, _ := json.Marshal(struct {
		Package                Selection `json:"package"`
		NativeAcceptanceDigest string    `json:"nativeAcceptanceDigest"`
	}{a.Package, a.NativeAcceptanceDigest})
	return Digest(raw)
}
func BindingDigest(b Binding) string { raw, _ := json.Marshal(b); return Digest(raw) }
func DecodeArtifactRecord(raw []byte) (ArtifactRecord, error) {
	var r ArtifactRecord
	if Canonical(raw, &r, MaxRecordBytes) != nil || r.Validate() != nil {
		return ArtifactRecord{}, ErrIntegrity
	}
	return r, nil
}

type ArtifactStore interface {
	WindowsManagedMSIArtifactTransaction(context.Context, ed25519.PublicKey, time.Time, func(*ArtifactRecord, time.Time) error) (ArtifactRecord, error)
	ReadWindowsManagedMSIArtifact(context.Context, ed25519.PublicKey) (ArtifactRecord, error)
	WindowsManagedMSIFleetBindings(context.Context, ed25519.PublicKey) ([]Binding, error)
}
