package windowsmanagedmsimanager

import (
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
	"strconv"
)

type artifactOccurrenceKey struct{}
type artifactReserveKey struct{}
type jobOccurrenceKey struct{}
type jobOccurrence struct {
	retiredCount uint64
	transferID   string
	sequence     uint64
}

func (m *ArtifactManager) Reusable() bool { return m != nil && m.reusable }
func (m *Manager) Reusable() bool         { return m != nil && m.artifact.Reusable() }

func occurrenceNumber(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, msi.ErrInvalid
	}
	return n, nil
}

// Pins are checked inside the same locked transaction that changes custody or
// job evidence. A preliminary content-hash lookup alone cannot bind A -> B -> A.
func WithArtifactRetiredCount(ctx context.Context, value string) (context.Context, error) {
	n, err := occurrenceNumber(value)
	if err != nil {
		return ctx, err
	}
	return msi.WithCatalogueOccurrence(context.WithValue(ctx, artifactOccurrenceKey{}, n), n), nil
}

// Initial-empty and first-retired custody both have retiredCount zero. Reserve
// therefore also pins the previously displayed artifact identity (or empty).
func WithArtifactReserveOccurrence(ctx context.Context, value, expectedArtifactID string) (context.Context, error) {
	if expectedArtifactID != "" && !msi.ValidDigest(expectedArtifactID) {
		return ctx, msi.ErrInvalid
	}
	ctx, err := WithArtifactRetiredCount(ctx, value)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, artifactReserveKey{}, expectedArtifactID), nil
}
func WithJobOccurrence(ctx context.Context, value, transfer, sequence string) (context.Context, error) {
	n, err := occurrenceNumber(value)
	seq, seqErr := occurrenceNumber(sequence)
	if err != nil || seqErr != nil || seq == 0 || !msi.ValidTransferID(transfer) {
		return ctx, msi.ErrInvalid
	}
	ctx = msi.WithCatalogueOccurrence(context.WithValue(ctx, artifactOccurrenceKey{}, n), n)
	return context.WithValue(ctx, jobOccurrenceKey{}, jobOccurrence{n, transfer, seq}), nil
}
func checkArtifactOccurrence(ctx context.Context, r msi.ArtifactRecord) error {
	if id, ok := ctx.Value(artifactReserveKey{}).(string); ok {
		current := ""
		if r.Artifact != nil {
			current = msi.ArtifactIdentity(*r.Artifact)
		}
		if current != id {
			return msi.ErrConflict
		}
	}
	if n, ok := ctx.Value(artifactOccurrenceKey{}).(uint64); ok && (!r.Reusable() || r.RetiredCount != n) {
		return msi.ErrConflict
	}
	return nil
}
func checkJobOccurrence(ctx context.Context, r msi.Record) error {
	if p, ok := ctx.Value(jobOccurrenceKey{}).(jobOccurrence); ok {
		if !r.Grant.Reusable() || r.ArtifactRetiredCount != p.retiredCount || r.TransferID != p.transferID || r.Jobs == nil || r.Jobs.Sequence != p.sequence {
			return msi.ErrConflict
		}
	}
	return nil
}
