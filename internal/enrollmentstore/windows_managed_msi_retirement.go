package enrollmentstore

import (
	"context"
	"database/sql"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"sort"
)

// All registered references are checked in the same enrollment transaction.
// Revoked/offline targets with unresolved work still block payload retirement.
func validateMSIArtifactRetirement(ctx context.Context, c *sql.Conn, before, after msi.ArtifactRecord) error {
	if before.Artifact == nil || before.Version != msi.ReusableArtifactRecordVersion {
		return msi.ErrAuthority
	}
	rows, e := c.QueryContext(ctx, `SELECT body FROM enrollment_windows_managed_msi_records ORDER BY invitation_id`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	var evidence []string
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			return ErrStorage
		}
		r, e := msi.DecodeRecord(raw)
		if e != nil {
			return ErrStorage
		}
		if r.Artifact == nil || msi.ArtifactIdentity(*r.Artifact) != msi.ArtifactIdentity(*before.Artifact) {
			continue
		}
		if len(r.RetiredReport) == 0 {
			return msi.ErrUncertain
		}
		evidence = append(evidence, msi.BindingDigest(r.Grant.Binding)+":"+msi.Digest(r.RetiredReport))
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	sort.Strings(evidence)
	raw, _ := json.Marshal(evidence)
	if after.RetirementEvidenceDigest != msi.Digest(raw) {
		return msi.ErrConflict
	}
	return nil
}
