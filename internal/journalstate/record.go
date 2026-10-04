package journalstate

import (
	"bytes"
	"encoding/json"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalrequest"
)

// This deliberately has no query, result, snapshot, body or free-text member.
type diskRecord struct {
	Version       string `json:"version"`
	SenderBinding string `json:"senderBinding"`
	Sequence      uint64 `json:"sequence"`
	QueryID       string `json:"queryId"`
	QueryDigest   string `json:"queryDigest"`
	PolicyDigest  string `json:"policyDigest"`
	ExpiresAt     string `json:"expiresAt"`
}

func encodeRecord(r diskRecord) ([]byte, error) {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) == 0 || len(raw) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	return raw, nil
}
func decodeRecord(raw []byte) (diskRecord, error) {
	var r diskRecord
	if len(raw) == 0 || len(raw) > MaxStateBytes || json.Unmarshal(raw, &r) != nil {
		return r, ErrCorrupt
	}
	// Native canonical JSON only: reject unknown/missing/duplicate/case-folded
	// fields, null scalars, invalid UTF-8, number aliases and any trailing bytes.
	canonical, e := encodeRecord(r)
	if e != nil || !bytes.Equal(canonical, raw) || r.Version != Version || !validBinding(r.SenderBinding) {
		return r, ErrCorrupt
	}
	if r.Sequence == 0 {
		if r.QueryID != "" || r.QueryDigest != "" || r.PolicyDigest != "" || r.ExpiresAt != "" {
			return r, ErrCorrupt
		}
	} else {
		expires, e := time.Parse(time.RFC3339Nano, r.ExpiresAt)
		if !enrollmentcrypto.ValidID(r.QueryID, "journal_") || !journalrequest.ValidDigest(r.QueryDigest) || !journalrequest.ValidDigest(r.PolicyDigest) || e != nil || expires.Location() != time.UTC || expires.Unix() <= 0 || expires.Year() > 9999 || expires.Format(time.RFC3339Nano) != r.ExpiresAt {
			return r, ErrCorrupt
		}
	}
	return r, nil
}
