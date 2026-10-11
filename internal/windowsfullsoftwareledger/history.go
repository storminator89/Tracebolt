package windowsfullsoftwareledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsfullsoftware"
	"time"
)

// History reserves a fixed 1 MiB inside existing software/global ceilings.
// Comparison work cannot consume any additional storage reservation or prevent
// promotion merely because the complete difference is too large to retain.
type History struct {
	Consent        windowsfullsoftware.Consent            `json:"consent"`
	Comparison     *windowsfullsoftware.HistoryComparison `json:"comparison"`
	GapCount       uint64                                 `json:"gapCount"`
	OmittedChanges uint64                                 `json:"omittedChanges"`
	ExpiredChanges uint64                                 `json:"expiredChanges"`
	Changes        []windowsfullsoftware.HistoryChange    `json:"changes"`
}

func ResetHistory(ctx context.Context, tx Transaction, device string, c windowsfullsoftware.Consent) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM wfw_history WHERE device=?`, device); e != nil {
		return ErrStorage
	}
	if !c.Enabled || c.HistoryScope == "" {
		return nil
	}
	return SaveHistory(ctx, tx, device, History{Consent: c, Changes: []windowsfullsoftware.HistoryChange{}})
}
func SaveHistory(ctx context.Context, tx Transaction, device string, h History) error {
	raw, e := json.Marshal(h)
	if e != nil || len(raw) > windowsfullsoftware.MaxHistoryBytes || ValidateHistory(h) != nil {
		return ErrStorage
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO wfw_history VALUES(?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body`, device, raw); e != nil {
		return ErrStorage
	}
	return nil
}
func LoadHistory(ctx context.Context, tx Transaction, device string, c windowsfullsoftware.Consent) (History, error) {
	var raw []byte
	if e := tx.QueryRowContext(ctx, `SELECT body FROM wfw_history WHERE device=?`, device).Scan(&raw); e != nil {
		return History{}, ErrStorage
	}
	var h History
	if len(raw) > windowsfullsoftware.MaxHistoryBytes || json.Unmarshal(raw, &h) != nil || h.Consent != c || ValidateHistory(h) != nil {
		return History{}, ErrStorage
	}
	canonical, _ := json.Marshal(h)
	if !bytes.Equal(raw, canonical) {
		return History{}, ErrStorage
	}
	return h, nil
}
func ValidateHistory(h History) error {
	if windowsfullsoftware.ValidateConsent(h.Consent) != nil || !h.Consent.Enabled || h.Consent.HistoryScope != windowsfullsoftware.HistoryScope || h.Changes == nil || len(h.Changes) > windowsfullsoftware.MaxHistoryRows || h.GapCount > windowsfullsoftware.MaxSequence || h.OmittedChanges > windowsfullsoftware.MaxSequence || h.ExpiredChanges > windowsfullsoftware.MaxSequence {
		return ErrStorage
	}
	seen := map[string]bool{}
	for _, c := range h.Changes {
		if !windowsfullsoftware.ValidHex(c.ID, 64) || seen[c.ID] || !windowsfullsoftware.ValidHex(c.RegistrationID, 64) || (c.RegistryView != "32" && c.RegistryView != "64") || !windowsfullsoftware.ValidTime(c.BeforeObservedAt) || !windowsfullsoftware.ValidTime(c.AfterObservedAt) || !windowsfullsoftware.ValidTime(c.ExpiresAt) || c.BeforeObservedAt.Before(h.Consent.ChangedAt) || c.AfterObservedAt.Before(c.BeforeObservedAt) || c.ExpiresAt.After(c.BeforeObservedAt.Add(windowsfullsoftware.HistoryRetention)) || c.ExpiresAt.Before(c.BeforeObservedAt.Add(windowsfullsoftware.HistoryRetention-windowsfullsoftware.CaptureTimeout)) || c.ChangedFields == nil {
			return ErrStorage
		}
		seen[c.ID] = true
		for _, r := range []*windowsfullsoftware.Row{c.Before, c.After} {
			if r != nil && (windowsfullsoftware.ValidateRow(*r) != nil || r.RegistrationID != c.RegistrationID || r.RegistryView != c.RegistryView) {
				return ErrStorage
			}
		}
		switch c.Kind {
		case "registration_added":
			if c.Before != nil || c.After == nil || len(c.ChangedFields) != 0 {
				return ErrStorage
			}
		case "registration_removed":
			if c.Before == nil || c.After != nil || len(c.ChangedFields) != 0 {
				return ErrStorage
			}
		case "metadata_changed":
			if c.Before == nil || c.After == nil {
				return ErrStorage
			}
			expected := []string{}
			for _, f := range []struct {
				name string
				a, b *string
			}{{"name", c.Before.Name, c.After.Name}, {"version", c.Before.Version, c.After.Version}, {"publisher", c.Before.Publisher, c.After.Publisher}} {
				if f.a != nil && f.b != nil && *f.a != *f.b {
					expected = append(expected, f.name)
				}
			}
			a, _ := json.Marshal(expected)
			b, _ := json.Marshal(c.ChangedFields)
			if len(expected) == 0 || !bytes.Equal(a, b) {
				return ErrStorage
			}
		default:
			return ErrStorage
		}
	}
	if h.Comparison != nil {
		c := h.Comparison
		if !windowsfullsoftware.ValidTime(c.AfterObservedAt) || c.AfterObservedAt.Before(h.Consent.ChangedAt) || !windowsfullsoftware.ValidTime(c.ExpiresAt) || c.ObservedChanges < 0 || c.ObservedChanges > 2*windowsfullsoftware.MaxRows {
			return ErrStorage
		}
		if c.BeforeObservedAt != nil && (!windowsfullsoftware.ValidTime(*c.BeforeObservedAt) || c.BeforeObservedAt.Before(h.Consent.ChangedAt) || c.AfterObservedAt.Before(*c.BeforeObservedAt)) {
			return ErrStorage
		}
		original := c.AfterObservedAt
		if c.BeforeObservedAt != nil {
			original = *c.BeforeObservedAt
		}
		if c.ExpiresAt.After(original.Add(windowsfullsoftware.HistoryRetention)) || c.ExpiresAt.Before(original.Add(windowsfullsoftware.HistoryRetention-windowsfullsoftware.CaptureTimeout)) {
			return ErrStorage
		}
		switch c.Status {
		case "baseline":
			if c.Reason != "no_baseline" || c.BeforeObservedAt != nil || c.ObservedChanges != 0 {
				return ErrStorage
			}
		case "compared":
			if c.Reason != "" || c.BeforeObservedAt == nil {
				return ErrStorage
			}
		case "gap":
			if c.Reason != "source_gap" && c.Reason != "incomparable" && c.Reason != "resource_limit" {
				return ErrStorage
			}
		default:
			return ErrStorage
		}
	}
	return nil
}
func addCount(a uint64, b int) uint64 {
	if uint64(b) > windowsfullsoftware.MaxSequence-a {
		return windowsfullsoftware.MaxSequence
	}
	return a + uint64(b)
}
func PruneHistory(h *History, now time.Time) bool {
	changed := false
	rows := make([]windowsfullsoftware.HistoryChange, 0, len(h.Changes))
	for _, c := range h.Changes {
		if now.Before(c.ExpiresAt) {
			rows = append(rows, c)
		} else {
			h.ExpiredChanges = addCount(h.ExpiredChanges, 1)
			changed = true
		}
	}
	h.Changes = rows
	if h.Comparison != nil && !now.Before(h.Comparison.ExpiresAt) {
		h.Comparison = nil
		changed = true
	}
	return changed
}
func HistoryDigest(h History) string {
	raw, _ := json.Marshal(h)
	return windowsfullsoftware.Hash(append([]byte("tracebolt.windows-software-history.snapshot.v1\x00"), raw...))
}

// ObserveHistory is called exactly once at validated final promotion, before
// the previous complete generation becomes garbage. Retries never duplicate it.
func ObserveHistory(ctx context.Context, tx Transaction, m windowsfullsoftware.Message, r Record, newRows []windowsfullsoftware.Row, now time.Time) error {
	if r.Consent.HistoryScope == "" {
		return nil
	}
	h, e := LoadHistory(ctx, tx, m.DeviceID, r.Consent)
	if e != nil {
		return e
	}
	PruneHistory(&h, now)
	after := *m.Manifest
	comparison := windowsfullsoftware.HistoryComparison{Status: "baseline", Reason: "no_baseline", AfterObservedAt: after.CaptureFinishedAt, ExpiresAt: after.CaptureStartedAt.Add(windowsfullsoftware.HistoryRetention)}
	if r.Current != "" {
		old, e := LoadGeneration(ctx, tx, m.DeviceID, r.Current)
		if e != nil {
			return e
		}
		// An expired complete capture is no longer retained comparison authority.
		if now.Before(old.Manifest.ExpiresAt) {
			comparison.BeforeObservedAt = &old.Manifest.CaptureFinishedAt
			comparison.ExpiresAt = old.Manifest.CaptureStartedAt.Add(windowsfullsoftware.HistoryRetention)
			comparison.Status = "gap"
			comparison.Reason = "incomparable"
			comparable := old.State == "current" && old.NextRow == old.Manifest.RowCount && old.NextChunk == old.Manifest.ChunkCount && !old.CompletedAt.IsZero() && old.Manifest.GrantID == r.Consent.GrantID && old.Manifest.GrantRevision == r.Consent.Revision && old.Manifest.SenderBinding == r.Consent.SenderBinding && !old.Manifest.CaptureStartedAt.Before(r.Consent.ChangedAt) && !after.CaptureStartedAt.Before(r.Consent.ChangedAt) && !after.CaptureStartedAt.Before(old.Manifest.CaptureFinishedAt)
			if !comparable {
				comparison.BeforeObservedAt = nil
				comparison.ExpiresAt = after.CaptureStartedAt.Add(windowsfullsoftware.HistoryRetention)
			}
			if comparable && after.Sequence != old.Manifest.Sequence+1 {
				comparison.Reason = "source_gap"
			} else if comparable {
				if e = verifyCompleteRows(ctx, tx, m.DeviceID, old); e != nil {
					return e
				}
				oldRows, e := ReadRows(ctx, tx, m.DeviceID, r.Current)
				if e != nil {
					return e
				}
				changes, count, diffErr := windowsfullsoftware.DiffHistory(old.Manifest, after, oldRows, newRows)
				comparison.ObservedChanges = count
				if diffErr != nil && !errors.Is(diffErr, windowsfullsoftware.ErrBudget) {
					comparison.Reason = "incomparable"
				} else {
					candidate := h
					candidate.Comparison = &comparison
					candidate.Changes = append(append([]windowsfullsoftware.HistoryChange{}, h.Changes...), changes...)
					raw, _ := json.Marshal(candidate)
					if diffErr != nil || len(candidate.Changes) > windowsfullsoftware.MaxHistoryRows || len(raw) > windowsfullsoftware.MaxHistoryBytes-4096 {
						comparison.Reason = "resource_limit"
						h.OmittedChanges = addCount(h.OmittedChanges, count)
					} else {
						comparison.Status = "compared"
						comparison.Reason = ""
						h.Changes = candidate.Changes
					}
				}
			}
			if comparison.Status == "gap" {
				h.GapCount = addCount(h.GapCount, 1)
			}
		}
	}
	h.Comparison = &comparison
	return SaveHistory(ctx, tx, m.DeviceID, h)
}
