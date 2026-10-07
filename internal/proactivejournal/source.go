// Package proactivejournal coordinates bounded, explicitly approved journal reads.
// It neither grants local helper permissions nor contacts a model provider.
package proactivejournal

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"time"
)

const DataScope = "service-journal-ai-v1"
const MaxTargets = 8
const MaxRows = 10
const MaxAnalysesPerHour = 2
const Cooldown = 30 * time.Minute

var ErrScope = errors.New("journal_ai_scope_invalid")
var ErrUnavailable = errors.New("journal_ai_source_unavailable")
var ErrOccupied = errors.New("journal_ai_manual_request_active")
var ErrChanged = errors.New("journal_ai_policy_changed")
var ErrPending = errors.New("journal_ai_capture_pending")

type Source interface {
	Now() time.Time
	JournalStatus(context.Context, string, time.Time) (journalrequest.Status, string, error)
	JournalGenerationStatus(context.Context, string, time.Time) (*enrollmentstore.JournalGenerationView, error)
	CreateJournalRequestWithGeneration(context.Context, string, uint64, journalview.Query, journalgeneration.Tuple, time.Time) (journalrequest.Description, error)
	CancelJournalRequest(context.Context, string, journalrequest.Identity, time.Time) error
	JournalPage(context.Context, string, journalcache.PageRequest, time.Time) (journalcache.Page, error)
}
type Target struct {
	DeviceID   string                  `json:"deviceId"`
	Unit       string                  `json:"unit"`
	Generation journalgeneration.Tuple `json:"generation"`
}

// Capture is metadata only. An ambiguous creation is never adopted or repeated.
type Capture struct {
	Description journalrequest.Description `json:"description"`
}

func ValidUnit(unit string) bool {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return journalview.ValidateQuery(journalview.Query{Unit: unit, Start: now.Add(-time.Minute), End: now, MaxPriority: 4}, now) == nil
}
func PermittedGeneration(v *enrollmentstore.JournalGenerationView, unit string, now time.Time) bool {
	if v == nil || v.SchemaVersion != "tracebolt.journal-generation-view.v2" || !v.Fresh || !now.Before(v.ExpiresAt) || v.PolicyEnabled == nil || !*v.PolicyEnabled || v.AllowedUnits == nil || journalgeneration.Validate(v.PolicyGeneration) != nil || journalgeneration.ValidateServiceAuthorization(v.ServiceAuthorization, *v.AllowedUnits) != nil || !ValidUnit(unit) {
		return false
	}
	if v.ServiceAuthorization == journalgeneration.AllSystemServices {
		return true
	}
	if v.ServiceAuthorization != journalgeneration.ExactUnits {
		return false
	}
	for _, allowed := range *v.AllowedUnits {
		if allowed == unit {
			return true
		}
	}
	return false
}
func CheckTarget(ctx context.Context, s Source, t Target, now time.Time) error {
	if journalgeneration.Validate(t.Generation) != nil || !ValidUnit(t.Unit) {
		return ErrScope
	}
	v, err := s.JournalGenerationStatus(ctx, t.DeviceID, now)
	if err != nil || !PermittedGeneration(v, t.Unit, s.Now().UTC()) {
		return ErrUnavailable
	}
	if v.PolicyGeneration != t.Generation {
		return ErrChanged
	}
	return nil
}

// CheckCapture is the final source authorization boundary after page/packet
// preparation. Policy and exact accepted content must both remain current.
func CheckCapture(ctx context.Context, s Source, t Target, c Capture, digest string, now time.Time) error {
	d := c.Description
	if d.DeviceID != t.DeviceID || d.Query.Unit != t.Unit || d.PolicyGeneration != t.Generation || !journalrequest.ValidDigest(digest) || !now.Before(d.ExpiresAt) {
		return ErrChanged
	}
	if err := CheckTarget(ctx, s, t, now); err != nil {
		return err
	}
	status, _, err := s.JournalStatus(ctx, t.DeviceID, s.Now().UTC())
	at := s.Now().UTC()
	if err != nil || ctx.Err() != nil || at.Before(now) || !at.Before(d.ExpiresAt) || status.Description != d || status.State != journalrequest.Accepted || status.ContentStatus != "available" || status.Receipt == nil || status.Receipt.Identity != d.Identity || status.Receipt.ExpiresAt != d.ExpiresAt || status.Receipt.ResultDigest != digest {
		return ErrChanged
	}
	return nil
}
func Begin(ctx context.Context, s Source, t Target, openedAt time.Time, minutes int, now time.Time) (Capture, error) {
	if minutes != 5 && minutes != 15 {
		return Capture{}, ErrScope
	}
	if err := CheckTarget(ctx, s, t, now); err != nil {
		return Capture{}, err
	}
	current, _, err := s.JournalStatus(ctx, t.DeviceID, s.Now().UTC())
	floor := uint64(0)
	if err == nil {
		floor = current.Description.Identity.Sequence
		// An automatic request never replaces live operator work, even an accepted
		// snapshot someone may still be paging. Original expiry is not extended.
		if current.State != journalrequest.Canceled && current.State != journalrequest.Expired && s.Now().UTC().Before(current.Description.ExpiresAt) {
			return Capture{}, ErrOccupied
		}
	} else if !errors.Is(err, journalrequest.ErrNotFound) {
		return Capture{}, ErrUnavailable
	}
	at := s.Now().UTC()
	end := openedAt.UTC().Truncate(time.Microsecond)
	q := journalview.Query{Unit: t.Unit, Start: end.Add(-time.Duration(minutes) * time.Minute), End: end, MaxPriority: 4}
	if journalview.ValidateQuery(q, at) != nil || at.Before(now) || at.Sub(now) > 5*time.Second {
		return Capture{}, ErrScope
	}
	if err := CheckTarget(ctx, s, t, at); err != nil {
		return Capture{}, err
	}
	d, err := s.CreateJournalRequestWithGeneration(ctx, t.DeviceID, floor, q, t.Generation, s.Now().UTC())
	if err != nil {
		return Capture{}, ErrUnavailable
	}
	if d.DeviceID != t.DeviceID || d.Query != q || d.PolicyGeneration != t.Generation || d.SchemaVersion != journalrequest.SchemaVersionV2 || d.Identity.Sequence != floor+1 || d.Budgets != journalrequest.FixedBudgets() || !s.Now().UTC().Before(d.ExpiresAt) {
		return Capture{}, ErrChanged
	}
	return Capture{Description: d}, nil
}
func Read(ctx context.Context, s Source, t Target, c Capture, now time.Time) (journalcache.Page, error) {
	d := c.Description
	if d.DeviceID != t.DeviceID || d.Query.Unit != t.Unit || d.PolicyGeneration != t.Generation || !now.Before(d.ExpiresAt) {
		return journalcache.Page{}, ErrChanged
	}
	if err := CheckTarget(ctx, s, t, now); err != nil {
		return journalcache.Page{}, err
	}
	status, _, err := s.JournalStatus(ctx, t.DeviceID, s.Now().UTC())
	if err != nil || status.Description != d {
		return journalcache.Page{}, ErrChanged
	}
	if status.State == journalrequest.Pending || status.State == journalrequest.Claimed {
		return journalcache.Page{}, ErrPending
	}
	if status.State != journalrequest.Accepted || status.Receipt == nil || status.ContentStatus != "available" {
		return journalcache.Page{}, ErrUnavailable
	}
	page, err := s.JournalPage(ctx, t.DeviceID, journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: status.Receipt.ResultDigest, Search: "", Offset: 0, Limit: MaxRows}, s.Now().UTC())
	if err != nil {
		return journalcache.Page{}, ErrUnavailable
	}
	if page.Identity != d.Identity || page.Query != d.Query || page.ExpiresAt != d.ExpiresAt || page.SnapshotDigest != status.Receipt.ResultDigest || page.Offset != 0 || len(page.Rows) > MaxRows || page.Coverage == journalview.Failed || !s.Now().UTC().Before(page.ExpiresAt) {
		return journalcache.Page{}, ErrUnavailable
	}
	if page.TotalCapturedRows > MaxRows {
		offset := page.TotalCapturedRows - MaxRows
		page, err = s.JournalPage(ctx, t.DeviceID, journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: status.Receipt.ResultDigest, Search: "", Offset: offset, Limit: MaxRows}, s.Now().UTC())
		if err != nil || page.Offset != offset || page.Identity != d.Identity || page.Query != d.Query || page.ExpiresAt != d.ExpiresAt || page.SnapshotDigest != status.Receipt.ResultDigest || len(page.Rows) > MaxRows || page.Coverage == journalview.Failed || !s.Now().UTC().Before(page.ExpiresAt) {
			return journalcache.Page{}, ErrUnavailable
		}
	}
	if err := CheckCapture(ctx, s, t, c, page.SnapshotDigest, s.Now().UTC()); err != nil {
		return journalcache.Page{}, err
	}
	return page, nil
}
func Cancel(ctx context.Context, s Source, c Capture) error {
	return s.CancelJournalRequest(ctx, c.Description.DeviceID, c.Description.Identity, s.Now().UTC())
}
