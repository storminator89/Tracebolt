package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"time"
)

// JournalCache is wired once at manager construction to the same-store ingress.
// It is process memory only; New never loads content from durable state.
func (s *Service) JournalCache() *journalcache.Cache {
	if s == nil || s.serviceState == nil {
		return nil
	}
	return s.journal
}
func (s *Service) CreateJournalRequest(ctx context.Context, device string, floor uint64, q journalview.Query, now time.Time) (journalrequest.Description, error) {
	if s.JournalCache() == nil {
		return journalrequest.Description{}, ErrConfiguration
	}
	return s.journal.Create(ctx, device, floor, q, now)
}
func (s *Service) CancelJournalRequest(ctx context.Context, device string, id journalrequest.Identity, now time.Time) error {
	if s.JournalCache() == nil {
		return ErrConfiguration
	}
	return s.journal.Cancel(ctx, device, id, now)
}
func (s *Service) JournalStatus(ctx context.Context, device string, now time.Time) (journalrequest.Status, string, error) {
	if s.JournalCache() == nil {
		return journalrequest.Status{}, "unknown", ErrConfiguration
	}
	return s.journal.Status(ctx, device, now)
}
func (s *Service) JournalPage(ctx context.Context, device string, q journalcache.PageRequest, now time.Time) (journalcache.Page, error) {
	if s.JournalCache() == nil {
		return journalcache.Page{}, ErrConfiguration
	}
	return s.journal.Page(ctx, device, q, now)
}

func (s *Service) CreateJournalRequestWithGeneration(ctx context.Context, device string, floor uint64, q journalview.Query, expected journalgeneration.Tuple, now time.Time) (journalrequest.Description, error) {
	if s.JournalCache() == nil {
		return journalrequest.Description{}, ErrConfiguration
	}
	return s.journal.CreateWithGeneration(ctx, device, floor, q, expected, now)
}
func (s *Service) JournalGenerationStatus(ctx context.Context, device string, now time.Time) (*enrollmentstore.JournalGenerationView, error) {
	if s == nil || s.serviceState == nil || s.store == nil {
		return nil, ErrConfiguration
	}
	return s.store.JournalGenerationStatus(ctx, device, now)
}
