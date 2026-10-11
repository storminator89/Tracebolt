package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"time"
)

func (s *Service) InitializeWindowsEventContent(ctx context.Context) error {
	if s == nil || s.serviceState == nil || s.windowsEvents == nil {
		return ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windowsEventsInitialized {
		return nil
	}
	if err := s.store.InitializeWindowsEventContent(ctx); err != nil {
		return err
	}
	// Session ownership is memory-only. No old pending/claimed work is exposed
	// after process restart. Accepted digest receipts remain retryable without text.
	if err := s.store.MaintainWindowsEventContent(ctx, s.Now().UTC(), true); err != nil {
		return err
	}
	s.windowsEventsInitialized = true
	return nil
}
func (s *Service) WindowsEventCache() *windowseventcache.Cache {
	if s == nil || s.serviceState == nil {
		return nil
	}
	return s.windowsEvents
}
func (s *Service) ReportWindowsEventCapability(ctx context.Context, device, cert string, c windowseventwire.Capability, now time.Time) (windowseventwire.Capability, error) {
	if s.WindowsEventCache() == nil {
		return windowseventwire.Capability{}, ErrConfiguration
	}
	return s.windowsEvents.ReportCapability(ctx, device, cert, c, now)
}
func (s *Service) PeekWindowsEventRequest(ctx context.Context, device, cert string, now time.Time) (*windowseventrequest.Description, error) {
	if s.WindowsEventCache() == nil {
		return nil, ErrConfiguration
	}
	return s.windowsEvents.Peek(ctx, device, cert, now)
}
func (s *Service) ClaimWindowsEventRequest(ctx context.Context, device, cert string, c windowseventwire.Claim, now time.Time) (windowseventwire.Grant, error) {
	if s.WindowsEventCache() == nil {
		return windowseventwire.Grant{}, ErrConfiguration
	}
	return s.windowsEvents.Claim(ctx, device, cert, c, now)
}
func (s *Service) AcceptWindowsEventResult(ctx context.Context, device, cert string, r windowseventwire.Result, now time.Time) (windowseventrequest.Receipt, error) {
	if s.WindowsEventCache() == nil {
		return windowseventrequest.Receipt{}, ErrConfiguration
	}
	return s.windowsEvents.Accept(ctx, device, cert, r, now)
}
func (s *Service) ReportWindowsEventStatus(ctx context.Context, device, cert string, r windowseventwire.StatusInput, now time.Time) error {
	if s.WindowsEventCache() == nil {
		return ErrConfiguration
	}
	return s.windowsEvents.ReportStatus(ctx, device, cert, r, now)
}
func (s *Service) MaintainWindowsEventContent(ctx context.Context, now time.Time) error {
	if s.WindowsEventCache() == nil {
		return ErrConfiguration
	}
	return s.windowsEvents.Maintain(ctx, now)
}
func (s *Service) CloseWindowsEventContent() {
	if s.WindowsEventCache() != nil {
		s.windowsEvents.Close()
	}
}
func (s *Service) CreateWindowsEventRequest(ctx context.Context, device string, owner windowseventcache.Owner, floor uint64, generation, digest string, selections []windowseventrequest.Selection, now time.Time) (windowseventrequest.Description, error) {
	if s.WindowsEventCache() == nil {
		return windowseventrequest.Description{}, ErrConfiguration
	}
	return s.windowsEvents.Create(ctx, device, owner, floor, generation, digest, selections, now)
}
func (s *Service) CancelWindowsEventRequest(ctx context.Context, device string, owner windowseventcache.Owner, id windowseventrequest.Identity, now time.Time) error {
	if s.WindowsEventCache() == nil {
		return ErrConfiguration
	}
	return s.windowsEvents.Cancel(ctx, device, owner, id, now)
}
func (s *Service) WindowsEventContentStatus(ctx context.Context, device string, owner windowseventcache.Owner, now time.Time) (enrollmentstore.WindowsEventStatus, string, error) {
	if s.WindowsEventCache() == nil {
		return enrollmentstore.WindowsEventStatus{}, "unavailable", ErrConfiguration
	}
	return s.windowsEvents.Status(ctx, device, owner, now)
}
func (s *Service) WindowsEventContentQuery(ctx context.Context, device string, owner windowseventcache.Owner, id windowseventrequest.Identity, now time.Time) (windowseventcache.Page, error) {
	if s.WindowsEventCache() == nil {
		return windowseventcache.Page{}, ErrConfiguration
	}
	return s.windowsEvents.Query(ctx, device, owner, id, now)
}
