package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"time"
)

func (s *Service) InitializeWindowsHistory(ctx context.Context) error {
	if s == nil || s.serviceState == nil || s.windowsHistory == nil {
		return ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windowsHistoryInitialized {
		return nil
	}
	if err := s.store.InitializeWindowsHistory(ctx); err != nil {
		return err
	}
	// Session ownership is memory-only. No old pending/claimed work is exposed
	// after process restart. Accepted digest receipts remain retryable without text.
	if err := s.store.MaintainWindowsHistory(ctx, s.Now().UTC(), true); err != nil {
		return err
	}
	s.windowsHistoryInitialized = true
	return nil
}
func (s *Service) WindowsHistoryCache() *windowshistorycache.Cache {
	if s == nil || s.serviceState == nil {
		return nil
	}
	return s.windowsHistory
}
func (s *Service) ReportWindowsHistoryCapability(ctx context.Context, device, cert string, c windowshistorywire.Capability, now time.Time) (windowshistorywire.Capability, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistorywire.Capability{}, ErrConfiguration
	}
	return s.windowsHistory.ReportCapability(ctx, device, cert, c, now)
}
func (s *Service) PeekWindowsHistoryRequest(ctx context.Context, device, cert string, now time.Time) (*windowshistoryrequest.Description, error) {
	if s.WindowsHistoryCache() == nil {
		return nil, ErrConfiguration
	}
	return s.windowsHistory.Peek(ctx, device, cert, now)
}
func (s *Service) ClaimWindowsHistoryRequest(ctx context.Context, device, cert string, c windowshistorywire.Claim, now time.Time) (windowshistorywire.Grant, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistorywire.Grant{}, ErrConfiguration
	}
	return s.windowsHistory.Claim(ctx, device, cert, c, now)
}
func (s *Service) AcceptWindowsHistoryResult(ctx context.Context, device, cert string, r windowshistorywire.Result, now time.Time) (windowshistoryrequest.Receipt, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistoryrequest.Receipt{}, ErrConfiguration
	}
	return s.windowsHistory.Accept(ctx, device, cert, r, now)
}
func (s *Service) ReportWindowsHistoryStatus(ctx context.Context, device, cert string, r windowshistorywire.StatusInput, now time.Time) error {
	if s.WindowsHistoryCache() == nil {
		return ErrConfiguration
	}
	return s.windowsHistory.ReportStatus(ctx, device, cert, r, now)
}
func (s *Service) MaintainWindowsHistory(ctx context.Context, now time.Time) error {
	if s.WindowsHistoryCache() == nil {
		return ErrConfiguration
	}
	return s.windowsHistory.Maintain(ctx, now)
}
func (s *Service) CloseWindowsHistory() {
	if s.WindowsHistoryCache() != nil {
		s.windowsHistory.Close()
	}
}
func (s *Service) CreateWindowsHistorySearch(ctx context.Context, device string, owner windowshistorycache.Owner, floor uint64, search windowseventhistory.Search, now time.Time) (windowshistoryrequest.Description, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistoryrequest.Description{}, ErrConfiguration
	}
	return s.windowsHistory.CreateSearch(ctx, device, owner, floor, search, now)
}
func (s *Service) CreateWindowsHistoryMessages(ctx context.Context, device string, owner windowshistorycache.Owner, floor uint64, receipt windowshistoryrequest.Receipt, selections []windowshistoryrequest.Selection, now time.Time) (windowshistoryrequest.Description, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistoryrequest.Description{}, ErrConfiguration
	}
	return s.windowsHistory.CreateMessages(ctx, device, owner, floor, receipt, selections, now)
}
func (s *Service) CancelWindowsHistoryRequest(ctx context.Context, device string, owner windowshistorycache.Owner, id windowshistoryrequest.Identity, now time.Time) error {
	if s.WindowsHistoryCache() == nil {
		return ErrConfiguration
	}
	return s.windowsHistory.Cancel(ctx, device, owner, id, now)
}
func (s *Service) WindowsHistoryStatus(ctx context.Context, device string, owner windowshistorycache.Owner, now time.Time) (enrollmentstore.WindowsHistoryStatus, string, error) {
	if s.WindowsHistoryCache() == nil {
		return enrollmentstore.WindowsHistoryStatus{}, "unavailable", ErrConfiguration
	}
	return s.windowsHistory.Status(ctx, device, owner, now)
}
func (s *Service) WindowsHistoryQuery(ctx context.Context, device string, owner windowshistorycache.Owner, id windowshistoryrequest.Identity, now time.Time) (windowshistorycache.Page, error) {
	if s.WindowsHistoryCache() == nil {
		return windowshistorycache.Page{}, ErrConfiguration
	}
	return s.windowsHistory.Query(ctx, device, owner, id, now)
}
