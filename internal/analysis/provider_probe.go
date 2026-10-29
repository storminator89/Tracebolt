package analysis

import (
	"context"
	"time"

	"localrmm/internal/model"
)

// TestProvider performs exactly one synthetic analysis through the same
// provider, shared service slot, bounded context, packet and strict response
// validation as ordinary analysis. It transmits no case, device or user data
// from a store, and returns no model output, provider response or raw error.
// The caller must authorize and bind the exact current provider/session before
// network access and recheck them before reporting a result. A nil error means
// only that this synthetic request received a structurally valid answer; it is
// not proof of provider locality, future availability or diagnostic accuracy.
// A provider that ignores context may continue running after cancellation.
func (s *Service) TestProvider(ctx context.Context) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrUnavailable
		}
	}()
	if ctx == nil {
		return ErrUnavailable
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := model.Evidence{ID: "fixture-connectivity-observation", Title: "Synthetic connectivity fixture", Source: "synthetic-provider-test", Quality: "healthy", CollectedAt: at, Detail: "Synthetic test data only; no device observation.", Value: "fixture", Synthetic: true}
	c := model.Case{ID: "case-provider-test", Title: "Synthetic provider test", Summary: "This is a synthetic test, not a device incident.", Category: "service", RuleID: "synthetic-provider-test", RunbookID: "service", EvidenceIDs: []string{e.ID}, Evidence: []model.Evidence{e}, CreatedAt: at, UpdatedAt: at, Synthetic: true}
	value, err := s.Analyze(ctx, c, []model.Evidence{e})
	if err != nil {
		return ErrUnavailable
	}
	switch value.AI.Status {
	case "completed":
		return nil
	case "not_configured":
		return ErrNotConfigured
	case "busy":
		return ErrBusy
	case "canceled":
		return context.Canceled
	case "timeout":
		return context.DeadlineExceeded
	case "invalid_response":
		return ErrInvalidResponse
	default:
		return ErrUnavailable
	}
}
