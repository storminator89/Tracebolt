package enrollmentservice

import (
	"context"
	"errors"
	"localrmm/internal/overviewledger"
	"testing"
	"time"
)

func TestCompleteOverviewServiceRequiresStore(t *testing.T) {
	for _, s := range []*Service{nil, {}} {
		if _, err := s.CompleteOverviewView(context.Background(), "agent_00000000000000000000000000000001", time.Now().UTC()); !errors.Is(err, ErrConfiguration) {
			t.Fatal("missing store returned success", err)
		}
		if _, err := s.CompleteOverviewPage(context.Background(), "agent_00000000000000000000000000000001", overviewledger.PageRequest{Section: "processes", Limit: 100}, time.Now().UTC()); !errors.Is(err, ErrConfiguration) {
			t.Fatal("missing store query returned success", err)
		}
	}
}
