package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	"testing"
	"time"
)

func TestConditionalReviewOperationalReadBusyHasFixedRetryContract(t *testing.T) {
	s, _ := reviewEnabled(t)
	s.lanPackages = func(context.Context, string, time.Time) (enrollmentstore.PackageView, error) {
		return enrollmentstore.PackageView{}, enrollmentstore.ErrOperationalBusy
	}
	w, _ := reviewResponse(t, s)
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" {
		t.Fatal("shared read pressure lacks bounded retry contract")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatal("invalid fixed error response")
	}
	var detail map[string]string
	if len(body) != 1 || json.Unmarshal(body["error"], &detail) != nil || len(detail) != 2 || detail["code"] != "storage_busy" || detail["message"] != "Stored package observations are busy; retry shortly." {
		t.Fatal("shared read pressure misclassified")
	}
	if _, ok := body["review"]; ok {
		t.Fatal("busy response exposed review data")
	}
}
