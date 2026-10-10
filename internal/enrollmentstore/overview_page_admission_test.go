package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/overviewledger"
	"reflect"
	"testing"
	"time"
)

// Only invented rows and the disposable store fixture are used. Holding the
// shared inventory slot reproduces expected page backpressure without a native
// collector, manager process, maintenance race or change to production admission.
func TestCompleteOverviewPageSharedAdmissionBackpressure(t *testing.T) {
	_, store, _, snapshot, certificate := overviewFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	binding, manifest, chunks := overviewGeneration(t, snapshot.Approval.DeviceID, 1, 3, at)
	promoteOverview(t, store, snapshot, certificate, binding, manifest, chunks, at)
	query := overviewledger.PageRequest{Section: "processes", GenerationID: binding.GenerationID, Limit: 100}
	before, err := store.OverviewPage(ctx, snapshot.Approval.DeviceID, query, at)
	if err != nil || len(before.Items) != 3 || !before.Exhausted {
		t.Fatal("overview_page_fixture_invalid")
	}
	release, err := store.inventoryAdmission(ctx)
	if err != nil {
		t.Fatal("overview_page_fixture_admission_failed")
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	page, err := store.OverviewPage(ctx, snapshot.Approval.DeviceID, query, at)
	if !errors.Is(err, ErrOverviewBusy) || ctx.Err() != nil || !reflect.DeepEqual(page, OverviewPageResult{}) {
		t.Fatal("overview_page_expected_bounded_busy")
	}
	release()
	release = nil
	after, err := store.OverviewPage(ctx, snapshot.Approval.DeviceID, query, at)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("overview_page_released_admission_changed_generation")
	}
}
