package agentloop

import "testing"

func TestCompleteUpdatesMetadataIsBoundedAndContentFree(t *testing.T) {
	for _, status := range []string{"disabled", "not_due", "pending_retained", "acknowledged", "failure_acknowledged", "aborted"} {
		if !valid(Result{Outcome: Success, Metadata: Metadata{CachedUpdatesStatus: status, CachedUpdatesSequence: 1, CachedUpdatesOperations: 64}}) {
			t.Fatal("valid update status rejected", status)
		}
	}
	for _, m := range []Metadata{{CachedUpdatesStatus: "raw package name"}, {CachedUpdatesStatus: "acknowledged"}, {CachedUpdatesOperations: 1}, {CachedUpdatesStatus: "pending_retained", CachedUpdatesOperations: 65}} {
		if valid(Result{Outcome: Success, Metadata: m}) {
			t.Fatal("unsafe update metadata accepted")
		}
	}
}
