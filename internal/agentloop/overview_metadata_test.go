package agentloop

import "testing"

func TestOverviewMetadataFixedStatusesAndCombinedBudget(t *testing.T) {
	for _, status := range []string{"not_due", "pending_retained", "disabled", "acknowledged", "failure_acknowledged", "aborted"} {
		r := Result{Outcome: Success, Metadata: Metadata{ProcessesStatus: status, ProcessesSequence: 1, VolumesStatus: status, VolumesSequence: 1, OverviewOperations: 64}}
		if !valid(r) {
			t.Fatal("valid overview metadata rejected", status)
		}
		r.Metadata.OverviewOperations = 65
		if valid(r) {
			t.Fatal("unbounded burst accepted")
		}
	}
	for _, m := range []Metadata{{ProcessesStatus: "raw source detail"}, {VolumesStatus: "acknowledged"}, {ProcessesSequence: 1}, {VolumesSequence: 1}, {OverviewOperations: 1}} {
		if valid(Result{Outcome: Success, Metadata: m}) {
			t.Fatal("invalid overview metadata")
		}
	}
}
