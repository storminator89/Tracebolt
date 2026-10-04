package agentloop

import "testing"

func TestInventoryMetadataIsFixedBoundedAndOptional(t *testing.T) {
	for _, status := range []string{"", "not_due", "pending_retained", "acknowledged", "failure_acknowledged", "aborted"} {
		r := Result{Outcome: Success}
		if status != "" {
			r.Metadata.InventoryStatus = status
			r.Metadata.InventorySequence = 1
			r.Metadata.InventoryOperations = 64
		}
		if !valid(r) {
			t.Fatal("known fixed inventory metadata rejected")
		}
	}
	for _, m := range []Metadata{{InventoryStatus: "private diagnostic"}, {InventoryStatus: "pending_retained", InventoryOperations: 65}, {InventorySequence: 1}, {InventoryOperations: 1}, {InventoryStatus: "acknowledged"}, {InventoryStatus: "failure_acknowledged"}, {InventoryStatus: "aborted"}} {
		if valid(Result{Outcome: Success, Metadata: m}) {
			t.Fatal("invalid inventory status escaped fixed metadata boundary")
		}
	}
}
