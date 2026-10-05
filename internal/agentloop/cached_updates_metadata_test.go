package agentloop

import "testing"

func TestExtensionConsentWithdrawalStatusRemainsBounded(t *testing.T) {
	for _, status := range []string{"cached_updates_disabled", "endpoint_identity_disabled"} {
		if !valid(Result{Outcome: Success, Metadata: Metadata{SystemStatus: status, SystemSequence: 1}}) {
			t.Fatal("valid consumed extension withdrawal rejected", status)
		}
		if valid(Result{Outcome: Success, Metadata: Metadata{SystemStatus: status}}) {
			t.Fatal("withdrawal missing consumed sequence accepted", status)
		}
	}
	if valid(Result{Outcome: Success, Metadata: Metadata{SystemStatus: "raw package diagnostic", SystemSequence: 1}}) {
		t.Fatal("unbounded status accepted")
	}
}
