package rustcompat

import (
	"encoding/json"
	"testing"
)

func TestExactPublicContract(t *testing.T) {
	raw, err := json.Marshal(Expected("https://manager.example", "https://agent.example", true))
	const want = `{"schemaVersion":"tracebolt.rust-basic-manager-capabilities.v1","enrollmentProtocol":"tracebolt.enrollment.v2","collectionProfile":"windows-inventory-v1","agentProfile":"rust-windows-basic-v1","telemetryFrame":"tracebolt.agent-telemetry.windows.v1","receiptSchema":"tracebolt.agent-receipt.v1","enrollmentOrigin":"https://manager.example","agentOrigin":"https://agent.example","automaticRegistration":true}`
	if err != nil || string(raw) != want || len(raw) > 2048 {
		t.Fatal("public contract changed")
	}
}
