package lanclient

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/windowsaction"
	"testing"
)

func TestWindowsActionRelayV2DoesNotPromoteLegacyQueryConsent(t *testing.T) {
	old := WindowsActionRelayGrant{Version: "tracebolt.windows-service-action-relay.v1"}
	raw, _ := json.Marshal(old)
	if bytes.Contains(raw, []byte("provisionDigest")) || bytes.Contains(raw, []byte("brokerImageDigest")) || !validWindowsActionRelayVersion(old) {
		t.Fatal("legacy bytes changed")
	}
	modern := old
	modern.Version = "tracebolt.windows-service-action-relay.v2"
	if validWindowsActionRelayVersion(modern) {
		t.Fatal("v2 inferred missing approval")
	}
	modern.ProvisionDigest = windowsaction.Digest([]byte("plan"))
	modern.BrokerImageDigest = windowsaction.Digest([]byte("image"))
	if !validWindowsActionRelayVersion(modern) {
		t.Fatal("fresh grant rejected")
	}
	modern.Version = old.Version
	if validWindowsActionRelayVersion(modern) {
		t.Fatal("v1 promoted to query grant")
	}
}
