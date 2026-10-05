package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestLocalTelemetryRejectsOperatorCertificateMetadata(t *testing.T) {
	now := time.Now().UTC()
	raw := sample(t, now)
	if strings.Contains(string(raw), "agentCertificate") {
		t.Fatal("existing endpoint wire shape changed")
	}
	if _, err := decodeBundle(raw, now); err != nil {
		t.Fatal("unchanged endpoint bundle rejected")
	}
	for _, field := range []any{nil, map[string]any{}, map[string]any{"source": "manual-approval", "expiresAt": now.Add(time.Hour).Format(time.RFC3339), "checkedAt": now.Format(time.RFC3339)}} {
		injected := edit(t, raw, func(value map[string]any) { obs(value)["agentCertificate"] = field })
		if _, err := decodeBundle(injected, now); err == nil {
			t.Fatal("endpoint supplied operator certificate metadata")
		}
	}
}
