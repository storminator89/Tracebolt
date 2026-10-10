package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/applicationcheck"
)

// The initial DNS/TCP fixture has exactly these public fields and values. Only
// serverNow varies, and it must still be a canonical UTC timestamp. Comparing
// the decoded contract rejects private keys, nested objects, and target values
// injected into public fields. Scanning raw JSON for a bare port number instead
// incorrectly rejects legitimate fractional timestamp digits.
func applicationChecksV2InitialStatusIsPublic(v map[string]any) bool {
	serverNow, ok := v["serverNow"].(string)
	if !ok {
		return false
	}
	now, err := time.Parse(time.RFC3339Nano, serverNow)
	if err != nil || now.UTC().Format(time.RFC3339Nano) != serverNow {
		return false
	}
	return reflect.DeepEqual(v, map[string]any{
		"schemaVersion":   applicationcheck.SchemaVersionV2,
		"enabled":         true,
		"vantage":         "management_server",
		"serverNow":       serverNow,
		"intervalSeconds": float64(60),
		"maxAgeSeconds":   float64(75),
		"items": []any{
			map[string]any{"kind": "dns", "id": "resolution", "state": "unknown", "reason": "not_checked", "observedAt": nil},
			map[string]any{"kind": "tcp", "id": "connection", "state": "unknown", "reason": "not_checked", "observedAt": nil},
		},
	})
}

// Marshal the real public types and decode in the same way as operatorFixture.call.
func applicationChecksV2PublicStatusFixture(t *testing.T, now time.Time) map[string]any {
	t.Helper()
	view := applicationcheck.View{
		SchemaVersion: applicationcheck.SchemaVersionV2,
		Enabled:       true, Vantage: "management_server", ServerNow: now,
		IntervalSeconds: 60, MaxAgeSeconds: 75,
		Items: []applicationcheck.Result{
			{Kind: "dns", ID: "resolution", State: "unknown", Reason: "not_checked"},
			{Kind: "tcp", ID: "connection", State: "unknown", Reason: "not_checked"},
		},
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal("public status fixture serialization failed")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal("public status fixture decoding failed")
	}
	return decoded
}

func TestApplicationChecksV2StatusPrivacyAllowsTimestampDigits(t *testing.T) {
	for _, nanos := range []int{0, 543200000, 125432678} {
		view := applicationChecksV2PublicStatusFixture(t, time.Date(2026, 10, 10, 8, 43, 0, nanos, time.UTC))
		if nanos != 0 && !strings.Contains(view["serverNow"].(string), "5432") {
			t.Fatal("timestamp collision regression fixture lacks target port digits")
		}
		if !applicationChecksV2InitialStatusIsPublic(view) {
			t.Fatal("privacy assertion rejected a legitimate public timestamp")
		}
	}
}

func TestApplicationChecksV2StatusPrivacyRejectsConfiguration(t *testing.T) {
	now := time.Date(2026, 10, 10, 8, 43, 0, 125432678, time.UTC)
	privateFields := map[string]any{
		"host": "private-fixture.internal", "port": float64(5432),
		"url":              "https://private-fixture.internal:5432/status",
		"allowedAddresses": []any{"10.2.3.4"}, "allowPrivateLAN": true,
		"operatorOrigin": "https://manager.example", "managerInstanceId": "private-manager",
		"profile": "tls", "checksFromManagerAcknowledged": true,
		"targets": []any{map[string]any{"host": "10.2.3.4", "port": float64(5432)}},
	}
	// No configuration field is allowed at the top level or in either row,
	// including null-valued fields that a map lookup alone would miss.
	for key, value := range privateFields {
		for _, injected := range []any{value, nil} {
			for position := 0; position < 3; position++ {
				view := applicationChecksV2PublicStatusFixture(t, now)
				object := view
				if position > 0 {
					object = view["items"].([]any)[position-1].(map[string]any)
				}
				object[key] = injected
				if applicationChecksV2InitialStatusIsPublic(view) {
					t.Fatal("privacy assertion accepted a private configuration field")
				}
			}
		}
	}
	// A key-only allowlist is insufficient: actual host, address, and port
	// values must also be rejected when substituted into any public field.
	privateValues := []any{
		"private-fixture.internal", "10.2.3.4", "5432", float64(5432),
		"10.2.3.4:5432", map[string]any{"port": float64(5432)},
		[]any{map[string]any{"allowedAddresses": []any{"10.2.3.4"}}},
	}
	for _, value := range privateValues {
		for position := 0; position < 3; position++ {
			baseline := applicationChecksV2PublicStatusFixture(t, now)
			object := baseline
			if position > 0 {
				object = baseline["items"].([]any)[position-1].(map[string]any)
			}
			for key := range object {
				view := applicationChecksV2PublicStatusFixture(t, now)
				mutated := view
				if position > 0 {
					mutated = view["items"].([]any)[position-1].(map[string]any)
				}
				mutated[key] = value
				if applicationChecksV2InitialStatusIsPublic(view) {
					t.Fatal("privacy assertion accepted a private value in a public field")
				}
			}
		}
	}
}

func TestApplicationChecksV2StatusPrivacyRejectsMalformedShape(t *testing.T) {
	now := time.Date(2026, 10, 10, 8, 43, 0, 125432678, time.UTC)
	for position := 0; position < 3; position++ {
		baseline := applicationChecksV2PublicStatusFixture(t, now)
		object := baseline
		if position > 0 {
			object = baseline["items"].([]any)[position-1].(map[string]any)
		}
		for key := range object {
			view := applicationChecksV2PublicStatusFixture(t, now)
			mutated := view
			if position > 0 {
				mutated = view["items"].([]any)[position-1].(map[string]any)
			}
			delete(mutated, key)
			if applicationChecksV2InitialStatusIsPublic(view) {
				t.Fatal("public status assertion accepted a missing field")
			}
		}
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["items"] = []any{} },
		func(v map[string]any) { v["items"] = v["items"].([]any)[:1] },
		func(v map[string]any) { v["items"] = append(v["items"].([]any), v["items"].([]any)[0]) },
		func(v map[string]any) { v["items"].([]any)[1] = v["items"].([]any)[0] },
		func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["httpStatus"] = nil },
		func(v map[string]any) { v["items"].([]any)[1].(map[string]any)["tls"] = nil },
		func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["targetScheme"] = "https" },
		func(v map[string]any) {
			v["items"].([]any)[1].(map[string]any)["observedAt"] = now.Format(time.RFC3339Nano)
		},
		func(v map[string]any) { v["items"].([]any)[0].(map[string]any)["state"] = "ok" },
		func(v map[string]any) { v["items"].([]any)[1].(map[string]any)["reason"] = "stale" },
		func(v map[string]any) { v["enabled"] = false },
		func(v map[string]any) { v["serverNow"] = "2026-13-10T08:43:00.5432Z" },
		func(v map[string]any) { v["serverNow"] = "2026-10-10T08:43:00.5432Z private-fixture.internal" },
		func(v map[string]any) { v["serverNow"] = "2026-10-10T08:43:00.5432+01:00" },
	} {
		view := applicationChecksV2PublicStatusFixture(t, now)
		mutate(view)
		if applicationChecksV2InitialStatusIsPublic(view) {
			t.Fatal("public status assertion accepted malformed shape or evidence")
		}
	}
}
