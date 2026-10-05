package alarmdelivery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func webhookConfigFixture() map[string]any {
	return map[string]any{
		"schemaVersion": ConfigSchemaVersion, "enabled": true, "payloadSharingAcknowledged": true,
		"managerInstanceId": "manager-fixture", "profile": "tls", "destinationId": "primary", "generation": "generation-1",
		"endpoint": "https://receiver.example.test/hooks/fixture-only?key=fixture-endpoint-marker",
	}
}

func writeWebhookConfig(t *testing.T, values map[string]any) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("protected file support is Linux-only")
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal("marshal fixture")
	}
	path := filepath.Join(t.TempDir(), "delivery.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("write fixture")
	}
	return path
}

func loadWebhookFixture(t *testing.T) Config {
	t.Helper()
	c, err := Load(writeWebhookConfig(t, webhookConfigFixture()), "manager-fixture", "tls")
	if err != nil {
		t.Fatal("valid protected configuration rejected")
	}
	return c
}

func TestWebhookDefaultOff(t *testing.T) {
	c, err := Load("", "", "")
	if err != nil || c.Enabled() || c.Binding().Valid() {
		t.Fatal("omitted configuration must be inert")
	}
	transport, err := NewWebhook(c)
	if err != nil {
		t.Fatal("disabled constructor")
	}
	w := transport.(*webhook)
	w.resolve = nil
	w.dialTLS = nil
	if got := w.Send(context.Background(), Payload{}); got != (Result{Failed, "disabled"}) {
		t.Fatal("disabled sender attempted work")
	}
	c, err = Load(writeWebhookConfig(t, map[string]any{"schemaVersion": ConfigSchemaVersion, "enabled": false}), "", "")
	if err != nil || c.Enabled() {
		t.Fatal("minimal disabled configuration rejected")
	}
	f := webhookConfigFixture()
	f["enabled"] = false
	f["payloadSharingAcknowledged"] = false
	f["bearerTokenFile"] = filepath.Join(t.TempDir(), "deliberately-absent")
	c, err = Load(writeWebhookConfig(t, f), "manager-fixture", "tls")
	if err != nil || c.Enabled() || c.bearer != "" {
		t.Fatal("disabled configuration read bearer material")
	}
}

func TestWebhookConfigRequiresExplicitBoundConsent(t *testing.T) {
	c := loadWebhookFixture(t)
	if !c.Enabled() || !c.Binding().Valid() {
		t.Fatal("valid configuration not enabled and bound")
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"no enabled", func(f map[string]any) { delete(f, "enabled") }},
		{"no consent", func(f map[string]any) { delete(f, "payloadSharingAcknowledged") }},
		{"false consent", func(f map[string]any) { f["payloadSharingAcknowledged"] = false }},
		{"different manager", func(f map[string]any) { f["managerInstanceId"] = "other-manager" }},
		{"different profile", func(f map[string]any) { f["profile"] = "http-test" }},
		{"missing destination", func(f map[string]any) { delete(f, "destinationId") }},
		{"missing generation", func(f map[string]any) { delete(f, "generation") }},
		{"missing endpoint", func(f map[string]any) { delete(f, "endpoint") }},
		{"relative token", func(f map[string]any) { f["bearerTokenFile"] = "token" }},
		{"unclean token", func(f map[string]any) { f["bearerTokenFile"] = "/tmp/../token" }},
		{"unknown", func(f map[string]any) { f["retryUncertain"] = true }},
		{"null", func(f map[string]any) { f["generation"] = nil }},
		{"wrong type", func(f map[string]any) { f["enabled"] = "true" }},
		{"disabled malformed", func(f map[string]any) { f["enabled"] = false; f["endpoint"] = "http://receiver.example.test" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := webhookConfigFixture()
			tc.mutate(f)
			if _, err := Load(writeWebhookConfig(t, f), "manager-fixture", "tls"); err != ErrConfiguration {
				t.Fatal("invalid configuration accepted or diagnostic not static")
			}
		})
	}
	for _, raw := range []string{
		`{"schemaVersion":"tracebolt.alarm-delivery-config.v1","enabled":false,"enabled":true}`,
		`{"schemaVersion":"tracebolt.alarm-delivery-config.v1","Enabled":false}`,
		`{"schemaVersion":"tracebolt.alarm-delivery-config.v1","enabled":false} {}`,
		`{"schemaVersion":"tracebolt.alarm-delivery-config.v1","enabled":false,"endpoint":[]}`,
	} {
		path := writeWebhookConfig(t, webhookConfigFixture())
		if os.WriteFile(path, []byte(raw), 0600) != nil {
			t.Fatal("write fixture")
		}
		if _, err := Load(path, "manager-fixture", "tls"); err != ErrConfiguration {
			t.Fatal("ambiguous configuration accepted")
		}
	}
}

func TestWebhookProtectedFilesAndTokenSnapshot(t *testing.T) {
	f := webhookConfigFixture()
	tokenFile := filepath.Join(t.TempDir(), "bearer")
	if os.WriteFile(tokenFile, []byte("fixture-bearer-marker\n"), 0600) != nil {
		t.Fatal("write token fixture")
	}
	f["bearerTokenFile"] = tokenFile
	path := writeWebhookConfig(t, f)
	c, err := Load(path, "manager-fixture", "tls")
	if err != nil || c.bearer != "fixture-bearer-marker" {
		t.Fatal("protected bearer fixture rejected")
	}
	if os.WriteFile(tokenFile, []byte("rotated-fixture-only"), 0600) != nil {
		t.Fatal("rotate fixture")
	}
	rotated, err := Load(path, "manager-fixture", "tls")
	if err != nil || c.Binding() != rotated.Binding() || c.bearer == rotated.bearer || c.bearer != "fixture-bearer-marker" {
		t.Fatal("credential rotation changed routing or old snapshot")
	}
	for _, value := range []any{c, &c} {
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"redacted":true}` {
			t.Fatal("configuration JSON not redacted")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			for _, marker := range []string{"receiver.example.test", "fixture-endpoint-marker", "fixture-bearer-marker", tokenFile} {
				if strings.Contains(output, marker) {
					t.Fatal("configuration diagnostic exposed private material")
				}
			}
		}
	}
	if os.Chmod(tokenFile, 0644) != nil {
		t.Fatal("fixture permission")
	}
	if _, err := Load(path, "manager-fixture", "tls"); err != ErrConfiguration {
		t.Fatal("shared bearer file accepted")
	}
	if os.Chmod(tokenFile, 0600) != nil || os.Chmod(path, 0644) != nil {
		t.Fatal("fixture permission")
	}
	if _, err := Load(path, "manager-fixture", "tls"); err != ErrConfiguration {
		t.Fatal("shared endpoint configuration accepted")
	}
	if os.Chmod(path, 0600) != nil {
		t.Fatal("fixture permission")
	}
	symlink := filepath.Join(t.TempDir(), "config-link")
	if os.Symlink(path, symlink) != nil {
		t.Fatal("symlink fixture")
	}
	if _, err := Load(symlink, "manager-fixture", "tls"); err != ErrConfiguration {
		t.Fatal("symlink config accepted")
	}
	if os.Remove(tokenFile) != nil || os.Symlink(path, tokenFile) != nil {
		t.Fatal("token symlink fixture")
	}
	if _, err := Load(path, "manager-fixture", "tls"); err != ErrConfiguration {
		t.Fatal("symlink token accepted")
	}
}

func TestWebhookFingerprintBindsExactDestination(t *testing.T) {
	original := loadWebhookFixture(t).Binding().Fingerprint
	for _, key := range []string{"managerInstanceId", "profile", "destinationId", "generation", "endpoint"} {
		t.Run(key, func(t *testing.T) {
			f := webhookConfigFixture()
			if key == "profile" {
				f[key] = "http-test"
			} else {
				f[key] = f[key].(string) + "-changed"
			}
			c, err := Load(writeWebhookConfig(t, f), f["managerInstanceId"].(string), f["profile"].(string))
			if err != nil || c.Binding().Fingerprint == original {
				t.Fatal("routing identity change not bound")
			}
		})
	}
}

func TestWebhookEndpointAndBearerGrammar(t *testing.T) {
	for _, raw := range []string{"https://receiver.example.test", "https://receiver.example.test:443/hook?x=fixture", "https://8.8.8.8/hook", "https://[2606:4700:4700::1111]/hook"} {
		if _, err := parseWebhookEndpoint(raw); err != nil {
			t.Fatal("valid exact HTTPS endpoint rejected")
		}
	}
	for _, raw := range []string{
		"", "http://receiver.example.test/hook", "https://fixture@receiver.example.test/hook", "https://receiver.example.test/#fragment", "https://receiver.example.test/#", "https://receiver.example.test:8443", "https://receiver.example.test:", "https://receiver.example.test:0443", "https://RECEIVER.example.test", "https://receiver.example.test.", "https://localhost", "https://127.0.0.1/hook", "https://192.0.2.1/hook", "https://[::1]/hook", "https://[::ffff:127.0.0.1]/hook", "https://[fe80::1%25eth0]/hook", "https://receiver.example.test/with space", "https://receiver.example.test/\\path", "https://receiver.example.test/%zz", "https://receiver.example.test\r\n/header", "https://-bad.example.test", "https://bad-.example.test", "https://receiver..example.test",
	} {
		if _, err := parseWebhookEndpoint(raw); err != ErrConfiguration {
			t.Fatal("unsafe or ambiguous endpoint accepted")
		}
	}
	for _, s := range []string{"fixture-only", "abc.DEF_123~+/=="} {
		if !validBearer(s) {
			t.Fatal("valid bearer rejected")
		}
	}
	for _, s := range []string{"", "=", "a=b", "two words", "foo\nbar", "token\r", "foo:bar", strings.Repeat("a", 4097)} {
		if validBearer(s) {
			t.Fatal("invalid bearer accepted")
		}
	}
}
