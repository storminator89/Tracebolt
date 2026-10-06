package applicationcheck

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func configFixture() map[string]any {
	return map[string]any{"schemaVersion": ConfigSchemaVersion, "enabled": true, "managerInstanceId": "", "operatorOrigin": "https://manager.example.test:8443", "profile": "tls", "intervalSeconds": 60, "checksFromManagerAcknowledged": true, "targets": []any{map[string]any{"id": "app", "url": "https://app.example.test/status", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false, "plaintextHTTPAcknowledged": false}}}
}
func targetFixture(f map[string]any) map[string]any { return f["targets"].([]any)[0].(map[string]any) }
func writeConfig(t *testing.T, raw []byte) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("protected file support is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "checks.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write")
	}
	return path
}
func loadFixture(t *testing.T, f map[string]any) (Config, error) {
	t.Helper()
	raw, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	return Load(writeConfig(t, raw), "", "https://manager.example.test:8443", "tls")
}
func TestApplicationConfigOmittedDisabledAndBinding(t *testing.T) {
	c, e := Load("", "", "", "")
	if e != nil || c.Enabled() {
		t.Fatal("default not inert")
	}
	c, e = Load(writeConfig(t, []byte(`{"schemaVersion":"tracebolt.application-checks-config.v1","enabled":false}`)), "", "", "")
	if e != nil || c.Enabled() {
		t.Fatal("disabled invalid")
	}
	c, e = loadFixture(t, configFixture())
	if e != nil || !c.Enabled() || c.interval != time.Minute || !c.Matches("", "https://manager.example.test:8443", "tls") {
		t.Fatal("valid configuration rejected")
	}
	if c.Matches("other", "https://manager.example.test:8443", "tls") || c.Matches("", "https://other.example.test:8443", "tls") || c.Matches("", "https://manager.example.test:8443", "http-test") {
		t.Fatal("binding ignored")
	}
	f := configFixture()
	f["managerInstanceId"] = "manager-fixture"
	raw, _ := json.Marshal(f)
	if _, e := Load(writeConfig(t, raw), "manager-fixture", "https://manager.example.test:8443", "tls"); e != nil {
		t.Fatal("enrolled binding rejected")
	}
}
func TestApplicationConfigStrictBoundsAndConsent(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"disabled with targets", func(f map[string]any) { f["enabled"] = false }},
		{"missing enabled", func(f map[string]any) { delete(f, "enabled") }},
		{"missing consent", func(f map[string]any) { delete(f, "checksFromManagerAcknowledged") }},
		{"false consent", func(f map[string]any) { f["checksFromManagerAcknowledged"] = false }},
		{"origin", func(f map[string]any) { f["operatorOrigin"] = "https://other.example.test" }},
		{"profile", func(f map[string]any) { f["profile"] = "http-test" }},
		{"manager", func(f map[string]any) { f["managerInstanceId"] = "other" }},
		{"quick cadence", func(f map[string]any) { f["intervalSeconds"] = 59 }},
		{"slow cadence", func(f map[string]any) { f["intervalSeconds"] = 3601 }},
		{"fraction cadence", func(f map[string]any) { f["intervalSeconds"] = 60.5 }},
		{"null", func(f map[string]any) { f["targets"] = nil }},
		{"empty targets", func(f map[string]any) { f["targets"] = []any{} }},
		{"many targets", func(f map[string]any) {
			targets := []any{}
			for i := 0; i < 9; i++ {
				v := targetFixture(configFixture())
				v["id"] = fmt.Sprintf("app-%d", i)
				targets = append(targets, v)
			}
			f["targets"] = targets
		}},
		{"duplicate ids", func(f map[string]any) { f["targets"] = []any{targetFixture(f), targetFixture(configFixture())} }},
		{"missing private choice", func(f map[string]any) { delete(targetFixture(f), "allowPrivateLAN") }},
		{"missing plaintext choice", func(f map[string]any) { delete(targetFixture(f), "plaintextHTTPAcknowledged") }},
		{"unknown field", func(f map[string]any) { targetFixture(f)["method"] = "POST" }},
		{"bad id", func(f map[string]any) { targetFixture(f)["id"] = "private endpoint.example" }},
		{"null address", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []any{nil} }},
		{"empty addresses", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []string{} }},
		{"many addresses", func(f map[string]any) {
			a := []string{}
			for i := 1; i <= 17; i++ {
				a = append(a, fmt.Sprintf("8.8.8.%d", i))
			}
			targetFixture(f)["allowedAddresses"] = a
		}},
		{"duplicate addresses", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []string{"8.8.8.8", "8.8.8.8"} }},
		{"address host", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []string{"app.example.test"} }},
		{"mapped configured address", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []string{"::ffff:8.8.8.8"} }},
		{"private without consent", func(f map[string]any) { targetFixture(f)["allowedAddresses"] = []string{"10.1.2.3"} }},
		{"literal mismatch", func(f map[string]any) { targetFixture(f)["url"] = "https://1.1.1.1/status" }},
		{"credentials", func(f map[string]any) { targetFixture(f)["url"] = "https://u:p@app.example.test/status" }},
		{"query", func(f map[string]any) { targetFixture(f)["url"] = "https://app.example.test/status?token=x" }},
		{"fragment", func(f map[string]any) { targetFixture(f)["url"] = "https://app.example.test/status#secret" }},
		{"https ack", func(f map[string]any) { targetFixture(f)["plaintextHTTPAcknowledged"] = true }},
		{"http missing ack", func(f map[string]any) { targetFixture(f)["url"] = "http://app.example.test/status" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := configFixture()
			tc.mutate(f)
			if _, e := loadFixture(t, f); e != ErrConfiguration {
				t.Fatal("bad configuration accepted or diagnostic not static")
			}
		})
	}
	raw, _ := json.Marshal(configFixture())
	for _, bad := range []string{
		strings.Replace(string(raw), `"enabled":true`, `"enabled":true,"enabled":false`, 1),
		strings.Replace(string(raw), `"enabled":true`, `"Enabled":true`, 1),
		strings.Replace(string(raw), `"id":"app"`, `"id":"app","id":"other"`, 1),
		strings.Replace(string(raw), `"id":"app"`, `"ID":"app"`, 1),
		strings.Replace(string(raw), `"allowPrivateLAN":false`, `"allowPrivateLAN":null`, 1),
		string(raw) + ` {}`,
	} {
		if _, e := Load(writeConfig(t, []byte(bad)), "", "https://manager.example.test:8443", "tls"); e != ErrConfiguration {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
func TestApplicationConfigTargetTransportIndependent(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		f := configFixture()
		f["profile"] = profile
		origin := "https://manager.example.test:8443"
		if profile == "http-test" {
			origin = "http://manager.example.test:8443"
		}
		f["operatorOrigin"] = origin
		targetFixture(f)["url"] = "http://app.example.test:8080/status"
		targetFixture(f)["plaintextHTTPAcknowledged"] = true
		raw, _ := json.Marshal(f)
		if _, e := Load(writeConfig(t, raw), "", origin, profile); e != nil {
			t.Fatal("acknowledged HTTP target tied to manager profile")
		}
		targetFixture(f)["url"] = "https://app.example.test/status"
		targetFixture(f)["plaintextHTTPAcknowledged"] = false
		raw, _ = json.Marshal(f)
		if _, e := Load(writeConfig(t, raw), "", origin, profile); e != nil {
			t.Fatal("HTTPS target tied to manager profile")
		}
	}
	f := configFixture()
	targetFixture(f)["allowedAddresses"] = []string{"10.1.2.3", "fd00:1234::1"}
	targetFixture(f)["allowPrivateLAN"] = true
	if _, e := loadFixture(t, f); e != nil {
		t.Fatal("explicit private LAN denied")
	}
}
func TestApplicationConfigProtectedAndRedacted(t *testing.T) {
	raw, _ := json.Marshal(configFixture())
	path := writeConfig(t, raw)
	c, e := Load(path, "", "https://manager.example.test:8443", "tls")
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []any{c, &c} {
		b, _ := json.Marshal(v)
		if string(b) != `{"redacted":true}` {
			t.Fatal("JSON config leak")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, "example.test") || strings.Contains(s, "8.8.8.8") {
				t.Fatal("format leak")
			}
		}
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("fixture chmod")
	}
	if _, e := Load(path, "", "https://manager.example.test:8443", "tls"); e != ErrConfiguration {
		t.Fatal("shared configuration accepted")
	}
	path = writeConfig(t, raw)
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture link")
	}
	if _, e := Load(link, "", "https://manager.example.test:8443", "tls"); e != ErrConfiguration {
		t.Fatal("symlink accepted")
	}
	if _, e := Load(writeConfig(t, []byte(strings.Repeat(" ", 32769))), "", "", ""); e != ErrConfiguration {
		t.Fatal("oversized accepted")
	}
}
func TestApplicationDestinationPermanentExclusions(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "127.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.0.192", "192.0.2.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "ff02::1", "2001:db8::1", "2002:0808:0808::1", "64:ff9b::808:808", "168.63.129.16", "fd00:ec2::254", "fd20:ce::254", "::ffff:127.0.0.1"} {
		if allowedAddress(netip.MustParseAddr(s), true) {
			t.Fatalf("special address admitted: %s", s)
		}
	}
	for _, s := range []string{"10.2.3.4", "172.16.1.1", "192.168.1.1", "fd12:3456::1"} {
		ip := netip.MustParseAddr(s)
		if allowedAddress(ip, false) || !allowedAddress(ip, true) {
			t.Fatal("private consent policy")
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !allowedAddress(netip.MustParseAddr(s), false) {
			t.Fatal("public address rejected")
		}
	}
	if allowedAddress(netip.MustParseAddr("fe80::1%eth0"), true) || allowedAddress(netip.Addr{}, true) {
		t.Fatal("zone/invalid accepted")
	}
}
func TestApplicationURLGrammar(t *testing.T) {
	for _, s := range []string{"ftp://app.example.test", "https://app.example.test/%2fsecret", "https://app.example.test/a/../b", "https://app.example.test//b", "https://app.example.test:0", "https://app.example.test:65536", "https://app.example.test:0443", "https://APP.example.test", "https://app.example.test.", "https://[::ffff:8.8.8.8]", "https://[fe80::1%25eth0]", "https://app.example.test/\n", "https://app.example.test/é", "https://app.example.test/?", "https://app.example.test:"} {
		if _, e := parseURL(s, "tls", false); e == nil {
			t.Fatalf("bad URL accepted: %q", s)
		}
	}
	for _, s := range []string{"https://singlelabel/status", "https://app.example.test/status", "https://8.8.8.8:8443/status", "https://[2606:4700:4700::1111]/status"} {
		if _, e := parseURL(s, "tls", false); e != nil {
			t.Fatal("valid HTTPS URL rejected")
		}
	}
}
