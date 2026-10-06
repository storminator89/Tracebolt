package applicationcheck

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func dnsTCPConfigFixture(kind string) map[string]any {
	f := configFixture()
	f["schemaVersion"] = ConfigSchemaVersionV2
	t := map[string]any{"kind": kind, "id": "fixture", "host": "service.internal", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false}
	if kind == kindTCP {
		t["port"] = 5432
	}
	if kind == kindHTTP {
		t = targetFixture(configFixture())
		t["kind"] = kindHTTP
	}
	f["targets"] = []any{t}
	return f
}
func TestV2ConfigPerKindAndV1Compatibility(t *testing.T) {
	for _, kind := range []string{kindHTTP, kindDNS, kindTCP} {
		c, e := loadFixture(t, dnsTCPConfigFixture(kind))
		if e != nil || c.schema != ConfigSchemaVersionV2 || len(c.targets) != 1 || c.targets[0].Kind != kind {
			t.Fatal("valid v2 target rejected", kind)
		}
		m := New(c)
		v := m.Status()
		if v.SchemaVersion != SchemaVersionV2 || v.Items[0].Kind != kind || v.Items[0].State != "unknown" {
			t.Fatal("wrong v2 initial contract")
		}
	}
	c, e := loadFixture(t, configFixture())
	if e != nil || c.schema != ConfigSchemaVersion {
		t.Fatal("v1 config changed")
	}
	v := New(c).Status()
	raw, e := json.Marshal(v.Items[0])
	if e != nil {
		t.Fatal(e)
	}
	var row map[string]any
	if json.Unmarshal(raw, &row) != nil || len(row) != 7 || row["kind"] != nil || v.SchemaVersion != SchemaVersion {
		t.Fatal("v1 row schema changed", string(raw))
	}
	f := configFixture()
	targetFixture(f)["kind"] = kindHTTP
	if _, e := loadFixture(t, f); e != ErrConfiguration {
		t.Fatal("v1 accepted kind extension")
	}
}
func TestV2ConfigDisabledPreservesSchemaAndInertState(t *testing.T) {
	raw := []byte(`{"schemaVersion":"tracebolt.application-checks-config.v2","enabled":false}`)
	c, e := Load(writeConfig(t, raw), "", "", "")
	if e != nil || c.Enabled() || c.schema != ConfigSchemaVersionV2 {
		t.Fatal("disabled v2 lost schema")
	}
	m := New(c)
	m.check = nil
	m.wait = nil
	if e := m.Run(context.Background()); e != nil {
		t.Fatal("disabled v2 ran work")
	}
	v := m.Status()
	if v.SchemaVersion != SchemaVersionV2 || v.Enabled || len(v.Items) != 0 || v.IntervalSeconds != 0 || v.MaxAgeSeconds != 0 {
		t.Fatal("disabled v2 downgraded")
	}
}
func TestV2ConfigRejectsCrossKindFieldsAndUnsafeTargets(t *testing.T) {
	cases := []struct {
		name, kind string
		change     func(map[string]any)
	}{
		{"kind missing", kindDNS, func(f map[string]any) { delete(targetFixture(f), "kind") }},
		{"kind unknown", kindDNS, func(f map[string]any) { targetFixture(f)["kind"] = "udp" }},
		{"kind alias", kindDNS, func(f map[string]any) { targetFixture(f)["Kind"] = kindDNS }},
		{"DNS literal", kindDNS, func(f map[string]any) { targetFixture(f)["host"] = "8.8.8.8" }},
		{"DNS port", kindDNS, func(f map[string]any) { targetFixture(f)["port"] = 53 }},
		{"DNS type", kindDNS, func(f map[string]any) { targetFixture(f)["recordType"] = "TXT" }},
		{"DNS resolver", kindDNS, func(f map[string]any) { targetFixture(f)["resolver"] = "8.8.8.8" }},
		{"DNS URL", kindDNS, func(f map[string]any) { targetFixture(f)["url"] = "https://service.internal" }},
		{"DNS plaintext", kindDNS, func(f map[string]any) { targetFixture(f)["plaintextHTTPAcknowledged"] = true }},
		{"TCP missing port", kindTCP, func(f map[string]any) { delete(targetFixture(f), "port") }},
		{"TCP port zero", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = 0 }},
		{"TCP port over", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = 65536 }},
		{"TCP port string", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = "5432" }},
		{"TCP port range", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = "1-65535" }},
		{"TCP port list", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = []int{80, 443} }},
		{"TCP fractional", kindTCP, func(f map[string]any) { targetFixture(f)["port"] = 5432.5 }},
		{"TCP banner", kindTCP, func(f map[string]any) { targetFixture(f)["readBanner"] = true }},
		{"TCP payload", kindTCP, func(f map[string]any) { targetFixture(f)["payload"] = "PING" }},
		{"TCP credentials", kindTCP, func(f map[string]any) { targetFixture(f)["password"] = "fixture-only" }},
		{"TCP URL", kindTCP, func(f map[string]any) { targetFixture(f)["url"] = "tcp://service.internal:5432" }},
		{"TCP TLS option", kindTCP, func(f map[string]any) { targetFixture(f)["verifyTLS"] = false }},
		{"TCP literal mismatch", kindTCP, func(f map[string]any) { targetFixture(f)["host"] = "1.1.1.1" }},
		{"HTTP host", kindHTTP, func(f map[string]any) { targetFixture(f)["host"] = "service.internal" }},
		{"HTTP port", kindHTTP, func(f map[string]any) { targetFixture(f)["port"] = 443 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := dnsTCPConfigFixture(tc.kind)
			tc.change(f)
			if _, e := loadFixture(t, f); e != ErrConfiguration {
				t.Fatal("bad kind shape accepted")
			}
		})
	}
	for _, kind := range []string{kindDNS, kindTCP} {
		for _, host := range []string{"", "*.internal", "service.internal/health", "service.internal:5432", "user@service.internal", "https://service.internal", "SERVICE.internal", "service.internal.", "service_internal", "service\ninternal", "[::1]", "fe80::1%eth0", "::ffff:8.8.8.8", "8.8.8.0/24"} {
			f := dnsTCPConfigFixture(kind)
			targetFixture(f)["host"] = host
			if _, e := loadFixture(t, f); e != ErrConfiguration {
				t.Fatal("unsafe host accepted", kind, host)
			}
		}
	}
	// Test duplicate discriminators independently of normal map serialization.
	raw := []byte(`{"schemaVersion":"tracebolt.application-checks-config.v2","enabled":true,"managerInstanceId":"","operatorOrigin":"https://manager.example.test:8443","profile":"tls","intervalSeconds":60,"checksFromManagerAcknowledged":true,"targets":[{"kind":"dns","kind":"tcp","id":"fixture","host":"service.internal","allowedAddresses":["8.8.8.8"],"allowPrivateLAN":false}]}`)
	if _, e := Load(writeConfig(t, raw), "", "https://manager.example.test:8443", "tls"); e != ErrConfiguration {
		t.Fatal("duplicate kind accepted")
	}
}
func TestV2ConfigSharedTargetBudgetAndLiteralPrivatePolicy(t *testing.T) {
	f := dnsTCPConfigFixture(kindDNS)
	f["targets"] = []any{targetFixture(dnsTCPConfigFixture(kindDNS)), targetFixture(dnsTCPConfigFixture(kindTCP))}
	if _, e := loadFixture(t, f); e != ErrConfiguration {
		t.Fatal("duplicate cross-kind IDs accepted")
	}
	targets := []any{}
	for i := 0; i < MaxTargets; i++ {
		v := targetFixture(dnsTCPConfigFixture([]string{kindDNS, kindTCP, kindHTTP}[i%3]))
		v["id"] = string(rune('a' + i))
		targets = append(targets, v)
	}
	f["targets"] = targets
	if _, e := loadFixture(t, f); e != nil {
		t.Fatal("bounded mixed list rejected")
	}
	f["targets"] = append(targets, targetFixture(dnsTCPConfigFixture(kindDNS)))
	if _, e := loadFixture(t, f); e != ErrConfiguration {
		t.Fatal("extra protocol expanded shared target budget")
	}
	for _, kind := range []string{kindDNS, kindTCP} {
		f = dnsTCPConfigFixture(kind)
		v := targetFixture(f)
		v["allowedAddresses"] = []string{"10.1.2.3"}
		if kind == kindTCP {
			v["host"] = "10.1.2.3"
		}
		if _, e := loadFixture(t, f); e != ErrConfiguration {
			t.Fatal("private target without consent")
		}
		v["allowPrivateLAN"] = true
		if _, e := loadFixture(t, f); e != nil {
			t.Fatal("explicit private target rejected")
		}
		v["allowedAddresses"] = []string{"169.254.169.254"}
		if kind == kindTCP {
			v["host"] = "169.254.169.254"
		}
		if _, e := loadFixture(t, f); e != ErrConfiguration {
			t.Fatal("private flag admitted metadata")
		}
	}
	f = dnsTCPConfigFixture(kindTCP)
	v := targetFixture(f)
	v["host"] = "2606:4700:4700::1111"
	v["port"] = 65535
	v["allowedAddresses"] = []string{"2606:4700:4700::1111"}
	if _, e := loadFixture(t, f); e != nil {
		t.Fatal("canonical IPv6 literal/port rejected")
	}
}
func TestHTTPSharedResolutionBehaviorRemainsCompatible(t *testing.T) {
	p, fixture := pipeProbe(t, nil, nil, httpResponse(200))
	p.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	target := transportTarget("http://fixture.example/status")
	target.Kind = kindHTTP
	r := p.check(transportContext(t), target, "tls", time.Now())
	if r.State != "ok" || r.HTTPStatus == nil || *r.HTTPStatus != 200 || r.TLS.State != "not_applicable" || fixture.calls.Load() != 1 {
		t.Fatal("HTTP dispatch changed")
	}
}
