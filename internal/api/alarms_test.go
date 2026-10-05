package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAlarmStatusAuthenticationReadOnlyAndRedaction(t *testing.T) {
	o, _ := namedOperatorFixture(t)
	if r, _ := o.call(t, "GET", "/api/alerts/status", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous alarm status")
	}
	_, login := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	r, view := o.call(t, "GET", "/api/alerts/status", nil, "", nil)
	if r.StatusCode != 200 || view["enabled"] != false || view["schemaVersion"] != "tracebolt.alarm-status.v1" {
		t.Fatal(r.StatusCode, view)
	}
	raw, _ := json.Marshal(view)
	for _, s := range []string{"endpoint", "token", "fingerprint", "destination", "managerInstance"} {
		if strings.Contains(string(raw), s) {
			t.Fatal("private alarm configuration in status")
		}
	}
	if r, _ = o.call(t, "POST", "/api/alerts/status", map[string]bool{"enabled": true}, login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named reader gained send authority")
	}
	if r, _ = o.call(t, "POST", "/api/auth/logout", map[string]any{}, login["csrfToken"].(string), nil); r.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if r, _ = o.call(t, "GET", "/api/alerts/status", nil, "", nil); r.StatusCode != 401 {
		t.Fatal("revoked status readable")
	}
	legacy := newOperatorFixture(t, 0)
	_, shared := legacy.login(t)
	if r, _ = legacy.call(t, "POST", "/api/alerts/status", map[string]any{}, shared["csrfToken"].(string), nil); r.StatusCode != 405 {
		t.Fatal("shared login gained send endpoint")
	}
}
