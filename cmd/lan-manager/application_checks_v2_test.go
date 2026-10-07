//go:build linux

package main

import (
	"encoding/json"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/lanconfig"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicationChecksV2ManagerDisabledSchemaWithoutWorker(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	path := filepath.Join(t.TempDir(), "v2-disabled.json")
	if os.WriteFile(path, []byte(`{"schemaVersion":"tracebolt.application-checks-config.v2","enabled":false}`), 0600) != nil {
		t.Fatal("fixture write")
	}
	c, e := applicationcheck.Load(path, "", m.Config.OperatorOrigin, m.Config.Profile)
	if e != nil {
		t.Fatal(e)
	}
	p, e := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if p.applicationChecks == nil || p.applicationChecks.View().Mode != "external" || p.applicationChecks.Status().Enabled {
		t.Fatal("disabled v2 settings did not preserve immutable external mode")
	}
	view := readApplicationChecksPrepared(t, p, m.Config.OperatorOrigin)
	if view["schemaVersion"] != applicationcheck.SchemaVersionV2 || view["enabled"] != false || len(view["items"].([]any)) != 0 {
		t.Fatal("disabled schema lost at manager boundary")
	}
}
func TestApplicationChecksV2ManagerMixedStatusIsInert(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	raw, _ := json.Marshal(map[string]any{"schemaVersion": applicationcheck.ConfigSchemaVersionV2, "enabled": true, "managerInstanceId": "", "operatorOrigin": m.Config.OperatorOrigin, "profile": m.Config.Profile, "intervalSeconds": 60, "checksFromManagerAcknowledged": true, "targets": []any{
		map[string]any{"kind": "dns", "id": "resolution", "host": "fixture.internal", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false},
		map[string]any{"kind": "tcp", "id": "connection", "host": "8.8.8.8", "port": 5432, "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false},
		map[string]any{"kind": "http", "id": "http", "url": "https://fixture.internal/status", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false, "plaintextHTTPAcknowledged": false},
	}})
	path := filepath.Join(t.TempDir(), "v2-mixed.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write")
	}
	c, e := applicationcheck.Load(path, "", m.Config.OperatorOrigin, m.Config.Profile)
	if e != nil {
		t.Fatal(e)
	}
	p, e := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if p.applicationChecks == nil {
		t.Fatal("enabled configuration has no worker")
	}
	view := readApplicationChecksPrepared(t, p, m.Config.OperatorOrigin)
	if view["schemaVersion"] != applicationcheck.SchemaVersionV2 || view["enabled"] != true {
		t.Fatal("v2 lost at manager boundary")
	}
	rows := view["items"].([]any)
	if len(rows) != 3 {
		t.Fatal("wrong mixed rows")
	}
	for i, v := range rows {
		row := v.(map[string]any)
		if row["observedAt"] != nil || row["state"] != "unknown" || row["reason"] != "not_checked" {
			t.Fatal("status read performed a probe")
		}
		want := 5
		if i == 2 {
			want = 8
		}
		if len(row) != want {
			t.Fatal("protocol-specific wire fields wrong")
		}
	}
}
func readApplicationChecksPrepared(t *testing.T, p *prepared, origin string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, origin+"/api/auth/login", strings.NewReader(`{"password":"fixture-password-only"}`))
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:32100"
	w := httptest.NewRecorder()
	p.operator.ServeHTTP(w, r)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("fixture login failed", w.Code)
	}
	get := httptest.NewRequest(http.MethodGet, origin+"/api/application-checks/status", nil)
	get.AddCookie(w.Result().Cookies()[0])
	get.RemoteAddr = "127.0.0.1:32100"
	out := httptest.NewRecorder()
	p.operator.ServeHTTP(out, get)
	if out.Code != 200 {
		t.Fatal("fixture status failed", out.Code)
	}
	var v map[string]any
	if json.Unmarshal(out.Body.Bytes(), &v) != nil {
		t.Fatal("invalid status JSON")
	}
	return v
}
