package api

import (
	"encoding/json"
	"localrmm/internal/applicationcheck"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestApplicationChecksV2NamedReadAndPrivateFieldBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected file support is Linux-only")
	}
	o, _ := namedOperatorFixture(t)
	raw, _ := json.Marshal(map[string]any{"schemaVersion": applicationcheck.ConfigSchemaVersionV2, "enabled": true, "managerInstanceId": "", "operatorOrigin": o.server.URL, "profile": "tls", "intervalSeconds": 60, "checksFromManagerAcknowledged": true, "targets": []any{
		map[string]any{"kind": "dns", "id": "resolution", "host": "private-fixture.internal", "allowedAddresses": []string{"10.2.3.4"}, "allowPrivateLAN": true},
		map[string]any{"kind": "tcp", "id": "connection", "host": "10.2.3.4", "port": 5432, "allowedAddresses": []string{"10.2.3.4"}, "allowPrivateLAN": true},
	}})
	path := filepath.Join(t.TempDir(), "v2.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write")
	}
	c, e := applicationcheck.Load(path, "", o.server.URL, "tls")
	if e != nil {
		t.Fatal(e)
	}
	o.server.Config.Handler.(*operatorHandler).applicationChecks = applicationcheck.New(c)
	if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous v2 read")
	}
	_, session := o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	r, v := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil)
	if r.StatusCode != 200 || v["schemaVersion"] != applicationcheck.SchemaVersionV2 {
		t.Fatal("named v2 read failed")
	}
	for _, item := range v["items"].([]any) {
		row := item.(map[string]any)
		if len(row) != 5 || row["httpStatus"] != nil || row["tls"] != nil || row["observedAt"] != nil || row["state"] != "unknown" {
			t.Fatal("wrong kind fields or read triggered work")
		}
	}
	payload, _ := json.Marshal(v)
	for _, secret := range []string{"private-fixture.internal", "10.2.3.4", "5432", "allowedAddresses", "allowPrivateLAN", "operatorOrigin"} {
		if strings.Contains(string(payload), secret) {
			t.Fatal("configuration leaked in status")
		}
	}
	csrf := session["csrfToken"].(string)
	if r, _ := o.call(t, "POST", applicationCheckStatusPath, map[string]any{"kind": "tcp", "host": "other.internal", "port": 22}, csrf, nil); r.StatusCode != 403 {
		t.Fatal("reader gained target/run controls")
	}
	o.call(t, "POST", "/api/auth/logout", map[string]any{}, csrf, nil)
	if r, _ := o.call(t, "GET", applicationCheckStatusPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("revoked v2 status readable")
	}
}
