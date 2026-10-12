package windowssoftwaremanager

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPreparedMSINestedConfigurationStrictness(t *testing.T) {
	m, _, _ := finalSetupFixture(t)
	c := Config{Version: ConfigVersion, Enabled: true, Binding: m.plan.Registration.Consent.Binding, PrivateKeyFile: "/protected/key"}
	raw, _ := json.Marshal(c)
	var decoded Config
	if strictManagerObject(raw, &decoded) != nil || !validConfig(decoded) {
		t.Fatal("exact nested v1 binding rejected")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":false`), 1),
		bytes.Replace(raw, []byte(`"deviceId":`), []byte(`"DeviceId":`), 1),
		bytes.Replace(raw, []byte(`"binding":{`), []byte(`"binding":{"unknown":"x",`), 1),
		bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":null`), 1),
		append(bytes.Clone(raw), []byte(` {}`)...),
	} {
		if strictManagerObject(bad, &decoded) == nil {
			t.Fatal("ambiguous config admitted")
		}
	}
	registry := RegistryConfig{Version: RegistryVersion, Enabled: true, ManagerID: c.Binding.ManagerID, ConfigFiles: []string{"/protected/first.json", "/protected/second.json"}}
	raw, _ = json.Marshal(registry)
	var got RegistryConfig
	if strictManagerObject(raw, &got) != nil || !validRegistry(got, 25) {
		t.Fatal("explicit bounded registry rejected")
	}
	if strictManagerObject(bytes.Replace(raw, []byte(`"configFiles":[`), []byte(`"configFiles":null,"configFiles":[`), 1), &got) == nil {
		t.Fatal("ambiguous registry admitted")
	}
}
