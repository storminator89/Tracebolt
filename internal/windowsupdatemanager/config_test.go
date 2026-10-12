package windowsupdatemanager

import (
	"context"
	"strings"
	"testing"

	"localrmm/internal/windowsupdatejob"
)

func TestSelectedUpdateConfigRequiresFreshExactTLSAuthority(t *testing.T) {
	c := Config{Version: ConfigVersion, Enabled: true, PrivateKeyFile: "/tmp/protected-wua-key", Binding: windowsupdatejob.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: "sha256:" + strings.Repeat("3", 64), ExecutorID: "executor_" + strings.Repeat("4", 32), ExecutorKeyID: "sha256:" + strings.Repeat("5", 64), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: "sha256:" + strings.Repeat("7", 64)}}
	if !validConfig(c) {
		t.Fatal("valid protected source config rejected")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Enabled = false }, func(c *Config) { c.Version = "tracebolt.windows-service-actions-config.v1" }, func(c *Config) { c.PrivateKeyFile = "relative" }, func(c *Config) { c.Binding.ExecutorKeyID = c.Binding.KeyID }, func(c *Config) { c.Binding.GrantID = "" }} {
		other := c
		change(&other)
		if validConfig(other) {
			t.Fatal("invalid scope accepted")
		}
	}
	if _, e := Load(context.Background(), nil, "/tmp/absent"); e == nil {
		t.Fatal("missing existing store adopted")
	}
}
