package macosservice

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/renewalidentity"
	"strings"
	"testing"
)

func basicFixture() lanclient.Config {
	return lanclient.Config{SchemaVersion: lanclient.GuidedConfigVersion, Profile: "tls", ManagerOrigin: "https://manager.example", AgentID: "agent_" + strings.Repeat("1", 32), CertificateFile: EnrollmentDirectory + "/agent-cert.pem", PrivateKeyFile: EnrollmentDirectory + "/agent-key.pem", ServerCAFile: EnrollmentDirectory + "/server-ca.pem", StateDirectory: EnrollmentDirectory + "/telemetry"}
}
func TestBasicTLSConfigBoundToExactFixedPaths(t *testing.T) {
	raw, err := json.Marshal(basicFixture())
	if err != nil || validateBasicConfig(raw) != nil {
		t.Fatal("valid basic fixture rejected")
	}
	cases := []struct {
		name   string
		change func(*lanclient.Config)
	}{
		{"manual", func(c *lanclient.Config) { c.SchemaVersion = lanclient.ConfigVersion }},
		{"operational", func(c *lanclient.Config) {
			c.SchemaVersion = lanclient.OperationalConfigVersion
			c.CollectionProfile = "managed-operations-v1"
		}},
		{"renewal", func(c *lanclient.Config) {
			c.SchemaVersion = lanclient.RenewalConfigVersion
			c.RenewalManifestFile = EnrollmentDirectory + "/renewal-manifest.json"
		}},
		{"implicit-profile", func(c *lanclient.Config) { c.Profile = "" }},
		{"http", func(c *lanclient.Config) {
			c.Profile = "http-test"
			c.InsecureHTTPAcknowledged = true
			c.ServerCAFile = ""
			c.ManagerOrigin = "http://manager.example"
		}},
		{"implicit-scope", func(c *lanclient.Config) { c.CollectionProfile = "basic-v1" }},
		{"different-key", func(c *lanclient.Config) { c.PrivateKeyFile = "/Users/user/key.pem" }},
		{"different-cert", func(c *lanclient.Config) { c.CertificateFile = "/Users/user/cert.pem" }},
		{"different-ca", func(c *lanclient.Config) { c.ServerCAFile = "/Users/user/ca.pem" }},
		{"different-state", func(c *lanclient.Config) { c.StateDirectory = StateDirectory + "/new-telemetry" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c := basicFixture()
			test.change(&c)
			raw, _ := json.Marshal(c)
			if validateBasicConfig(raw) == nil {
				t.Fatal("unexpected schema/scope/path admitted")
			}
		})
	}
	for _, suffix := range []string{`,"profile":"tls"}`, `,"renewalManifestFile":""}`, `,"unknown":true}`, `,"collectionProfile":null}`} {
		bad := append(append([]byte{}, raw[:len(raw)-1]...), []byte(suffix)...)
		if validateBasicConfig(bad) == nil {
			t.Fatal("noncanonical field accepted")
		}
	}
}

func TestRenewableBasicTLSUsesExactManifestWithoutScopeExpansion(t *testing.T) {
	c := basicFixture()
	c.SchemaVersion = lanclient.RenewalConfigVersion
	c.CollectionProfile = enrollmentcrypto.CollectionProfile
	c.RenewalManifestFile = EnrollmentDirectory + "/" + renewalidentity.ManifestName
	raw, _ := json.Marshal(c)
	if validateBasicConfig(raw) != nil {
		t.Fatal("explicit basic renewable source rejected")
	}
	for _, change := range []func(*lanclient.Config){
		func(c *lanclient.Config) { c.CollectionProfile = enrollmentcrypto.CollectionProfileComplete },
		func(c *lanclient.Config) { c.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory },
		func(c *lanclient.Config) { c.RenewalManifestFile = "/private/other/renewal-manifest.json" },
		func(c *lanclient.Config) { c.RenewalManifestFile = "" },
		func(c *lanclient.Config) { c.Profile = "http-test"; c.InsecureHTTPAcknowledged = true },
	} {
		bad := c
		change(&bad)
		raw, _ := json.Marshal(bad)
		if validateBasicConfig(raw) == nil {
			t.Fatal("renewal widened profile or manifest path")
		}
	}
}
