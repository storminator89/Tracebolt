package container_test

import (
	"encoding/json"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"testing"
)

func TestDeploymentExampleSchemas(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "lan."+profile+".example.json"))
		if err != nil {
			t.Fatal(err)
		}
		var c lanconfig.Config
		if json.Unmarshal(raw, &c) != nil || c.Validate() != nil {
			t.Fatalf("%s deployment example is incompatible with manager schema", profile)
		}
		if c.Profile != profile || c.StateDirectory != "/data/state" || c.WebDirectory != "/tracebolt/web" {
			t.Fatal("container configuration paths/profile drifted")
		}
	}
}
