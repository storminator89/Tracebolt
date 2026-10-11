//go:build linux

package agentinstall

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentclient"
	"os"
	"testing"
)

func TestRenewalFreshInstallerPreflightRejectsMismatchWithoutEffects(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		for _, acknowledged := range []bool{false, true} {
			r, b, events := installerHostFixture(t)
			raw, _ := os.ReadFile(r.BootstrapFile)
			var public enrollmentclient.Bootstrap
			if json.Unmarshal(raw, &public) != nil {
				t.Fatal("fixture")
			}
			if renewable {
				public.SchemaVersion = enrollmentclient.RenewableBootstrapVersion
				public.RenewalPolicy = "same-key-v1"
			}
			raw, _ = json.Marshal(public)
			if os.WriteFile(r.BootstrapFile, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			r.BootstrapSHA256 = sum(raw)
			r.AutomaticRenewalAcknowledged = acknowledged
			facts, err := b.Inspect(context.Background(), r)
			if (err == nil) != (renewable == acknowledged) {
				t.Fatal("preflight consent mismatch", err)
			}
			if err == nil && facts.AutomaticRenewal != renewable {
				t.Fatal("bootstrap selection lost")
			}
			if len(*events) != 0 {
				t.Fatal("preflight changed host")
			}
			if _, err := os.Lstat(b.host.path(controlDirectory)); !os.IsNotExist(err) {
				t.Fatal("preflight wrote state")
			}
		}
	}
}
