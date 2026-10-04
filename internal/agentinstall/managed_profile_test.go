//go:build linux

package agentinstall

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"os"
	"path/filepath"
	"testing"
)

// Synthetic public certificates and disposable files only. This checks the
// installer's shared bootstrap seam, not real account/service acceptance.
func TestManagedPackageBootstrapInstallerCompatibility(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			var b enrollmentclient.Bootstrap
			if json.Unmarshal(installerBootstrap(t, transport), &b) != nil {
				t.Fatal("fixture")
			}
			b.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal("fixture encoding")
			}
			p := filepath.Join(t.TempDir(), "bootstrap.json")
			if os.WriteFile(p, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			selected, parsed, err := readBootstrap(context.Background(), p, sum(raw))
			if err != nil || string(selected) != string(raw) || parsed != b {
				t.Fatal("managed installer bootstrap compatibility")
			}
			if b.CollectionProfile != "managed-operations-v2" {
				t.Fatal("profile drift")
			}
			request := Request{Action: Install, AgentBinary: "/selected/lan-agent", EnrollBinary: "/selected/enroll-agent", SourceArchive: "/selected/source.tar", BootstrapFile: p, AgentSHA256: sum([]byte("agent")), EnrollSHA256: sum([]byte("enroll")), SourceSHA256: sum([]byte("source")), BootstrapSHA256: sum(raw), InsecureHTTPTest: transport == "http-test"}
			facts := HostFacts{Linux: true, SystemdAvailable: true, AccountCompatible: true, Profile: parsed.Profile}
			plan, err := BuildPlan(request, facts)
			if err != nil || !plan.DryRun || !plan.ServiceStartRequiresEnrollment {
				t.Fatal("managed plan boundary")
			}
			b.CollectionProfile = "managed-operations-unknown"
			rejected, _ := json.Marshal(b)
			if os.WriteFile(p, rejected, 0600) != nil {
				t.Fatal("fixture rewrite")
			}
			if _, _, err := readBootstrap(context.Background(), p, sum(rejected)); err == nil {
				t.Fatal("unknown collection profile accepted")
			}
		})
	}
}
