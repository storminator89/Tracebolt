package security_test

import (
	"encoding/json"
	"localrmm/internal/analysis"
	"localrmm/internal/model"
	"localrmm/internal/windowsnetworkcontext"
	"strings"
	"testing"
)

func TestWindowsNetworkContextDoesNotAuthorizeProviderExport(t *testing.T) {
	sentinel := "synthetic-private-interface-label"
	for _, profile := range []string{"windows-inventory-v1", windowsnetworkcontext.Scope} {
		packet, e := analysis.BuildPacket(model.Case{CollectionProfile: profile, Title: sentinel}, []model.Evidence{{CollectionProfile: profile, Detail: sentinel}})
		raw, _ := json.Marshal(packet)
		if e == nil || strings.Contains(string(raw), sentinel) {
			t.Fatal("private context promoted to provider evidence")
		}
	}
}
func TestWindowsNetworkContextScopeHasBoundedExplicitReadOnlyContract(t *testing.T) {
	if windowsnetworkcontext.MaxRows != 4352 || windowsnetworkcontext.MaxRoutes != 4096 || windowsnetworkcontext.MaxInterfaces != 256 || windowsnetworkcontext.MaxSourceBytes != 2<<20 || windowsnetworkcontext.MaxPackBytes != 3<<20 || windowsnetworkcontext.MaxChunkBytes != 64<<10 || windowsnetworkcontext.MaxChunks != 64 {
		t.Fatal("context bounds changed")
	}
	for _, term := range []string{"interface aliases", "raw", "cannot be hard-canceled", "not atomic", "not rates", "since-boot", "No MAC addresses", "DNS resolution", "old inventory"} {
		if !strings.Contains(windowsnetworkcontext.Privacy, term) {
			t.Fatal("missing explicit scope limit")
		}
	}
}
