package native

import (
	"context"
	"localrmm/internal/windowsacceptance/profile"
	"reflect"
	"testing"
)

type capabilityGuard struct {
	selectedGuard
	expanded bool
}

func (g capabilityGuard) ExtensionsApproved() bool { return g.expanded }

// Every branch here is inert: missing scope is refused before platform dispatch.
func TestCapabilityConfigurationRequiresExactExpandedAuthority(t *testing.T) {
	for _, selection := range []profile.Selection{profile.BasicTLS(), profile.InventoryTLS()} {
		for _, expanded := range []bool{false, true} {
			for _, approved := range []bool{false, true} {
				if selection.Inventory() && expanded && approved {
					continue
				}
				d := &Driver{options: Options{Selection: selection, Expanded: expanded}}
				g := capabilityGuard{selectedGuard{selection}, approved}
				if d.ConfigureCapabilities(context.Background(), g) != ErrAcceptance || d.Evidence().Reason != ReasonGuard || d.state != nil {
					t.Fatal("incomplete scope entered platform")
				}
			}
		}
	}
	d := &Driver{options: Options{Selection: profile.InventoryTLS(), Expanded: true}}
	if d.ConfigureCapabilities(context.Background(), selectedGuard{profile.InventoryTLS()}) != ErrAcceptance || d.Evidence().Reason != ReasonGuard {
		t.Fatal("old grant promoted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.ConfigureCapabilities(ctx, capabilityGuard{selectedGuard{profile.InventoryTLS()}, true}) != ErrAcceptance || d.Evidence().Reason != ReasonTimeout {
		t.Fatal("cancelled grant entered platform")
	}
	if (*Driver)(nil).ConfigureCapabilities(context.Background(), nil) != ErrAcceptance {
		t.Fatal("nil driver")
	}
}

func TestCapabilitySiblingSchemasAndExactConsent(t *testing.T) {
	stores := capabilityStores()
	if len(stores) != 4 {
		t.Fatal("scope count")
	}
	want := []string{"-event-metadata", "-visible-volumes", "-process-metrics", "-network"}
	seen := map[string]bool{}
	for i, c := range stores {
		if c.suffix != want[i] || seen[c.scope] {
			t.Fatal("scope alias or path drift")
		}
		seen[c.scope] = true
		o := c.options("fixture-service-sid")
		if o.RuntimeSID != "fixture-service-sid" || o.Create || o.InstallerOnly || o.MaxBytes != 1024 || len(o.Directories) != 0 || !reflect.DeepEqual(o.Names, []string{"consent.json"}) {
			t.Fatal("protection/schema drift")
		}
		for _, insecure := range []bool{false, true} {
			r := c.consent(insecure)
			if r.Validate() != nil || r.InsecureHTTPAcknowledged != insecure || len(r.Scopes) != 2 || r.Scopes[1] != c.scope {
				t.Fatal("consent drift")
			}
		}
	}
}

func TestEveryMutatorBindsExpandedAuthority(t *testing.T) {
	for _, expanded := range []bool{false, true} {
		d := &Driver{options: Options{Selection: profile.InventoryTLS(), Expanded: expanded}}
		g := capabilityGuard{selectedGuard{profile.InventoryTLS()}, !expanded}
		if d.enter(context.Background(), g, StageStart) || d.Evidence().Reason != ReasonGuard {
			t.Fatal("expanded guard mismatch reached native mutator")
		}
	}
	d := &Driver{options: Options{Selection: profile.InventoryTLS(), Expanded: true}}
	if d.enter(context.Background(), selectedGuard{profile.InventoryTLS()}, StageStart) {
		t.Fatal("old guard resumed expanded service")
	}
}
