//go:build linux

package enrollmentclient

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshCompleteEnrollmentCreatesBoundDualLedgerBeforeReady(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := newClientFixture(t, transport, enrollmentcrypto.CollectionProfileComplete)
			opts := f.options()
			displayed := false
			opts.Display = func(d TrustDisplay) error {
				for _, term := range []string{"complete supported dpkg", "bounded chunks", "truncated list", "24 hours", "excluded from AI", "cannot be adopted"} {
					if !strings.Contains(d.CollectionPrivacy, term) {
						t.Error("missing explicit scope", term)
					}
				}
				displayed = true
				return nil
			}
			opts.Secret = func(context.Context) ([]byte, error) {
				if !displayed {
					t.Error("secret before full-scope display")
				}
				return []byte(f.secret), nil
			}
			result, e := Run(context.Background(), f.bootstrap, opts)
			if e != nil {
				t.Fatal("complete enrollment", e)
			}
			if result.Config.SchemaVersion != lanclient.CompleteConfigVersion || result.Config.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || lanclient.ValidateGuidedHandoff(result.ConfigPath) != nil {
				t.Fatal("complete handoff invalid")
			}
			if _, e := os.Stat(filepath.Join(result.Config.StateDirectory, "inventory")); e != nil {
				t.Fatal("missing prepublished inventory domain")
			}
			if _, e = Run(context.Background(), f.bootstrap, opts); e != nil {
				t.Fatal("exact bound resume rejected", e)
			}
		})
	}
}
