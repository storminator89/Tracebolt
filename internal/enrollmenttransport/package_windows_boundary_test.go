package enrollmenttransport

import (
	"bytes"
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/packagewire"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestWindowsIngressRejectsNativePackageRoutesBeforeDispatch(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, false)
			cfg := f.config
			cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
			s, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "windows.sqlite"), cfg, f.issuer.IssuerDER())
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			h, e := New(s, f.issuer.IssuerDER(), cfg.Binding.Origin)
			if e != nil {
				t.Fatal(e)
			}
			if e = h.ConfigurePackageActions(&packagecontroller.Manager{}); e == nil {
				t.Fatal("Windows ingress configured package controller")
			}
			for _, path := range []string{packagewire.PeekPath, packagewire.ClaimPath, packagewire.ResultPath, packagewire.CapabilitiesPath} {
				r := httptest.NewRequest("POST", cfg.Binding.Origin+path, bytes.NewBufferString("{}"))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 404 || !bytes.Contains(w.Body.Bytes(), []byte(`"not_found"`)) {
					t.Fatal("Windows route escaped early domain rejection", path, w.Code, w.Body.String())
				}
			}
			if e = s.AuthorizePackageDevice(context.Background(), f.snapshot.Approval.DeviceID, "sha256:invalid", f.now); e == nil {
				t.Fatal("Windows store accepted package authority")
			}
		})
	}
}
