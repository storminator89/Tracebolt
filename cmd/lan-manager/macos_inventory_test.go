//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacOSInventoryManagerDefaultOffAndMixedImmutableStores(t *testing.T) {
	for _, renewable := range []bool{false, true} {
		t.Run(fmt.Sprint(renewable), func(t *testing.T) {
			m, _, path := guidedFixture(t, lanconfig.TLS)
			var cfg enrollmentconfig.Config
			raw, _ := os.ReadFile(path)
			json.Unmarshal(raw, &cfg)
			cfg.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
			if renewable {
				cfg.SchemaVersion = enrollmentconfig.RenewableSchemaVersion
				cfg.AutomaticRenewal = true
			}
			raw, _ = json.Marshal(cfg)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			m.Config.WindowsInventoryEnabled = true
			m.Config.MacOSBasicEnabled = true
			material, err := enrollmentconfig.Load(path, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = material.MacOSInventoryStoreConfig(); err == nil {
				t.Fatal("implicit Mac enable")
			}
			p, err := prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal(err)
			}
			login := func() (*http.Cookie, string) {
				t.Helper()
				w := windowsOperatorCall(t, p, m, "POST", "/api/auth/login", map[string]string{"password": "fixture-password-only"}, nil, "")
				var auth map[string]any
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &auth) != nil {
					t.Fatal("login", w.Code)
				}
				return w.Result().Cookies()[0], auth["csrfToken"].(string)
			}
			cookie, csrf := login()
			list := func(enabled bool) {
				t.Helper()
				w := windowsOperatorCall(t, p, m, "GET", "/api/macos-inventory/enrollment", nil, cookie, "")
				var response struct {
					Enabled           bool
					Platforms         []string
					CollectionProfile string
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Enabled != enabled || len(response.Platforms) != 1 || response.Platforms[0] != "darwin" || response.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory {
					t.Fatal("Mac list", w.Code)
				}
			}
			list(false)
			if _, err = os.Stat(filepath.Join(m.Config.StateDirectory, enrollmentconfig.MacOSInventoryDatabaseFile)); !os.IsNotExist(err) {
				t.Fatal("Mac DB initialized when disabled")
			}
			p.close()
			before, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			m.Config.MacOSInventoryEnabled = true
			material, err = enrollmentconfig.Load(path, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			mac, err := material.MacOSInventoryStoreConfig()
			if err != nil || mac.Platform != "darwin" || mac.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory || mac.AutomaticRenewal != renewable {
				t.Fatal("Mac immutable policy", err)
			}
			p, err = prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			cookie, csrf = login()
			list(true)
			after, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.ModeFile))
			if !bytes.Equal(before, after) {
				t.Fatal("primary identity marker changed")
			}
			if w := windowsOperatorCall(t, p, m, "GET", "/api/macos-inventory/enrollment", nil, nil, ""); w.Code != 401 {
				t.Fatal("session bypass", w.Code)
			}
			body := map[string]any{"requestId": fmt.Sprintf("request_%032x", 91), "platform": "darwin", "collectionAcknowledged": true}
			if w := windowsOperatorCall(t, p, m, "POST", "/api/macos-inventory/enrollment/invitations", body, cookie, ""); w.Code != 403 {
				t.Fatal("CSRF bypass", w.Code)
			}
			for _, platform := range []string{"linux", "windows", "macos"} {
				body["platform"] = platform
				if w := windowsOperatorCall(t, p, m, "POST", "/api/macos-inventory/enrollment/invitations", body, cookie, csrf); w.Code != 400 {
					t.Fatal("platform bypass", platform, w.Code)
				}
			}
			body["platform"] = "darwin"
			w := windowsOperatorCall(t, p, m, "POST", "/api/macos-inventory/enrollment/invitations", body, cookie, csrf)
			var created struct {
				Snapshot  struct{ Platform string }
				Bootstrap struct{ CollectionProfile, SchemaVersion, RenewalPolicy string }
			}
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.Snapshot.Platform != "darwin" || created.Bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory {
				t.Fatal("Mac invitation", w.Code)
			}
			if renewable && created.Bootstrap.RenewalPolicy != "same-key-v1" {
				t.Fatal("renewal policy lost")
			}
			for _, route := range []string{"/api/enrollment", "/api/windows/enrollment", "/api/macos/enrollment"} {
				w = windowsOperatorCall(t, p, m, "GET", route, nil, cookie, "")
				var v struct{ Items []any }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || len(v.Items) != 0 {
					t.Fatal("Mac invitation crossed store", route)
				}
			}
			// The generic primary route cannot allocate the new Darwin domain.
			body["collectionAcknowledged"] = true
			if w = windowsOperatorCall(t, p, m, "POST", "/api/enrollment/invitations", body, cookie, csrf); w.Code != 400 {
				t.Fatal("Mac reused primary store", w.Code)
			}
			p.close()
			p, err = prepareWithEnrollment(m, &material)
			if err != nil {
				t.Fatal("mixed reopen", err)
			}
			cookie, csrf = login()
			list(true)
			p.close()
		})
	}
}
func TestMacOSInventoryManagerRejectsHTTPAndMissingGuidedProfile(t *testing.T) {
	m, _, path := guidedFixture(t, lanconfig.HTTPTest)
	m.Config.MacOSInventoryEnabled = true
	if m.Config.Validate() == nil {
		t.Fatal("HTTP Mac config admitted")
	}
	if _, err := enrollmentconfig.Load(path, m, time.Now().UTC()); err == nil {
		t.Fatal("HTTP Mac material admitted")
	}
	m, _, _, _ = fixture(t, lanconfig.TLS)
	m.Config.MacOSInventoryEnabled = true
	if p, err := prepare(m); err == nil {
		p.close()
		t.Fatal("manual Mac setup admitted")
	}
}
func TestMacOSInventoryManagerRouteFamilyNeverFallsThrough(t *testing.T) {
	primaryCalls, inventoryCalls := 0, 0
	primary := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { primaryCalls++ })
	inventory := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { inventoryCalls++ })
	for _, enabled := range []bool{false, true} {
		var target http.Handler
		if enabled {
			target = inventory
		}
		h := withMacOSInventoryIngress(withMacOSIngress(primary, nil), target)
		for _, path := range []string{"/v1/macos/inventory", "/v1/macos/inventory/control", "/v1/macos/inventory/report", "/v1/macos/inventory/unknown", "/v1/macos/inventory/telemetry", "/v1/macos/inventory/service-actions/claim"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
			if (!enabled || path != "/v1/macos/inventory/control" && path != "/v1/macos/inventory/report") && w.Code != 404 {
				t.Fatal("route not closed", path, w.Code)
			}
		}
	}
	if primaryCalls != 0 || inventoryCalls != 2 {
		t.Fatal("cross-domain route", primaryCalls, inventoryCalls)
	}
}

func TestMacOSInventoryFourDomainDeviceMergeRejectsCollisionsAndBounds(t *testing.T) {
	existing := []model.Device{{ID: "linux", Platform: "linux"}, {ID: "windows", Platform: "windows"}, {ID: "basic", Platform: "macos"}}
	fresh := []model.Device{{ID: "inventory", Platform: "macos"}}
	got, err := mergeMacOSInventoryRows(existing, fresh, 3)
	if err != nil || len(got) != 4 || got[0].ID != "basic" || got[1].ID != "inventory" {
		t.Fatal("four-domain merge", err)
	}
	for _, id := range []string{"linux", "windows", "basic"} {
		if _, err := mergeMacOSInventoryRows(existing, []model.Device{{ID: id, Platform: "macos"}}, 3); err == nil {
			t.Fatal("cross-domain identity collision", id)
		}
	}
	if _, err := mergeMacOSInventoryRows(existing, append(fresh, fresh...), 3); err == nil {
		t.Fatal("same-domain duplicate")
	}
	if _, err := mergeMacOSInventoryRows(existing, []model.Device{{ID: "foreign", Platform: "linux"}}, 3); err == nil {
		t.Fatal("foreign projection")
	}
	if _, err := mergeMacOSInventoryRows(make([]model.Device, 76), fresh, 3); err == nil {
		t.Fatal("prior domain budget")
	}
	if _, err := mergeMacOSInventoryRows(existing, make([]model.Device, 26), 3); err == nil {
		t.Fatal("inventory domain budget")
	}
}

func TestMacOSInventoryDisabledDomainRetainsMaintenanceOnly(t *testing.T) {
	m, _, path := guidedFixture(t, lanconfig.TLS)
	m.Config.MacOSInventoryEnabled = true
	material, e := enrollmentconfig.Load(path, m, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	p, e := prepareWithEnrollment(m, &material)
	if e != nil {
		t.Fatal(e)
	}
	p.close()
	m.Config.MacOSInventoryEnabled = false
	material, e = enrollmentconfig.Load(path, m, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	p, e = prepareWithEnrollment(m, &material)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if p.macosInventoryMaintenance == nil {
		t.Fatal("retained domain lost maintenance")
	}
	r := httptest.NewRequest("POST", "/v1/macos/inventory/report", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	p.agent.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("disabled maintenance exposed ingress", w.Code)
	}
	p.close()
	if e = os.WriteFile(filepath.Join(m.Config.StateDirectory, enrollmentconfig.MacOSInventoryDatabaseFile), []byte("retained broken fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if p, e = prepareWithEnrollment(m, &material); e == nil {
		p.close()
		t.Fatal("disabled broken database accepted")
	}
}
