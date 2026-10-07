//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func applicationCheckFixture(t *testing.T, managerID, origin, profile string) applicationcheck.Config {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": applicationcheck.ConfigSchemaVersion, "enabled": true,
		"managerInstanceId": managerID, "operatorOrigin": origin, "profile": profile,
		"intervalSeconds": 60, "checksFromManagerAcknowledged": true,
		"targets": []any{map[string]any{"id": "fixture", "url": "https://app.example.test/status", "allowedAddresses": []string{"8.8.8.8"}, "allowPrivateLAN": false, "plaintextHTTPAcknowledged": false}},
	})
	path := filepath.Join(t.TempDir(), "application-checks.json")
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("protected application check fixture failed")
	}
	config, err := applicationcheck.Load(path, managerID, origin, profile)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestApplicationChecksManagerDefaultOff(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	p, err := prepare(m)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if p.applicationChecks == nil || p.applicationChecks.View().Mode != "managed" || p.applicationChecks.View().Enabled || p.applicationChecks.View().Configured {
		t.Fatal("omitted configuration did not construct an inert managed supervisor")
	}
	view := p.applicationChecks.Status()
	if view.Enabled || len(view.Items) != 0 {
		t.Fatal("omitted configuration enabled application checks")
	}
}

func TestApplicationChecksManagerExplicitDisabled(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	path := filepath.Join(t.TempDir(), "disabled.json")
	raw, _ := json.Marshal(map[string]any{"schemaVersion": applicationcheck.ConfigSchemaVersion, "enabled": false})
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("protected disabled fixture failed")
	}
	config, err := applicationcheck.Load(path, "", m.Config.OperatorOrigin, m.Config.Profile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if p.applicationChecks == nil || p.applicationChecks.View().Mode != "external" || p.applicationChecks.Status().Enabled {
		t.Fatal("disabled external configuration became browser-managed or enabled")
	}
}

func TestApplicationChecksManagerRejectsMismatchedBindingBeforeStateCreation(t *testing.T) {
	for _, mismatch := range []string{"instance", "origin", "profile"} {
		t.Run(mismatch, func(t *testing.T) {
			m, _, _, _ := fixture(t, lanconfig.HTTPTest)
			managerID, origin, profile := "", m.Config.OperatorOrigin, m.Config.Profile
			switch mismatch {
			case "instance":
				managerID = "manager_11111111111111111111111111111111"
			case "origin":
				origin = "http://different.example.test:8787"
			case "profile":
				m.Config.Profile = lanconfig.TLS
			}
			config := applicationCheckFixture(t, managerID, origin, profile)
			p, err := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, config)
			if p != nil {
				p.close()
				t.Fatal("mismatched config prepared manager state")
			}
			if !errors.Is(err, applicationcheck.ErrConfiguration) {
				t.Fatal("mismatched binding not rejected", err)
			}
			if _, err := os.Lstat(m.Config.StateDirectory); !os.IsNotExist(err) {
				t.Fatal("mismatched config created state before validation", err)
			}
		})
	}
}

func TestApplicationChecksManagerPrepareIsInertInManualMode(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, _, _, _ := fixture(t, profile)
			config := applicationCheckFixture(t, "", m.Config.OperatorOrigin, m.Config.Profile)
			before := applicationcheck.New(config).Status()
			p, err := prepareWithApplicationChecks(m, nil, alarmdelivery.Config{}, config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			if p.applicationChecks == nil {
				t.Fatal("explicit manual config did not construct monitor")
			}
			after := p.applicationChecks.Status()
			if !after.Enabled || !reflect.DeepEqual(before.Items, after.Items) {
				t.Fatal("preparing manager ran a check or altered initial observations")
			}
		})
	}
}

func TestApplicationChecksManagerUsesEnrollmentBinding(t *testing.T) {
	m, enrollment, _ := guidedFixture(t, lanconfig.HTTPTest)
	config := applicationCheckFixture(t, "", m.Config.OperatorOrigin, m.Config.Profile)
	if p, err := prepareWithApplicationChecks(m, &enrollment, alarmdelivery.Config{}, config); !errors.Is(err, applicationcheck.ErrConfiguration) {
		if p != nil {
			p.close()
		}
		t.Fatal("manual-mode config adopted enrolled manager identity", err)
	}
	if _, err := os.Lstat(m.Config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("identity mismatch created manager state", err)
	}
	config = applicationCheckFixture(t, enrollment.StoreConfig().Binding.InstanceID, m.Config.OperatorOrigin, m.Config.Profile)
	p, err := prepareWithApplicationChecks(m, &enrollment, alarmdelivery.Config{}, config)
	if err != nil {
		t.Fatal("matching guided binding rejected", err)
	}
	defer p.close()
	if p.applicationChecks == nil || !p.applicationChecks.Status().Enabled {
		t.Fatal("matching guided configuration did not construct monitor")
	}
}
