//go:build linux

package main

import (
	"context"
	"encoding/json"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAlarmManagerOmittedConfigurationIsDisabled(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	p, e := prepare(m)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	if p.alarms != nil {
		t.Fatal("default startup constructed outbound worker")
	}
	s, e := store.Open(filepath.Join(m.Config.StateDirectory, "operator.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	status, e := s.AlarmStatus(context.Background())
	if e != nil || status.Enabled || status.Queued != 0 {
		t.Fatal("default startup activated delivery", e, status)
	}
}

func TestAlarmManagerCompleteProfileManagedSetupIsInertAndPersists(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, enrolled, path := guidedFixture(t, profile)
			raw, e := os.ReadFile(path)
			var ec enrollmentconfig.Config
			if e != nil || json.Unmarshal(raw, &ec) != nil {
				t.Fatal("fixture config")
			}
			ec.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
			raw, _ = json.Marshal(ec)
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			enrolled, e = enrollmentconfig.Load(path, m, time.Now().UTC())
			if e != nil {
				t.Fatal(e)
			}
			p, e := prepareWithEnrollment(m, &enrolled)
			if e != nil {
				t.Fatal(e)
			}
			if p.alarms == nil {
				p.close()
				t.Fatal("complete-profile settings unavailable")
			}
			v, e := p.alarms.View(context.Background())
			if e != nil || v.Mode != "managed" || v.Enabled || v.Configured {
				p.close()
				t.Fatal(v, e)
			}
			if e = p.alarms.Step(context.Background()); e != nil {
				p.close()
				t.Fatal(e)
			}
			revision := v.Revision
			p.close()
			p, e = prepareWithEnrollment(m, &enrolled)
			if e != nil {
				t.Fatal(e)
			}
			defer p.close()
			v, e = p.alarms.View(context.Background())
			if e != nil || v.Revision != revision || v.Enabled {
				t.Fatal("disabled restart changed config", v, e)
			}
			info, e := os.Stat(filepath.Join(m.Config.StateDirectory, alarmdelivery.SettingsFile))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("settings not in protected state volume")
			}
		})
	}
}
