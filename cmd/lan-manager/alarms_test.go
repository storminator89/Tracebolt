//go:build linux

package main

import (
	"context"
	"localrmm/internal/lanconfig"
	"localrmm/internal/store"
	"path/filepath"
	"testing"
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
