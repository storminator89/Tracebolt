package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
)

var updateWindowsMaintenanceFixture = flag.Bool("update-windows-maintenance-fixture", false, "regenerate reviewed Windows maintenance Go/TypeScript fixture")

func TestWindowsMaintenanceWireFixture(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(base)
	in.AuthorityUntil = base.Add(24 * time.Hour)
	authority := map[string]windowscapacity.Input{in.DeviceID: in}
	target := maintenanceTarget(in, "disk")
	st := store.WindowsMaintenanceState{Version: 1, Target: target, Revision: 1, ChangedAt: base, Windows: []store.WindowsMaintenanceWindow{{ID: 1, StartedAt: base, EndsAt: base.Add(time.Hour), Intent: "planned-work"}}}
	views := map[string]windowsMaintenanceView{}
	var err error
	views["empty"], err = projectWindowsMaintenance(nil, authority, base)
	if err != nil {
		t.Fatal(err)
	}
	views["active"], err = projectWindowsMaintenance([]store.WindowsMaintenanceState{st}, authority, base)
	if err != nil {
		t.Fatal(err)
	}
	ended := base.Add(time.Minute)
	st.Windows = append([]store.WindowsMaintenanceWindow{}, st.Windows...)
	st.Revision, st.ChangedAt, st.Windows[0].EndedAt = 2, ended, &ended
	views["ended"], err = projectWindowsMaintenance([]store.WindowsMaintenanceState{st}, authority, ended)
	if err != nil {
		t.Fatal(err)
	}
	st.Windows = append([]store.WindowsMaintenanceWindow{}, st.Windows...)
	st.Revision, st.ChangedAt, st.Windows[0].EndedAt = 1, base, nil
	views["expired"], err = projectWindowsMaintenance([]store.WindowsMaintenanceState{st}, authority, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(views, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-maintenance-view.json")
	if *updateWindowsMaintenanceFixture {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	existing, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(existing, raw) {
		t.Fatal("Windows maintenance Go/TypeScript fixture changed; review before regeneration", err)
	}
}
