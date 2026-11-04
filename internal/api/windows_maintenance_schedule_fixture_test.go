package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateWindowsMaintenanceScheduleFixture = flag.Bool("update-windows-maintenance-schedule-fixture", false, "regenerate reviewed Windows scheduled maintenance Go/TypeScript fixture")

func TestWindowsMaintenanceScheduleWireFixture(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(at)
	in.AuthorityUntil = at.Add(24 * time.Hour)
	authority := map[string]windowscapacity.Input{in.DeviceID: in}
	target := maintenanceTarget(in, "all")
	st := store.WindowsMaintenanceScheduleState{Version: 1, Target: target, Revision: 1, ChangedAt: at, ObservedAt: at, Windows: []store.WindowsMaintenanceScheduleWindow{{ID: 1, CreatedAt: at, StartsAt: at.Add(time.Hour), EndsAt: at.Add(2 * time.Hour), Intent: "planned-work"}}}
	views := map[string]windowsMaintenanceScheduleView{}
	add := func(name string, states []store.WindowsMaintenanceScheduleState, now time.Time) {
		t.Helper()
		v, e := projectWindowsMaintenanceSchedules(states, nil, authority, now)
		if e != nil {
			t.Fatal(e)
		}
		views[name] = v
	}
	add("empty", nil, at)
	add("pending", []store.WindowsMaintenanceScheduleState{st}, at)
	add("active", []store.WindowsMaintenanceScheduleState{st}, at.Add(time.Hour))
	add("expired", []store.WindowsMaintenanceScheduleState{st}, at.Add(2*time.Hour))
	st.Windows = append([]store.WindowsMaintenanceScheduleWindow{}, st.Windows...)
	ended := at.Add(61 * time.Minute)
	st.Revision = 2
	st.ChangedAt = ended
	st.ObservedAt = ended
	st.Windows[0].EndedAt = &ended
	add("ended", []store.WindowsMaintenanceScheduleState{st}, ended)
	st.Windows = append([]store.WindowsMaintenanceScheduleWindow{}, st.Windows...)
	cancelled := at.Add(time.Minute)
	st.ChangedAt = cancelled
	st.ObservedAt = cancelled
	st.Windows[0].EndedAt = nil
	st.Windows[0].CancelledAt = &cancelled
	add("cancelled", []store.WindowsMaintenanceScheduleState{st}, cancelled)
	raw, e := json.MarshalIndent(views, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-maintenance-schedule-view.json")
	if *updateWindowsMaintenanceScheduleFixture {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	existing, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, existing) {
		t.Fatal("Windows maintenance schedule fixture changed; review before regeneration", e)
	}
}
