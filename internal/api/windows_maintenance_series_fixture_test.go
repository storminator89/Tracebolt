package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"os"
	"strings"
	"testing"
	"time"
)

var updateWindowsMaintenanceSeriesFixture = flag.Bool("update-windows-maintenance-series-fixture", false, "regenerate reviewed maintenance series Go/TypeScript fixture")

func TestWindowsMaintenanceSeriesWireFixture(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(at)
	in.AuthorityUntil = at.Add(30 * 24 * time.Hour)
	authority := map[string]windowscapacity.Input{in.DeviceID: in}
	target := maintenanceTarget(in, "all")
	views := map[string]windowsMaintenanceSeriesView{}
	legacyViews := map[string]windowsMaintenanceSeriesLegacyView{}
	add := func(name string, states []store.WindowsMaintenanceSeriesState, legacy []store.WindowsMaintenanceScheduleState, now time.Time) {
		t.Helper()
		v, e := projectWindowsMaintenanceSeries(states, legacy, nil, authority, now)
		if e != nil {
			t.Fatal(e)
		}
		views[name] = v
		aware, e := projectWindowsMaintenanceSeriesLegacy(legacy, states, nil, authority, now)
		if e != nil {
			t.Fatal(e)
		}
		legacyViews[name] = aware
	}
	add("empty", nil, nil, at)
	st := store.WindowsMaintenanceSeriesState{Version: 1, Target: target, Revision: 1, ChangedAt: at, ObservedAt: at, LastOccurrenceID: 4, Occurrences: []store.WindowsMaintenanceSeriesOccurrence{}}
	for i := 0; i < 4; i++ {
		start := at.Add(time.Hour + time.Duration(i)*7*24*time.Hour)
		st.Occurrences = append(st.Occurrences, store.WindowsMaintenanceSeriesOccurrence{ID: uint64(i + 1), SeriesID: 1, CreatedAt: at, StartsAt: start, EndsAt: start.Add(time.Hour), Intent: "planned-work"})
	}
	add("pending", []store.WindowsMaintenanceSeriesState{st}, nil, at)
	add("active", []store.WindowsMaintenanceSeriesState{st}, nil, at.Add(time.Hour))
	cancelled := at.Add(time.Minute)
	st.Occurrences = append([]store.WindowsMaintenanceSeriesOccurrence{}, st.Occurrences...)
	st.Occurrences[2].CancelledAt = &cancelled
	st.Revision = 2
	st.ChangedAt = cancelled
	st.ObservedAt = cancelled
	add("cancelledSibling", []store.WindowsMaintenanceSeriesState{st}, nil, cancelled)
	ended := at.Add(90 * time.Minute)
	st.Occurrences = append([]store.WindowsMaintenanceSeriesOccurrence{}, st.Occurrences...)
	st.Occurrences[0].EndedAt = &ended
	st.Revision = 3
	st.ChangedAt = ended
	st.ObservedAt = ended
	add("endedSibling", []store.WindowsMaintenanceSeriesState{st}, nil, ended)
	add("expired", []store.WindowsMaintenanceSeriesState{st}, nil, at.Add(29*24*time.Hour))
	legacy := store.WindowsMaintenanceScheduleState{Version: 1, Target: target, Revision: 1, ChangedAt: at, ObservedAt: at, Windows: []store.WindowsMaintenanceScheduleWindow{{ID: 1, CreatedAt: at, StartsAt: at.Add(time.Hour), EndsAt: at.Add(2 * time.Hour), Intent: "other"}}}
	add("legacyReserved", nil, []store.WindowsMaintenanceScheduleState{legacy}, at)

	// Combined modern projection retains independent one-time actions.
	st.Target = maintenanceTarget(in, "cpu")
	legacy.Target = maintenanceTarget(in, "disk")
	aware, e := projectWindowsMaintenanceSeriesLegacy([]store.WindowsMaintenanceScheduleState{legacy}, []store.WindowsMaintenanceSeriesState{st}, nil, authority, ended)
	if e != nil {
		t.Fatal(e)
	}
	legacyViews["cpuSeriesDiskLegacy"] = aware
	other := in
	other.DeviceID = "agent_" + strings.Repeat("d", 32)
	other.InvitationID = "invite_" + strings.Repeat("e", 32)
	other.CertificateHash = strings.Repeat("f", 64)
	authority[other.DeviceID] = other
	st.Target = target
	legacy.Target = maintenanceTarget(other, "all")
	aware, e = projectWindowsMaintenanceSeriesLegacy([]store.WindowsMaintenanceScheduleState{legacy}, []store.WindowsMaintenanceSeriesState{st}, nil, authority, ended)
	if e != nil {
		t.Fatal(e)
	}
	legacyViews["deviceASeriesDeviceBLegacy"] = aware
	for path, value := range map[string]any{"testdata/windows-maintenance-series-view.json": views, "testdata/windows-maintenance-series-legacy-view.json": legacyViews} {
		raw, e := json.MarshalIndent(value, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, '\n')
		if *updateWindowsMaintenanceSeriesFixture {
			if e = os.MkdirAll("testdata", 0755); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, raw, 0644); e != nil {
				t.Fatal(e)
			}
		}
		want, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(raw, want) {
			t.Fatal("series fixture changed; review before regeneration", path, e)
		}
	}
}
