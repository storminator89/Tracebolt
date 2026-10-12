package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateWindowsNotificationFixture = flag.Bool("update-windows-notification-fixture", false, "regenerate reviewed Windows notification wire fixture")

func TestWindowsNotificationsWireFixture(t *testing.T) {
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	in := capacityFixtureInput(at)
	destination := alarmdelivery.SourceDestination{Binding: strings.Repeat("a", 64), Host: "receiver.example.test", Enabled: true}
	target := maintenanceTarget(in, "disk")
	snapshot := store.WindowsNotificationSnapshot{Binding: destination.Binding, DeliveryEnabled: true, Policies: []store.WindowsNotificationPolicy{{Version: 1, Target: target, Revision: 1, Enabled: true, Binding: destination.Binding, ChangedAt: at}}, Counts: store.AlarmStatus{ProviderAccepted: 1, Suppressed: 1}}
	maintenance := []store.WindowsMaintenanceState{{Version: 1, Target: target, Revision: 1, ChangedAt: at, Windows: []store.WindowsMaintenanceWindow{{ID: 1, StartedAt: at, EndsAt: at.Add(time.Hour), Intent: "planned-work"}}}}
	view, e := projectWindowsNotifications(snapshot, maintenance, map[string]windowscapacity.Input{in.DeviceID: in}, destination, at)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.MarshalIndent(view, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-notifications-view.json")
	if *updateWindowsNotificationFixture {
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	existing, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(existing, raw) {
		t.Fatal("Windows notification Go/TypeScript fixture changed; review before regeneration", e)
	}
}
