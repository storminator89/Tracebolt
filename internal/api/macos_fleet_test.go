package api

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"strings"
	"testing"
)

func TestMacOSMixedFleetLookupKeepsPlatformAndRejectsAmbiguity(t *testing.T) {
	windows := newFleetGroupSource()
	linux := newFleetGroupSource()
	mac := newFleetGroupSource()
	linux.now, mac.now = windows.now, windows.now
	linux.binding = windows.binding
	linux.binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	linux.snapshots[0].Binding = linux.binding
	linux.snapshots[0].Platform = "linux"
	linux.snapshots[0].Approval.DeviceID = "agent_" + strings.Repeat("2", 32)
	linux.devices[0].ID = linux.snapshots[0].Approval.DeviceID
	mac.binding = windows.binding
	mac.binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	mac.snapshots[0].Binding = mac.binding
	mac.snapshots[0].Platform = "darwin"
	mac.snapshots[0].Approval.DeviceID = "agent_" + strings.Repeat("3", 32)
	mac.devices[0].ID = mac.snapshots[0].Approval.DeviceID
	_, _, devices, err := fleetGroupAdmission(context.Background(), []fleetGroupSource{linux, windows, mac})
	if err != nil || len(devices) != 3 || devices[mac.devices[0].ID].Platform != "macos" {
		t.Fatal("mixed fleet projection", err)
	}
	if devices[windows.devices[0].ID].Platform != "windows" || devices[linux.devices[0].ID].Platform != "linux" {
		t.Fatal("existing platforms changed")
	}
	mac.snapshots[0].Approval.DeviceID = linux.snapshots[0].Approval.DeviceID
	mac.devices[0].ID = linux.devices[0].ID
	if _, _, _, err = fleetGroupAdmission(context.Background(), []fleetGroupSource{linux, windows, mac}); err == nil {
		t.Fatal("ambiguous cross-store ID admitted")
	}
}
