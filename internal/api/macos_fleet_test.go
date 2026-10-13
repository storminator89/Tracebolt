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

func TestMacOSInventoryFourthFleetDomainKeepsOriginalIdentity(t *testing.T) {
	sources := make([]fleetGroupSource, 0, 4)
	profiles := []string{enrollmentcrypto.CollectionProfileWindowsInventory, enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileMacOSInventory}
	platforms := []string{"windows", "linux", "darwin", "darwin"}
	for i, profile := range profiles {
		f := newFleetGroupSource()
		f.binding.CollectionProfile = profile
		f.snapshots[0].Binding = f.binding
		f.snapshots[0].Platform = platforms[i]
		id := "agent_" + strings.Repeat(string(rune('1'+i)), 32)
		f.snapshots[0].Approval.DeviceID = id
		f.devices[0].ID = id
		f.inputs[0].DeviceID = id
		if len(sources) > 0 {
			f.now = sources[0].Now()
		}
		sources = append(sources, f)
	}
	_, _, devices, err := fleetGroupAdmission(context.Background(), sources)
	if err != nil || len(devices) != 4 {
		t.Fatal("four enrollment domains did not coexist", err, len(devices))
	}
	basic := sources[2].(*fixtureFleetGroupSource)
	inventory := sources[3].(*fixtureFleetGroupSource)
	if devices[inventory.devices[0].ID].Platform != "macos" || devices[basic.devices[0].ID].identity == devices[inventory.devices[0].ID].identity {
		t.Fatal("fresh scope identity was conflated")
	}
	inventory.snapshots[0].Approval.DeviceID = basic.snapshots[0].Approval.DeviceID
	inventory.devices[0].ID = basic.devices[0].ID
	if _, _, _, err = fleetGroupAdmission(context.Background(), sources); err == nil {
		t.Fatal("basic and expanded identity collision admitted")
	}
	if _, _, _, err = fleetGroupAdmission(context.Background(), append(sources, newFleetGroupSource())); err == nil {
		t.Fatal("fifth unbounded domain admitted")
	}
}
