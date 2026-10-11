//go:build windows

package windowshardware

import (
	"context"
	"testing"
	"unsafe"
)

func TestFixedHardwareQueriesAndPowerABI(t *testing.T) {
	if unsafe.Sizeof(systemPowerStatus{}) != 12 || unsafe.Offsetof(systemPowerStatus{}.BatteryLifeTime) != 4 || unsafe.Offsetof(systemPowerStatus{}.BatteryFullLifeTime) != 8 {
		t.Fatal("SYSTEM_POWER_STATUS ABI")
	}
	if hardwareNamespace != `Root\CIMV2` || systemQuery != "SELECT Manufacturer, Model FROM Win32_ComputerSystem" || firmwareQuery != "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS" || chassisQuery != "SELECT SerialNumber FROM Win32_SystemEnclosure" {
		t.Fatal("fixed source widened")
	}
	if e := fixedSingleton(context.Background(), "SELECT * FROM Win32_BIOS", func(*automation) error { t.Fatal("arbitrary query opened"); return nil }); e != ErrInvalid {
		t.Fatal("arbitrary query accepted")
	}
}
