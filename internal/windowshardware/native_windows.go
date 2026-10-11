//go:build windows

package windowshardware

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unsafe"
)

var locatorID = windows.GUID{Data1: 0x76a64158, Data2: 0xcb41, Data3: 0x11d1, Data4: [8]byte{0x8b, 0x02, 0x00, 0x60, 0x08, 0x06, 0xd9, 0xb6}}
var enumID = windows.GUID{Data1: 0x00020404, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}

const hardwareNamespace = `Root\CIMV2`
const systemQuery = "SELECT Manufacturer, Model FROM Win32_ComputerSystem"
const firmwareQuery = "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber FROM Win32_BIOS"
const chassisQuery = "SELECT SerialNumber FROM Win32_SystemEnclosure"

// Fixed local WQL, forward-only semisynchronous; exactly two Next calls detect
// unexpected multiplicity. Multiple enclosures are unavailable/bounds rather
// than an invented unique physical serial. No caller can supply query text.
func fixedSingleton(ctx context.Context, queryText string, read func(*automation) error) error {
	if read == nil || (queryText != systemQuery && queryText != firmwareQuery && queryText != chassisQuery) {
		return ErrInvalid
	}
	locator, close, e := openAutomation(ctx, &locatorID)
	if e != nil {
		return e
	}
	defer close()
	server, e := bstrArgument(".")
	if e != nil {
		return e
	}
	defer server.clear()
	namespace, e := bstrArgument(hardwareNamespace)
	if e != nil {
		return e
	}
	defer namespace.clear()
	service, e := locator.objectValue(ctx, "ConnectServer", dispatchMethod, namespace, server)
	if e != nil {
		return e
	}
	defer service.close()
	query, e := bstrArgument(queryText)
	if e != nil {
		return e
	}
	defer query.clear()
	language, e := bstrArgument("WQL")
	if e != nil {
		return e
	}
	defer language.clear()
	rows, e := service.objectValue(ctx, "ExecQuery", dispatchMethod, intArgument(0x30), language, query)
	if e != nil {
		return e
	}
	defer rows.close()
	enumeration, e := rows.invoke(ctx, "_NewEnum", dispatchGet)
	if e != nil {
		return e
	}
	defer enumeration.clear()
	if enumeration.kind != 13 && enumeration.kind != vtDispatch || enumeration.data[0] == 0 {
		return ErrMetadata
	}
	unknown := (*dispatchObject)(enumeration.pointer())
	var enumerator *dispatchObject
	hr, _, _ := syscall.SyscallN(unknown.table[0], uintptr(unsafe.Pointer(unknown)), uintptr(unsafe.Pointer(&enumID)), uintptr(unsafe.Pointer(&enumerator)))
	if e = hrError(hr); e != nil {
		return e
	}
	if enumerator == nil {
		return ErrMetadata
	}
	defer syscall.SyscallN(enumerator.table[2], uintptr(unsafe.Pointer(enumerator)))
	next := func() (variant, uint32, error) {
		var value variant
		var fetched uint32
		if e := ctx.Err(); e != nil {
			return value, 0, e
		}
		hr, _, _ := syscall.SyscallN(enumerator.table[3], uintptr(unsafe.Pointer(enumerator)), 1, uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&fetched)))
		runtime.KeepAlive(enumerator)
		if e := hrError(hr); e != nil {
			value.clear()
			return variant{}, 0, e
		}
		if fetched > 1 {
			value.clear()
			return variant{}, 0, ErrBounds
		}
		return value, fetched, nil
	}
	value, n, e := next()
	if e != nil {
		return e
	}
	defer value.clear()
	if n == 0 {
		return ErrUnsupported
	}
	if value.kind != vtDispatch || value.data[0] == 0 {
		return ErrMetadata
	}
	object := &automation{(*dispatchObject)(value.pointer())}
	extra, count, e := next()
	extra.clear()
	if e != nil {
		return e
	}
	if count != 0 {
		return ErrBounds
	}
	return read(object)
}

func nativeField(ctx context.Context, o *automation, name string, limit int) Field {
	v, e := o.text(ctx, name, limit)
	return observedField(v, e, limit)
}
func nativeSystem(ctx context.Context) (System, error) {
	s := EmptySystem(ErrUnavailable.Error())
	e := fixedSingleton(ctx, systemQuery, func(o *automation) error {
		s.Manufacturer = nativeField(ctx, o, "Manufacturer", MaxStringUnits)
		s.Model = nativeField(ctx, o, "Model", MaxStringUnits)
		s.Quality, s.Reason = finishGroup(s.Manufacturer, s.Model)
		return nil
	})
	return s, e
}
func nativeFirmware(ctx context.Context) (Firmware, error) {
	s := EmptyFirmware(ErrUnavailable.Error())
	e := fixedSingleton(ctx, firmwareQuery, func(o *automation) error {
		s.Vendor = nativeField(ctx, o, "Manufacturer", MaxStringUnits)
		s.Version = nativeField(ctx, o, "SMBIOSBIOSVersion", MaxStringUnits)
		s.ReleaseDate = nativeField(ctx, o, "ReleaseDate", 25)
		if s.ReleaseDate.Value != nil && !validDMTF(*s.ReleaseDate.Value) {
			s.ReleaseDate = emptyField(ErrMetadata.Error())
		}
		s.SerialNumber = nativeField(ctx, o, "SerialNumber", 64)
		s.Quality, s.Reason = finishGroup(s.Vendor, s.Version, s.ReleaseDate, s.SerialNumber)
		return nil
	})
	return s, e
}
func nativeChassis(ctx context.Context) (Chassis, error) {
	s := EmptyChassis(ErrUnavailable.Error())
	e := fixedSingleton(ctx, chassisQuery, func(o *automation) error {
		s.SerialNumber = nativeField(ctx, o, "SerialNumber", 64)
		s.Quality, s.Reason = finishGroup(s.SerialNumber)
		return nil
	})
	return s, e
}

var powerDLL = windows.NewLazySystemDLL("kernel32.dll")
var getSystemPowerStatus = powerDLL.NewProc("GetSystemPowerStatus")

type systemPowerStatus struct {
	ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag uint8
	BatteryLifeTime, BatteryFullLifeTime                            uint32
}

func nativePower(ctx context.Context) (Power, error) {
	if e := ctx.Err(); e != nil {
		return Power{}, e
	}
	if getSystemPowerStatus.Find() != nil {
		return Power{}, ErrUnsupported
	}
	var v systemPowerStatus
	r, _, e := getSystemPowerStatus.Call(uintptr(unsafe.Pointer(&v)))
	runtime.KeepAlive(&v)
	if r == 0 {
		if e == windows.ERROR_ACCESS_DENIED {
			return Power{}, ErrDenied
		}
		return Power{}, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return Power{}, e
	}
	return powerStatus(v.ACLineStatus, v.BatteryFlag, v.BatteryLifePercent, v.BatteryLifeTime), nil
}
