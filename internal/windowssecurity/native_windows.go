//go:build windows

package windowssecurity

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unsafe"
)

// Windows SDK CLSID_SWbemLocator and CLSID_NetFwPolicy2. No ProgID lookup,
// remote server, user credentials, moniker, property put or rule API is used.
var locatorID = windows.GUID{Data1: 0x76a64158, Data2: 0xcb41, Data3: 0x11d1, Data4: [8]byte{0x8b, 0x02, 0x00, 0x60, 0x08, 0x06, 0xd9, 0xb6}}
var firewallID = windows.GUID{Data1: 0xe2b3c97f, Data2: 0x6ae1, Data3: 0x41ac, Data4: [8]byte{0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}}
var enumID = windows.GUID{Data1: 0x00020404, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}

const defenderNamespace = `Root\Microsoft\Windows\Defender`
const defenderQuery = "SELECT AMRunningMode, AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion, AntivirusSignatureAge FROM MSFT_MpComputerStatus"

// One forward-only, semisynchronous fixed local singleton query. We call Next
// exactly twice to detect unexpected multiplicity, never enumerate arbitrary rows.
func nativeDefender(ctx context.Context) (Defender, error) {
	locator, close, e := openAutomation(ctx, &locatorID)
	if e != nil {
		return Defender{}, e
	}
	defer close()
	server, e := bstrArgument(".")
	if e != nil {
		return Defender{}, e
	}
	defer server.clear()
	namespace, e := bstrArgument(defenderNamespace)
	if e != nil {
		return Defender{}, e
	}
	defer namespace.clear()
	service, e := locator.objectValue(ctx, "ConnectServer", dispatchMethod, namespace, server)
	if e != nil {
		return Defender{}, e
	}
	defer service.close()
	query, e := bstrArgument(defenderQuery)
	if e != nil {
		return Defender{}, e
	}
	defer query.clear()
	language, e := bstrArgument("WQL")
	if e != nil {
		return Defender{}, e
	}
	defer language.clear()
	rows, e := service.objectValue(ctx, "ExecQuery", dispatchMethod, intArgument(0x30), language, query)
	if e != nil {
		return Defender{}, e
	}
	defer rows.close()
	enumeration, e := rows.invoke(ctx, "_NewEnum", dispatchGet)
	if e != nil {
		return Defender{}, e
	}
	defer enumeration.clear()
	if enumeration.kind != 13 && enumeration.kind != vtDispatch || enumeration.data[0] == 0 {
		return Defender{}, ErrMetadata
	}
	unknown := (*dispatchObject)(enumeration.pointer())
	var enumerator *dispatchObject
	hr, _, _ := syscall.SyscallN(unknown.table[0], uintptr(unsafe.Pointer(unknown)), uintptr(unsafe.Pointer(&enumID)), uintptr(unsafe.Pointer(&enumerator)))
	if e = hrError(hr); e != nil {
		return Defender{}, e
	}
	if enumerator == nil {
		return Defender{}, ErrMetadata
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
		return Defender{}, e
	}
	defer value.clear()
	if n == 0 {
		return Defender{}, ErrUnsupported
	}
	if value.kind != vtDispatch || value.data[0] == 0 {
		return Defender{}, ErrMetadata
	}
	object := &automation{(*dispatchObject)(value.pointer())}
	d := EmptyDefender(ErrUnavailable.Error())
	reason := ""
	mark := func(e error) {
		if e != nil && reason == "" {
			reason = SafeReason(e)
		}
	}
	mode, e := object.text(ctx, "AMRunningMode", 32)
	mark(e)
	if e == nil {
		switch mode {
		case "Normal":
			d.Mode = "normal"
		case "Passive Mode", "SxS Passive Mode":
			d.Mode = "passive"
		case "EDR Block Mode":
			d.Mode = "edr-block"
		default:
			mark(ErrMetadata)
		}
	}
	for _, field := range []struct {
		name   string
		target *string
	}{{"AMServiceEnabled", &d.ServiceEnabled}, {"AntivirusEnabled", &d.AntivirusEnabled}, {"RealTimeProtectionEnabled", &d.RealTimeProtectionEnabled}} {
		b, e := object.boolean(ctx, field.name)
		mark(e)
		if e == nil {
			*field.target = boolState(b)
		}
	}
	signature, e := object.text(ctx, "AntivirusSignatureVersion", 64)
	mark(e)
	if e == nil {
		if validSignature(signature) {
			d.SignatureVersion = &signature
		} else {
			mark(ErrMetadata)
		}
	}
	age, e := object.integer(ctx, "AntivirusSignatureAge")
	mark(e)
	if e == nil {
		if age >= 0 && age <= 65534 {
			v := uint32(age)
			d.SignatureAgeDays = &v
		} else {
			mark(ErrMetadata)
		}
	}
	extra, count, e := next()
	extra.clear()
	if e != nil {
		return Defender{}, e
	}
	if count != 0 {
		return Defender{}, ErrBounds
	}
	return finishDefender(d, reason), nil
}
func nativeFirewall(ctx context.Context) (Firewall, error) {
	policy, close, e := openAutomation(ctx, &firewallID)
	if e != nil {
		return Firewall{}, e
	}
	defer close()
	f := EmptyFirewall(ErrUnavailable.Error())
	reason := ""
	current, e := policy.integer(ctx, "CurrentProfileTypes")
	if e != nil {
		reason = SafeReason(e)
	} else if current < 0 || current & ^int32(7) != 0 {
		reason = ErrMetadata.Error()
	} else {
		for i, bit := range []int32{1, 2, 4} {
			f.Profiles[i].Active = boolState(current&bit != 0)
		}
	}
	for i, bit := range []int32{1, 2, 4} {
		enabled, e := policy.boolean(ctx, "FirewallEnabled", intArgument(bit))
		if e == nil {
			f.Profiles[i].Enabled = boolState(enabled)
		} else if reason == "" {
			reason = SafeReason(e)
		}
	}
	return finishFirewall(f, reason), nil
}
