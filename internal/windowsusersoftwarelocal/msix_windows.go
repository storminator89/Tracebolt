//go:build windows

package windowsusersoftwarelocal

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsusersoftware"
	"syscall"
	"unsafe"
)

// The fixed WinRT read uses PackageManager.FindPackagesForUser(string.Empty),
// which selects only the calling normal user; FindPackages() and FindUsers()
// are never called. No other SID can be supplied.
// https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser
// ABI and IIDs: Microsoft's windows-rs Windows/Management/Deployment and
// Windows/ApplicationModel generated bindings, verified 2026-10-11.
// https://github.com/microsoft/windows-rs/tree/master/crates/libs/windows/src/Windows
var combase = windows.NewLazySystemDLL("combase.dll")
var roInitialize = combase.NewProc("RoInitialize")
var roUninitialize = combase.NewProc("RoUninitialize")
var roActivateInstance = combase.NewProc("RoActivateInstance")
var createHString = combase.NewProc("WindowsCreateString")
var deleteHString = combase.NewProc("WindowsDeleteString")
var rawHString = combase.NewProc("WindowsGetStringRawBuffer")
var packageManagerIID = windows.GUID{Data1: 0x9a7d4b65, Data2: 0x5e8f, Data3: 0x4fc7, Data4: [8]byte{0xa2, 0xe5, 0x7f, 0x69, 0x25, 0xcb, 0x8b, 0x53}}
var packageIID = windows.GUID{Data1: 0x163c792f, Data2: 0xbd75, Data3: 0x413c, Data4: [8]byte{0xbf, 0x23, 0xb1, 0xfe, 0x7b, 0x95, 0xd8, 0x25}}
var packageIdIID = windows.GUID{Data1: 0x1adb665e, Data2: 0x37c7, Data3: 0x4790, Data4: [8]byte{0x99, 0x80, 0xdd, 0x7a, 0xe7, 0x4e, 0x8b, 0xb2}}

type comObject struct{ vtable *[32]uintptr }

func (p *comObject) call(index int, args ...uintptr) error {
	if p == nil || p.vtable == nil || index < 0 || index >= 32 {
		return errMalformed
	}
	a := append([]uintptr{uintptr(unsafe.Pointer(p))}, args...)
	hr, _, _ := syscall.SyscallN(p.vtable[index], a...)
	return hresult(hr)
}
func (p *comObject) release() {
	if p != nil && p.vtable != nil {
		syscall.SyscallN(p.vtable[2], uintptr(unsafe.Pointer(p)))
	}
}
func (p *comObject) query(iid *windows.GUID) (*comObject, error) {
	var out *comObject
	e := p.call(0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if e != nil || out == nil {
		if out != nil {
			out.release()
		}
		if e != nil {
			return nil, e
		}
		return nil, errMalformed
	}
	return out, nil
}
func hresult(hr uintptr) error {
	if int32(hr) >= 0 {
		return nil
	}
	switch uint32(hr) {
	case 0x80070005:
		return windowsusersoftware.ErrDenied
	case 0x80040154, 0x80004002, 0x8007007f:
		return windowsusersoftware.ErrUnsupported
	case 0x8000000c:
		return errChanged
	default:
		return windowsusersoftware.ErrUnavailable
	}
}
func hstring(s string) (uintptr, error) {
	units, e := windows.UTF16FromString(s)
	if e != nil {
		return 0, errMalformed
	}
	var h uintptr
	hr, _, _ := createHString.Call(uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)-1), uintptr(unsafe.Pointer(&h)))
	if e = hresult(hr); e != nil {
		return 0, e
	}
	return h, nil
}
func (p *comObject) text(index int) (*string, error) {
	var h uintptr
	if e := p.call(index, uintptr(unsafe.Pointer(&h))); e != nil {
		return nil, e
	}
	if h != 0 {
		defer deleteHString.Call(h)
	}
	var n uint32
	ptr, _, _ := rawHString.Call(h, uintptr(unsafe.Pointer(&n)))
	if n > windowsusersoftware.MaxFieldUTF16 || n > 0 && ptr == 0 {
		return nil, errMalformed
	}
	var units []uint16
	if n > 0 {
		units = unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), int(n))
	}
	text, ok := decodeUTF16(units)
	if !ok {
		return nil, errMalformed
	}
	return &text, nil
}
func readMSIX(ctx context.Context) ([]windowsusersoftware.Row, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	for _, p := range []*windows.LazyProc{roInitialize, roUninitialize, roActivateInstance, createHString, deleteHString, rawHString} {
		if p.Find() != nil {
			return nil, windowsusersoftware.ErrUnsupported
		}
	}
	hr, _, _ := roInitialize.Call(1)
	if e := hresult(hr); e != nil {
		return nil, e
	}
	defer roUninitialize.Call()
	class, e := hstring("Windows.Management.Deployment.PackageManager")
	if e != nil {
		return nil, e
	}
	defer deleteHString.Call(class)
	var instance *comObject
	hr, _, _ = roActivateInstance.Call(class, uintptr(unsafe.Pointer(&instance)))
	if e = hresult(hr); e != nil || instance == nil {
		if instance != nil {
			instance.release()
		}
		if e != nil {
			return nil, e
		}
		return nil, errMalformed
	}
	defer instance.release()
	manager, e := instance.query(&packageManagerIID)
	if e != nil {
		return nil, e
	}
	defer manager.release()
	var iterable *comObject
	// IPackageManager: IInspectable(6), five mutator slots skipped, FindPackages
	// skipped, then FindPackagesByUserSecurityId at index 12. Null HSTRING is empty.
	if e = manager.call(12, 0, uintptr(unsafe.Pointer(&iterable))); e != nil {
		return nil, e
	}
	if iterable == nil {
		return nil, errMalformed
	}
	defer iterable.release()
	var iterator *comObject
	if e = iterable.call(6, uintptr(unsafe.Pointer(&iterator))); e != nil {
		return nil, e
	}
	if iterator == nil {
		return nil, errMalformed
	}
	defer iterator.release()
	rows := []windowsusersoftware.Row{}
	total := 2
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		var has uint8
		if e = iterator.call(7, uintptr(unsafe.Pointer(&has))); e != nil {
			return nil, e
		}
		if has == 0 {
			break
		}
		if has != 1 {
			return nil, errMalformed
		}
		if len(rows) >= windowsusersoftware.MaxRows {
			return nil, windowsusersoftware.ErrBudget
		}
		row, e := readPackage(iterator)
		if e != nil {
			return nil, e
		}
		b, e := boundedRow(row)
		if e != nil {
			return nil, e
		}
		total += len(b) + 1
		if total > windowsusersoftware.MaxSourceBytes {
			return nil, windowsusersoftware.ErrBudget
		}
		rows = append(rows, row)
		var moved uint8
		if e = iterator.call(8, uintptr(unsafe.Pointer(&moved))); e != nil {
			return nil, e
		}
		if moved > 1 {
			return nil, errMalformed
		}
	}
	return rows, nil
}
func readPackage(iterator *comObject) (windowsusersoftware.Row, error) {
	var value *comObject
	if e := iterator.call(6, uintptr(unsafe.Pointer(&value))); e != nil {
		return windowsusersoftware.Row{}, e
	}
	if value == nil {
		return windowsusersoftware.Row{}, errMalformed
	}
	defer value.release()
	pkg, e := value.query(&packageIID)
	if e != nil {
		return windowsusersoftware.Row{}, e
	}
	defer pkg.release()
	var rawID *comObject
	if e = pkg.call(6, uintptr(unsafe.Pointer(&rawID))); e != nil {
		return windowsusersoftware.Row{}, e
	}
	if rawID == nil {
		return windowsusersoftware.Row{}, errMalformed
	}
	defer rawID.release()
	id, e := rawID.query(&packageIdIID)
	if e != nil {
		return windowsusersoftware.Row{}, e
	}
	defer id.release()
	full, e := id.text(12)
	if e != nil || full == nil || *full == "" {
		if e != nil {
			return windowsusersoftware.Row{}, e
		}
		return windowsusersoftware.Row{}, errMalformed
	}
	units, e := windows.UTF16FromString(*full)
	if e != nil {
		return windowsusersoftware.Row{}, errMalformed
	}
	opaque, e := windowsusersoftware.RegistrationID("msix", units[:len(units)-1])
	if e != nil {
		return windowsusersoftware.Row{}, errMalformed
	}
	row := emptyRow("msix", opaque)
	// Identity Name, not a localized shell label. No install-location, application
	// launch, license, manifest, dependency, or package-user accessor is called.
	if v, e := id.text(6); e == nil {
		setField(&row.Name, &row.NameQuality, v)
	}
	if v, e := id.text(10); e == nil {
		setField(&row.Publisher, &row.PublisherQuality, v)
	}
	var version [4]uint16
	if e = id.call(7, uintptr(unsafe.Pointer(&version))); e == nil {
		v := fmt.Sprintf("%d.%d.%d.%d", version[0], version[1], version[2], version[3])
		setField(&row.Version, &row.VersionQuality, &v)
	}
	return row, nil
}
