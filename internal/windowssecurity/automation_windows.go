//go:build windows

package windowssecurity

import (
	"context"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ole32 = windows.NewLazySystemDLL("ole32.dll")
var oleaut32 = windows.NewLazySystemDLL("oleaut32.dll")
var coInitializeEx = ole32.NewProc("CoInitializeEx")
var coUninitialize = ole32.NewProc("CoUninitialize")
var coCreateInstance = ole32.NewProc("CoCreateInstance")
var variantClear = oleaut32.NewProc("VariantClear")
var sysAllocStringLen = oleaut32.NewProc("SysAllocStringLen")
var sysStringLen = oleaut32.NewProc("SysStringLen")

var dispatchID = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var nullID windows.GUID

const (
	vtI4                 = 3
	vtBSTR               = 8
	vtDispatch           = 9
	vtBool               = 11
	dispatchMethod       = 1
	dispatchGet          = 2
	MaxNativeStringUnits = 512
)

type variant struct {
	kind     uint16
	reserved [3]uint16
	data     [2]uintptr
}

func (v *variant) pointer() unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.data[0])) }

type dispatchParams struct {
	args       *variant
	named      *int32
	count      uint32
	namedCount uint32
}
type dispatchObject struct{ table *[7]uintptr }
type automation struct{ object *dispatchObject }

func hrError(hr uintptr) error {
	if int32(uint32(hr)) >= 0 {
		return nil
	}
	switch uint32(hr) {
	case 0x80070005, 0x80041003:
		return ErrDenied
	case 0x8004100e, 0x80041010, 0x80040154:
		return ErrUnsupported
	default:
		return ErrUnavailable
	}
}

// Locked high/system integrity and no impersonation prevent per-user COM class
// activation. Fixed local CLSIDs only, no elevation or credential changes.
func openAutomation(ctx context.Context, id *windows.GUID) (*automation, func(), error) {
	noop := func() {}
	if e := ctx.Err(); e != nil {
		return nil, noop, e
	}
	for _, p := range []*windows.LazyProc{coInitializeEx, coUninitialize, coCreateInstance, variantClear, sysAllocStringLen, sysStringLen} {
		if p.Find() != nil {
			return nil, noop, ErrUnavailable
		}
	}
	runtime.LockOSThread()
	if e := verifyNativeActivationTrust(); e != nil {
		runtime.UnlockOSThread()
		return nil, noop, e
	}
	hr, _, _ := coInitializeEx.Call(0, 2)
	if e := hrError(hr); e != nil {
		runtime.UnlockOSThread()
		return nil, noop, e
	}
	finish := func() { coUninitialize.Call(); runtime.UnlockOSThread() }
	var ptr *dispatchObject
	hr, _, _ = coCreateInstance.Call(uintptr(unsafe.Pointer(id)), 0, 1, uintptr(unsafe.Pointer(&dispatchID)), uintptr(unsafe.Pointer(&ptr)))
	if e := hrError(hr); e != nil {
		finish()
		return nil, noop, e
	}
	if ptr == nil {
		finish()
		return nil, noop, ErrUnavailable
	}
	a := &automation{ptr}
	return a, func() { a.close(); finish() }, nil
}
func (a *automation) close() {
	if a != nil && a.object != nil {
		syscall.SyscallN(a.object.table[2], uintptr(unsafe.Pointer(a.object)))
		a.object = nil
	}
}
func (v *variant) clear()         { variantClear.Call(uintptr(unsafe.Pointer(v))); *v = variant{} }
func intArgument(n int32) variant { return variant{kind: vtI4, data: [2]uintptr{uintptr(uint32(n))}} }
func bstrArgument(s string) (variant, error) {
	u := utf16.Encode([]rune(s))
	if len(u) == 0 || len(u) > MaxNativeStringUnits {
		return variant{}, ErrInvalid
	}
	p, _, _ := sysAllocStringLen.Call(uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)))
	runtime.KeepAlive(u)
	if p == 0 {
		return variant{}, ErrUnavailable
	}
	return variant{kind: vtBSTR, data: [2]uintptr{p}}, nil
}
func (a *automation) invoke(ctx context.Context, name string, flags uint16, args ...variant) (variant, error) {
	if e := ctx.Err(); e != nil {
		return variant{}, e
	}
	if a == nil || a.object == nil || len(args) > 3 || (flags != dispatchMethod && flags != dispatchGet) {
		return variant{}, ErrInvalid
	}
	str, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return variant{}, ErrInvalid
	}
	var id int32
	hr, _, _ := syscall.SyscallN(a.object.table[5], uintptr(unsafe.Pointer(a.object)), uintptr(unsafe.Pointer(&nullID)), uintptr(unsafe.Pointer(&str)), 1, 0x0409, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(str)
	if e = hrError(hr); e != nil {
		return variant{}, e
	}
	if e = ctx.Err(); e != nil {
		return variant{}, e
	}
	params := dispatchParams{count: uint32(len(args))}
	if len(args) > 0 {
		params.args = &args[0]
	}
	var out variant
	// pExcepInfo is deliberately nil: vendor error prose, URLs and paths are
	// neither requested nor retained. HRESULT is mapped to fixed public reasons.
	hr, _, _ = syscall.SyscallN(a.object.table[6], uintptr(unsafe.Pointer(a.object)), uintptr(uint32(id)), uintptr(unsafe.Pointer(&nullID)), 0x0409, uintptr(flags), uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&out)), 0, 0)
	runtime.KeepAlive(args)
	runtime.KeepAlive(params)
	runtime.KeepAlive(a)
	if e = hrError(hr); e != nil {
		out.clear()
		return variant{}, e
	}
	if e = ctx.Err(); e != nil {
		out.clear()
		return variant{}, e
	}
	return out, nil
}
func (a *automation) objectValue(ctx context.Context, name string, flags uint16, args ...variant) (*automation, error) {
	v, e := a.invoke(ctx, name, flags, args...)
	if e != nil {
		return nil, e
	}
	if v.kind != vtDispatch || v.data[0] == 0 {
		v.clear()
		return nil, ErrMetadata
	}
	// Transfer ownership of the returned reference; exactly one close releases it.
	obj := &automation{object: (*dispatchObject)(v.pointer())}
	v = variant{}
	return obj, nil
}
func (a *automation) integer(ctx context.Context, name string) (int32, error) {
	v, e := a.invoke(ctx, name, dispatchGet)
	if e != nil {
		return 0, e
	}
	defer v.clear()
	if v.kind != vtI4 {
		return 0, ErrMetadata
	}
	return int32(uint32(v.data[0])), nil
}
func (a *automation) boolean(ctx context.Context, name string, args ...variant) (bool, error) {
	v, e := a.invoke(ctx, name, dispatchGet, args...)
	if e != nil {
		return false, e
	}
	defer v.clear()
	if v.kind != vtBool {
		return false, ErrMetadata
	}
	n := uint16(v.data[0])
	if n != 0 && n != 0xffff {
		return false, ErrMetadata
	}
	return n == 0xffff, nil
}
func (a *automation) text(ctx context.Context, name string, maxUnits int, args ...variant) (string, error) {
	v, e := a.invoke(ctx, name, dispatchGet, args...)
	if e != nil {
		return "", e
	}
	defer v.clear()
	if v.kind != vtBSTR {
		return "", ErrMetadata
	}
	if v.data[0] == 0 {
		return "", nil
	}
	n, _, _ := sysStringLen.Call(v.data[0])
	if n > uintptr(maxUnits) || n > MaxNativeStringUnits {
		return "", ErrBounds
	}
	// Never scan for a terminator or copy the unbounded BSTR. Reject unpaired
	// surrogates so malformed native metadata cannot become replacement text.
	units := unsafe.Slice((*uint16)(v.pointer()), int(n))
	for _, u := range units {
		if u == 0 || u > 127 {
			return "", ErrMetadata
		}
	}
	return string(utf16.Decode(units)), nil
}
