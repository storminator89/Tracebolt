//go:build windows

package windowsupdateexecutor

import (
	"context"
	job "localrmm/internal/windowsupdatejob"
	"runtime"
	"syscall"
	"time"
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

// Fixed Microsoft WUA identifiers (MS-UAMG and Microsoft wuapi.h). Never resolve
// a ProgID, accept a CLSID/path from input, use a remote server or register one.
var sessionID = windows.GUID{Data1: 0x4cb43d7f, Data2: 0x7eee, Data3: 0x4906, Data4: [8]byte{0x86, 0x98, 0x60, 0xda, 0x1c, 0x38, 0xf2, 0xfe}}
var collectionID = windows.GUID{Data1: 0x13639463, Data2: 0x00db, Data3: 0x4646, Data4: [8]byte{0x80, 0x3d, 0x52, 0x80, 0x26, 0x14, 0x0d, 0x88}}
var installer2ID = windows.GUID{Data1: 0x3442d4fe, Data2: 0x224d, Data3: 0x4cee, Data4: [8]byte{0x98, 0xcf, 0x30, 0xe0, 0xc4, 0xd2, 0x29, 0xe6}}
var dispatchID = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var unknownID = windows.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var nullID windows.GUID

const (
	vtEmpty    = 0
	vtI4       = 3
	vtBSTR     = 8
	vtDispatch = 9
	vtBool     = 11
)

// VARIANT includes a two-pointer BRECORD union: 24 bytes on 64-bit, 16 on 386.
type variant struct {
	kind     uint16
	reserved [3]uint16
	data     [2]uintptr
}

func (v *variant) pointer() unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.data[0])) }
func (v *variant) clear()                  { variantClear.Call(uintptr(unsafe.Pointer(v))); *v = variant{} }

type dispatchParams struct {
	args              *variant
	named             *int32
	count, namedCount uint32
}
type dispatchObject struct{ table *[7]uintptr }
type nativeObject struct{ ptr *dispatchObject }
type nativeRuntime struct{}

func hrError(hr uintptr) error {
	if int32(uint32(hr)) < 0 {
		return ErrUnavailable
	}
	return nil
}
func openNative(ctx context.Context) (comRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// This is already the owner's locked thread. Prove privileges before loading
	// the fixed system COM libraries or touching WUA.
	if err := verifyNativeToken(); err != nil {
		return nil, err
	}
	for _, p := range []*windows.LazyProc{coInitializeEx, coUninitialize, coCreateInstance, variantClear, sysAllocStringLen, sysStringLen} {
		if p.Find() != nil {
			return nil, ErrUnavailable
		}
	}
	hr, _, _ := coInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED, no callbacks.
	if err := hrError(hr); err != nil {
		return nil, err
	}
	return &nativeRuntime{}, nil
}
func (n *nativeRuntime) close()             { coUninitialize.Call() }
func (n *nativeRuntime) verifyToken() error { return verifyNativeToken() }
func activate(ctx context.Context, id *windows.GUID) (comObject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := verifyNativeToken(); err != nil {
		return nil, err
	}
	var ptr *dispatchObject
	hr, _, _ := coCreateInstance.Call(uintptr(unsafe.Pointer(id)), 0, 1, uintptr(unsafe.Pointer(&dispatchID)), uintptr(unsafe.Pointer(&ptr))) // CLSCTX_INPROC_SERVER only
	if err := hrError(hr); err != nil {
		if ptr != nil {
			(&nativeObject{ptr: ptr}).close()
		}
		return nil, err
	}
	if ptr == nil {
		return nil, ErrUnavailable
	}
	return &nativeObject{ptr: ptr}, nil
}
func (n *nativeRuntime) session(ctx context.Context) (comObject, error) {
	return activate(ctx, &sessionID)
}
func (n *nativeRuntime) collection(ctx context.Context) (comObject, error) {
	return activate(ctx, &collectionID)
}
func (n *nativeRuntime) installer2(ctx context.Context, obj comObject) (comObject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o, ok := obj.(*nativeObject)
	if !ok {
		return nil, ErrSettings
	}
	return o.query(&installer2ID)
}
func (o *nativeObject) close() {
	if o != nil && o.ptr != nil {
		syscall.SyscallN(o.ptr.table[2], uintptr(unsafe.Pointer(o.ptr)))
		o.ptr = nil
	}
}
func (o *nativeObject) query(id *windows.GUID) (*nativeObject, error) {
	if o == nil || o.ptr == nil {
		return nil, ErrClosed
	}
	var ptr *dispatchObject
	hr, _, _ := syscall.SyscallN(o.ptr.table[0], uintptr(unsafe.Pointer(o.ptr)), uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(&ptr)))
	runtime.KeepAlive(o)
	if hrError(hr) != nil || ptr == nil {
		if ptr != nil {
			(&nativeObject{ptr: ptr}).close()
		}
		return nil, ErrUnavailable
	}
	return &nativeObject{ptr: ptr}, nil
}
func (o *nativeObject) same(other comObject) (bool, error) {
	b, ok := other.(*nativeObject)
	if !ok {
		return false, ErrIdentity
	}
	aID, err := o.query(&unknownID)
	if err != nil {
		return false, err
	}
	defer aID.close()
	bID, err := b.query(&unknownID)
	if err != nil {
		return false, err
	}
	defer bID.close()
	return aID.ptr == bID.ptr, nil
}
func (o *nativeObject) invoke(ctx context.Context, name string, flags uint16, args ...value) (value, error) {
	if err := ctx.Err(); err != nil {
		return value{}, err
	}
	if o == nil || o.ptr == nil || len(args) > 1 || (flags != method && flags != get && flags != put) {
		return value{}, ErrUnavailable
	}
	member, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return value{}, ErrUnavailable
	}
	var id int32
	hr, _, _ := syscall.SyscallN(o.ptr.table[5], uintptr(unsafe.Pointer(o.ptr)), uintptr(unsafe.Pointer(&nullID)), uintptr(unsafe.Pointer(&member)), 1, 0x0409, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(member)
	if hrError(hr) != nil {
		return value{}, ErrUnavailable
	}
	var arg variant
	if len(args) == 1 {
		a := args[0]
		switch a.kind {
		case boolKind:
			arg.kind = vtBool
			if a.boolean {
				arg.data[0] = 0xffff
			}
		case intKind:
			arg.kind = vtI4
			arg.data[0] = uintptr(uint32(a.number))
		case objectKind:
			ref, ok := a.object.(*nativeObject)
			if !ok || ref.ptr == nil {
				return value{}, ErrUnavailable
			}
			arg.kind = vtDispatch
			*(*unsafe.Pointer)(unsafe.Pointer(&arg.data[0])) = unsafe.Pointer(ref.ptr)
		case textKind:
			units := utf16.Encode([]rune(a.text))
			if len(units) == 0 || len(units) > 256 {
				return value{}, ErrUnavailable
			}
			p, _, _ := sysAllocStringLen.Call(uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)))
			runtime.KeepAlive(units)
			if p == 0 {
				return value{}, ErrUnavailable
			}
			arg.kind = vtBSTR
			arg.data[0] = p
			defer arg.clear()
		default:
			return value{}, ErrUnavailable
		}
	}
	params := dispatchParams{count: uint32(len(args))}
	if len(args) > 0 {
		params.args = &arg
	}
	named := int32(-3)
	if flags == put {
		params.named = &named
		params.namedCount = 1
	}
	if name == "Install" && flags == method {
		if err := verifyNativeToken(); err != nil {
			return value{}, err
		}
		// Name resolution/token queries can block. Repeat the two volatile
		// installer gates after them, immediately before the final time fence.
		reboot, err := getBool(ctx, o, "RebootRequiredBeforeInstallation")
		if err != nil || reboot {
			return value{}, ErrReadiness
		}
		busy, err := getBool(ctx, o, "IsBusy")
		if err != nil || busy {
			return value{}, ErrReadiness
		}
	}
	if err := ctx.Err(); err != nil {
		return value{}, err
	}
	if name == "Install" && flags == method {
		if err := job.CheckNativeInstallStart(ctx, time.Now()); err != nil {
			return value{}, err
		}
	}
	var out variant
	// No EXCEPINFO: never collect vendor prose, paths, URLs or source-media text.
	hr, _, _ = syscall.SyscallN(o.ptr.table[6], uintptr(unsafe.Pointer(o.ptr)), uintptr(uint32(id)), uintptr(unsafe.Pointer(&nullID)), 0x0409, uintptr(flags), uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&out)), 0, 0)
	runtime.KeepAlive(args)
	runtime.KeepAlive(arg)
	runtime.KeepAlive(params)
	runtime.KeepAlive(o)
	defer out.clear()
	if hrError(hr) != nil {
		return value{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return value{}, err
	}
	switch out.kind {
	case vtEmpty:
		return value{kind: emptyKind}, nil
	case vtI4:
		return integer(int32(uint32(out.data[0]))), nil
	case vtBool:
		b := uint16(out.data[0])
		if b != 0 && b != 0xffff {
			return value{}, ErrReadiness
		}
		return boolean(b == 0xffff), nil
	case vtDispatch:
		if out.pointer() == nil {
			return value{}, ErrUnavailable
		}
		ref := &nativeObject{ptr: (*dispatchObject)(out.pointer())}
		out = variant{}
		return objectArg(ref), nil
	case vtBSTR:
		if out.data[0] == 0 {
			return value{kind: textKind}, nil
		}
		size, _, _ := sysStringLen.Call(out.data[0])
		if size > 36 {
			return value{}, ErrIdentity
		}
		units := unsafe.Slice((*uint16)(out.pointer()), int(size))
		// The only returned string is an ASCII GUID. Never normalize malformed UTF-16.
		b := make([]byte, len(units))
		for i, u := range units {
			if u > 127 || u == 0 {
				return value{}, ErrIdentity
			}
			b[i] = byte(u)
		}
		return value{kind: textKind, text: string(b)}, nil
	default:
		return value{}, ErrUnavailable
	}
}
