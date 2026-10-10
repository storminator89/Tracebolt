//go:build windows

package windowsupdates

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

// MS-UAMG 1.9 CLSID_UpdateSession. A constant CLSID avoids ProgID resolution's
// legacy class-registration behavior. Activation is local in-process only.
var updateSessionID = windows.GUID{Data1: 0x4cb43d7f, Data2: 0x7eee, Data3: 0x4906, Data4: [8]byte{0x86, 0x98, 0x60, 0xda, 0x1c, 0x38, 0xf2, 0xfe}}
var dispatchID = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var nullID windows.GUID

const (
	vtI4           = 3
	vtBSTR         = 8
	vtDispatch     = 9
	vtBool         = 11
	dispatchMethod = 1
	dispatchGet    = 2
	dispatchPut    = 4
)

// VARIANT's union includes a two-pointer BRECORD: 24 bytes on x64/ARM64,
// 16 bytes on 386, with data at offset 8 on all three. No coercion, BYREF,
// SAFEARRAY or nested VARIANT is accepted by this metadata-only boundary.
type variant struct {
	kind     uint16
	reserved [3]uint16
	data     [2]uintptr
}

// pointer reads the native pointer member of the VARIANT union in place. The
// numeric storage remains uintptr so scalar variants are not scanned as Go
// pointers; a pointer is never round-tripped through a Go uintptr temporary.
func (v *variant) pointer() unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&v.data[0]))
}

type dispatchParams struct {
	args       *variant
	named      *int32
	count      uint32
	namedCount uint32
}
type dispatchObject struct{ table *[7]uintptr }
type automation struct{ object *dispatchObject }

type nativeSource struct {
	session, searcher *automation
	closed            bool
}
type nativeResult struct{ result, updates *automation }

func hrError(hr uintptr) error {
	if int32(uint32(hr)) >= 0 {
		return nil
	}
	if uint32(hr) == 0x80070005 {
		return ErrDenied
	}
	return ErrUnavailable
}
func openNative(ctx context.Context) (Source, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	for _, proc := range []*windows.LazyProc{coInitializeEx, coUninitialize, coCreateInstance, variantClear, sysAllocStringLen, sysStringLen} {
		if proc.Find() != nil {
			return nil, ErrUnavailable
		}
	}
	runtime.LockOSThread()
	if e := verifyNativeActivationTrust(); e != nil {
		runtime.UnlockOSThread()
		return nil, e
	}
	hr, _, _ := coInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED; no callbacks.
	if e := hrError(hr); e != nil {
		runtime.UnlockOSThread()
		return nil, e
	}
	s := &nativeSource{}
	var ptr *dispatchObject
	hr, _, _ = coCreateInstance.Call(uintptr(unsafe.Pointer(&updateSessionID)), 0, 1, uintptr(unsafe.Pointer(&dispatchID)), uintptr(unsafe.Pointer(&ptr))) // CLSCTX_INPROC_SERVER
	if e := hrError(hr); e != nil {
		s.Close()
		return nil, e
	}
	if ptr == nil {
		s.Close()
		return nil, ErrUnavailable
	}
	s.session = &automation{object: ptr}
	searcher, e := s.session.objectValue(ctx, "CreateUpdateSearcher", dispatchMethod)
	if e != nil {
		s.Close()
		return nil, e
	}
	s.searcher = searcher
	return s, nil
}
func (s *nativeSource) Close() {
	if s.closed {
		return
	}
	s.closed = true
	if s.searcher != nil {
		s.searcher.close()
	}
	if s.session != nil {
		s.session.close()
	}
	coUninitialize.Call()
	runtime.UnlockOSThread()
}
func (s *nativeSource) SetOnline(ctx context.Context, v bool) error {
	if v {
		return ErrOffline
	}
	return s.searcher.putFalse(ctx, "Online")
}
func (s *nativeSource) Online(ctx context.Context) (bool, error) {
	return s.searcher.boolean(ctx, "Online")
}
func (s *nativeSource) SetAutomaticUpgrade(ctx context.Context, v bool) error {
	if v {
		return ErrOffline
	}
	return s.searcher.putFalse(ctx, "CanAutomaticallyUpgradeService")
}
func (s *nativeSource) AutomaticUpgrade(ctx context.Context) (bool, error) {
	return s.searcher.boolean(ctx, "CanAutomaticallyUpgradeService")
}
func (s *nativeSource) Search(ctx context.Context, criteria string) (Result, error) {
	if criteria != SearchCriteria {
		return nil, ErrInvalid
	}
	arg, e := bstrArgument(criteria)
	if e != nil {
		return nil, e
	}
	defer arg.clear()
	obj, e := s.searcher.objectValue(ctx, "Search", dispatchMethod, arg)
	if e != nil {
		return nil, e
	}
	return &nativeResult{result: obj}, nil
}
func (r *nativeResult) Close() {
	if r.updates != nil {
		r.updates.close()
	}
	if r.result != nil {
		r.result.close()
	}
}
func (r *nativeResult) Code(ctx context.Context) (int32, error) {
	return r.result.integer(ctx, "ResultCode")
}
func (r *nativeResult) Count(ctx context.Context) (int32, error) {
	if r.updates == nil {
		obj, e := r.result.objectValue(ctx, "Updates", dispatchGet)
		if e != nil {
			return 0, e
		}
		r.updates = obj
	}
	return r.updates.integer(ctx, "Count")
}
func (r *nativeResult) Item(ctx context.Context, index int32) (Update, error) {
	if index < 0 || index >= MaxNativeRows || r.updates == nil {
		return Update{}, ErrInvalid
	}
	obj, e := r.updates.objectValue(ctx, "Item", dispatchGet, intArgument(index))
	if e != nil {
		return Update{}, e
	}
	defer obj.close()
	// Verify eligibility even though the fixed search already requested it.
	typ, e := obj.integer(ctx, "Type")
	if e != nil {
		return Update{}, e
	}
	if typ != 1 {
		return Update{}, ErrMetadata
	} // utSoftware
	installed, e := obj.boolean(ctx, "IsInstalled")
	if e != nil {
		return Update{}, e
	}
	hidden, e := obj.boolean(ctx, "IsHidden")
	if e != nil {
		return Update{}, e
	}
	if installed || hidden {
		return Update{}, ErrMetadata
	}
	identity, e := obj.objectValue(ctx, "Identity", dispatchGet)
	if e != nil {
		return Update{}, e
	}
	defer identity.close()
	id, e := identity.text(ctx, "UpdateID", 36)
	if e != nil {
		return Update{}, e
	}
	rev, e := identity.integer(ctx, "RevisionNumber")
	if e != nil {
		return Update{}, e
	}
	if rev < 0 {
		return Update{}, ErrMetadata
	}
	title, e := obj.text(ctx, "Title", MaxNativeStringUnits)
	if e != nil {
		return Update{}, e
	}
	severity, e := obj.text(ctx, "MsrcSeverity", 16)
	if e != nil {
		return Update{}, e
	}
	downloaded, e := obj.boolean(ctx, "IsDownloaded")
	if e != nil {
		return Update{}, e
	}
	kb, e := obj.objectValue(ctx, "KBArticleIDs", dispatchGet)
	if e != nil {
		return Update{}, e
	}
	defer kb.close()
	count, e := kb.integer(ctx, "Count")
	if e != nil {
		return Update{}, e
	}
	if count < 0 {
		return Update{}, ErrMetadata
	}
	u := Update{UpdateID: id, Revision: uint32(rev), Title: title, Severity: severity, Downloaded: downloaded, KBArticleIDs: []string{}}
	if count > MaxKBArticles {
		count = MaxKBArticles
		u.MetadataTruncated = true
	}
	for i := int32(0); i < count; i++ {
		v, e := kb.text(ctx, "Item", 12, intArgument(i))
		if e != nil {
			return Update{}, e
		}
		u.KBArticleIDs = append(u.KBArticleIDs, v)
	}
	return u, nil
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
	if a == nil || a.object == nil || len(args) > 1 {
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
	named := int32(-3) // DISPID_PROPERTYPUT
	if flags == dispatchPut {
		params.named = &named
		params.namedCount = 1
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
func (a *automation) putFalse(ctx context.Context, name string) error {
	v, e := a.invoke(ctx, name, dispatchPut, variant{kind: vtBool})
	if e == nil {
		v.clear()
	}
	return e
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
func (a *automation) boolean(ctx context.Context, name string) (bool, error) {
	v, e := a.invoke(ctx, name, dispatchGet)
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
	return decodeNativeString(units)
}
