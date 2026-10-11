//go:build windows

package windowsstorage

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var arrayDim = oleaut32.NewProc("SafeArrayGetDim")
var arrayLBound = oleaut32.NewProc("SafeArrayGetLBound")
var arrayUBound = oleaut32.NewProc("SafeArrayGetUBound")
var arrayVartype = oleaut32.NewProc("SafeArrayGetVartype")
var arrayElement = oleaut32.NewProc("SafeArrayGetElement")

func variantUint16(v variant) (uint16, error) {
	switch v.kind {
	case 3:
		n := int32(uint32(v.data[0]))
		if n >= 0 && n <= 65535 {
			return uint16(n), nil
		}
	case 18:
		return uint16(v.data[0]), nil
	case 19:
		n := uint32(v.data[0])
		if n <= 65535 {
			return uint16(n), nil
		}
	}
	return 0, ErrMetadata
}
func (a *automation) uint16Value(ctx context.Context, name string) (uint16, error) {
	v, e := a.invoke(ctx, name, dispatchGet)
	if e != nil {
		return 0, e
	}
	defer v.clear()
	return variantUint16(v)
}
func (a *automation) uint16Array(ctx context.Context, name string) ([]uint16, error) {
	v, e := a.invoke(ctx, name, dispatchGet)
	if e != nil {
		return nil, e
	}
	defer v.clear()
	typ := v.kind & ^uint16(0x2000)
	if v.kind&0x2000 == 0 || (typ != 3 && typ != 18 && typ != 19) || v.data[0] == 0 {
		return nil, ErrMetadata
	}
	for _, p := range []*windows.LazyProc{arrayDim, arrayLBound, arrayUBound, arrayVartype, arrayElement} {
		if p.Find() != nil {
			return nil, ErrUnsupported
		}
	}
	ptr := v.data[0]
	dim, _, _ := arrayDim.Call(ptr)
	if dim != 1 {
		return nil, ErrBounds
	}
	var vt uint16
	hr, _, _ := arrayVartype.Call(ptr, uintptr(unsafe.Pointer(&vt)))
	if hrError(hr) != nil || vt != typ {
		return nil, ErrMetadata
	}
	var lo, hi int32
	hr, _, _ = arrayLBound.Call(ptr, 1, uintptr(unsafe.Pointer(&lo)))
	if hrError(hr) != nil {
		return nil, ErrMetadata
	}
	hr, _, _ = arrayUBound.Call(ptr, 1, uintptr(unsafe.Pointer(&hi)))
	if hrError(hr) != nil {
		return nil, ErrMetadata
	}
	count := int64(hi) - int64(lo) + 1
	if count < 0 || count > MaxOperationalStatuses {
		return nil, ErrBounds
	}
	out := []uint16{}
	seen := map[uint16]bool{}
	for i := int64(0); i < count; i++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		index := int32(int64(lo) + i)
		var n uint32
		hr, _, _ := arrayElement.Call(ptr, uintptr(unsafe.Pointer(&index)), uintptr(unsafe.Pointer(&n)))
		runtime.KeepAlive(v)
		if hrError(hr) != nil {
			return nil, ErrMetadata
		}
		value, e := variantUint16(variant{kind: typ, data: [2]uintptr{uintptr(n)}})
		if e != nil || seen[value] {
			return nil, ErrMetadata
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}
