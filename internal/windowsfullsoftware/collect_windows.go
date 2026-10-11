//go:build windows

package windowsfullsoftware

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"runtime"
	"strings"
	"time"
)

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

type nativeView struct {
	key    registry.Key
	flag   uint32
	budget *nativeBudget
}

// Collect enumerates fixed HKLM machine registration views with read-only rights.
// No arbitrary key walk, profiles, expansion, command, elevation or write exists.
func Collect(ctx context.Context) (Capture, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return collectRegistry(ctx, openNativeView, func() time.Time { return time.Now().UTC() })
}
func nativeError(e error) error {
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return ErrDenied
	}
	if errors.Is(e, windows.ERROR_KEY_DELETED) {
		return ErrChanged
	}
	return ErrUnavailable
}

// REG_OPTION_OPEN_LINK opens a link object itself rather than following its
// target. Fixed ancestors are opened one at a time, so no intermediate link can
// redirect the source into a profile or another registry subtree.
const regOptionOpenLink = uint32(0x00000008)

func openNoFollow(parent registry.Key, name string, access uint32) (registry.Key, error) {
	ptr, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	var handle windows.Handle
	e = windows.RegOpenKeyEx(windows.Handle(parent), ptr, regOptionOpenLink, access, &handle)
	return registry.Key(handle), e
}
func registryLink(ctx context.Context, key registry.Key, b *nativeBudget) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if e := b.charge(0); e != nil {
		return false, e
	}
	ptr, _ := windows.UTF16PtrFromString("SymbolicLinkValue")
	var kind, size uint32
	// Type/length only. Never read, retain or follow the link target.
	e := windows.RegQueryValueEx(windows.Handle(key), ptr, nil, &kind, nil, &size)
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if e != nil {
		return false, nativeError(e)
	}
	return kind == windows.REG_LINK, nil
}
func openNativeView(ctx context.Context, view string, budget *nativeBudget) (registryView, error) {
	flag := uint32(registry.WOW64_64KEY)
	if view == "32" {
		flag = registry.WOW64_32KEY
	}
	key := registry.LOCAL_MACHINE
	for _, component := range strings.Split(uninstallPath, `\`) {
		if e := ctx.Err(); e != nil {
			if key != registry.LOCAL_MACHINE {
				key.Close()
			}
			return nil, e
		}
		if e := budget.charge(0); e != nil {
			if key != registry.LOCAL_MACHINE {
				key.Close()
			}
			return nil, e
		}
		next, e := openNoFollow(key, component, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|flag)
		if key != registry.LOCAL_MACHINE {
			key.Close()
		}
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return nil, nil
		}
		if e != nil {
			return nil, nativeError(e)
		}
		key = next
		linked, e := registryLink(ctx, key, budget)
		if e != nil || linked {
			key.Close()
			if e != nil {
				return nil, e
			}
			return nil, ErrUnsupported
		}
	}
	return &nativeView{key: key, flag: flag, budget: budget}, nil
}

func (v *nativeView) close() error { return v.key.Close() }
func (v *nativeView) stamp(ctx context.Context) (viewStamp, error) {
	return keyStamp(ctx, v.key, v.budget)
}
func keyStamp(ctx context.Context, key registry.Key, b *nativeBudget) (viewStamp, error) {
	if e := ctx.Err(); e != nil {
		return viewStamp{}, e
	}
	if e := b.charge(0); e != nil {
		return viewStamp{}, e
	}
	var count uint32
	var modified windows.Filetime
	e := windows.RegQueryInfoKey(windows.Handle(key), nil, nil, nil, &count, nil, nil, nil, nil, nil, nil, &modified)
	if e != nil {
		return viewStamp{}, nativeError(e)
	}
	return viewStamp{count: count, modified: uint64(modified.HighDateTime)<<32 | uint64(modified.LowDateTime)}, nil
}
func (v *nativeView) next(ctx context.Context, index uint32) (nativeRegistration, bool, error) {
	empty := nativeRegistration{}
	if e := ctx.Err(); e != nil {
		return empty, false, e
	}
	var name [256]uint16
	if e := v.budget.charge(len(name) * 2); e != nil {
		return empty, false, e
	}
	length := uint32(len(name))
	e := windows.RegEnumKeyEx(windows.Handle(v.key), index, &name[0], &length, nil, nil, nil, nil)
	if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
		return empty, true, nil
	}
	if e != nil {
		return empty, false, nativeError(e)
	}
	if length == 0 || length > 255 {
		return empty, false, ErrInvalid
	}
	text, ok := decodeUTF16(name[:length])
	if !ok {
		return empty, false, ErrInvalid
	}
	row := nativeRegistration{key: append([]uint16{}, name[:length]...)}
	if e := ctx.Err(); e != nil {
		return empty, false, e
	}
	if e := v.budget.charge(0); e != nil {
		return empty, false, e
	}
	sub, e := openNoFollow(v.key, text, registry.QUERY_VALUE|v.flag)
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_KEY_DELETED) {
		return empty, false, ErrChanged
	}
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return row, false, nil
	}
	if e != nil {
		return empty, false, nativeError(e)
	}
	defer sub.Close()
	linked, e := registryLink(ctx, sub, v.budget)
	if errors.Is(e, ErrDenied) {
		return row, false, nil
	}
	if e != nil {
		return empty, false, e
	}
	if linked {
		return row, false, nil
	}
	before, e := keyStamp(ctx, sub, v.budget)
	if e != nil {
		return empty, false, e
	}
	values := []**string{&row.name, &row.version, &row.publisher}
	for i, field := range []string{"DisplayName", "DisplayVersion", "Publisher"} {
		if e := ctx.Err(); e != nil {
			return empty, false, e
		}
		var buf [NativeValueBytes]byte
		if e := v.budget.charge(len(buf)); e != nil {
			return empty, false, e
		}
		ptr, _ := windows.UTF16PtrFromString(field)
		var kind uint32
		size := uint32(len(buf))
		e := windows.RegQueryValueEx(windows.Handle(sub), ptr, nil, &kind, &buf[0], &size)
		if errors.Is(e, windows.ERROR_KEY_DELETED) {
			return empty, false, ErrChanged
		}
		if e == nil && size <= uint32(len(buf)) {
			*values[i] = decodeRegistryValue(kind, buf[:size])
		}
		// Missing, denied, oversized and malformed optional values remain unavailable.
	}
	after, e := keyStamp(ctx, sub, v.budget)
	if e != nil {
		return empty, false, e
	}
	if before != after {
		return empty, false, ErrChanged
	}
	return row, false, nil
}
