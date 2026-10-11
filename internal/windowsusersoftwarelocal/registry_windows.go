//go:build windows

package windowsusersoftwarelocal

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"localrmm/internal/windowsusersoftware"
	"strings"
)

// HKCU\\Software is shared across WOW64. Deliberately enumerate once without
// WOW64 flags: https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys
const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
const valueBytes = (windowsusersoftware.MaxFieldUTF16 + 1) * 2

func nativeError(e error) error {
	switch {
	case errors.Is(e, windows.ERROR_ACCESS_DENIED):
		return windowsusersoftware.ErrDenied
	case errors.Is(e, windows.ERROR_KEY_DELETED):
		return errChanged
	case errors.Is(e, windows.ERROR_MORE_DATA):
		return windowsusersoftware.ErrBudget
	default:
		return windowsusersoftware.ErrUnavailable
	}
}
func openNoFollow(parent registry.Key, name string, access uint32) (registry.Key, error) {
	ptr, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, errMalformed
	}
	var h windows.Handle
	// REG_OPTION_OPEN_LINK avoids redirecting even an intermediate key into
	// another account or hive. No link target is read or followed.
	e = windows.RegOpenKeyEx(windows.Handle(parent), ptr, 0x8, access, &h)
	return registry.Key(h), e
}
func isRegistryLink(key registry.Key) (bool, error) {
	var kind, n uint32
	e := windows.RegQueryValueEx(windows.Handle(key), windows.StringToUTF16Ptr("SymbolicLinkValue"), nil, &kind, nil, &n)
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if e != nil {
		return false, nativeError(e)
	}
	return kind == windows.REG_LINK, nil
}

type keyStamp struct {
	Count uint32
	Time  windows.Filetime
}

func stamp(key registry.Key) (keyStamp, error) {
	var s keyStamp
	e := windows.RegQueryInfoKey(windows.Handle(key), nil, nil, nil, &s.Count, nil, nil, nil, nil, nil, nil, &s.Time)
	if e != nil {
		return s, nativeError(e)
	}
	return s, nil
}
func readHKCU(ctx context.Context) ([]windowsusersoftware.Row, error) {
	rows := []windowsusersoftware.Row{}
	key := registry.CURRENT_USER
	for _, component := range strings.Split(uninstallPath, `\`) {
		if e := ctx.Err(); e != nil {
			if key != registry.CURRENT_USER {
				key.Close()
			}
			return nil, e
		}
		next, e := openNoFollow(key, component, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if key != registry.CURRENT_USER {
			key.Close()
		}
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return rows, nil
		}
		if e != nil {
			return nil, nativeError(e)
		}
		key = next
		linked, e := isRegistryLink(key)
		if e != nil || linked {
			key.Close()
			if e != nil {
				return nil, e
			}
			return nil, windowsusersoftware.ErrUnsupported
		}
	}
	defer key.Close()
	before, e := stamp(key)
	if e != nil {
		return nil, e
	}
	if before.Count > windowsusersoftware.MaxRows {
		return nil, windowsusersoftware.ErrBudget
	}
	total := 2
	for i := uint32(0); ; i++ {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		var name [256]uint16
		n := uint32(len(name))
		e = windows.RegEnumKeyEx(windows.Handle(key), i, &name[0], &n, nil, nil, nil, nil)
		if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if e != nil {
			return nil, nativeError(e)
		}
		if i >= windowsusersoftware.MaxRows || n == 0 || n > 255 {
			return nil, windowsusersoftware.ErrBudget
		}
		text, ok := decodeUTF16(name[:n])
		if !ok || strings.Contains(text, `\`) {
			return nil, errMalformed
		}
		id, e := windowsusersoftware.RegistrationID("hkcu", name[:n])
		if e != nil {
			return nil, errMalformed
		}
		row, e := readRegistration(ctx, key, text, id)
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
	}
	after, e := stamp(key)
	if e != nil {
		return nil, e
	}
	if before != after || uint32(len(rows)) != before.Count {
		return nil, errChanged
	}
	return rows, nil
}
func readRegistration(ctx context.Context, parent registry.Key, name, id string) (windowsusersoftware.Row, error) {
	row := emptyRow("hkcu", id)
	sub, e := openNoFollow(parent, name, registry.QUERY_VALUE)
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		return row, nil
	}
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return row, errChanged
	}
	if e != nil {
		return row, nativeError(e)
	}
	defer sub.Close()
	linked, e := isRegistryLink(sub)
	if errors.Is(e, windowsusersoftware.ErrDenied) {
		return row, nil
	}
	if e != nil {
		return row, e
	}
	if linked {
		return row, nil
	}
	before, e := stamp(sub)
	if e != nil {
		return row, e
	}
	values := []**string{&row.Name, &row.Version, &row.Publisher}
	qualities := []*string{&row.NameQuality, &row.VersionQuality, &row.PublisherQuality}
	for i, field := range []string{"DisplayName", "DisplayVersion", "Publisher"} {
		if e = ctx.Err(); e != nil {
			return row, e
		}
		var raw [valueBytes]byte
		size := uint32(len(raw))
		var kind uint32
		e = windows.RegQueryValueEx(windows.Handle(sub), windows.StringToUTF16Ptr(field), nil, &kind, &raw[0], &size)
		if errors.Is(e, windows.ERROR_KEY_DELETED) {
			return row, errChanged
		}
		if e == nil && kind == windows.REG_SZ && size >= 2 && size <= uint32(len(raw)) && size%2 == 0 && raw[size-2] == 0 && raw[size-1] == 0 {
			units := make([]uint16, size/2-1)
			for j := range units {
				units[j] = uint16(raw[j*2]) | uint16(raw[j*2+1])<<8
			}
			if text, ok := decodeUTF16(units); ok {
				setField(values[i], qualities[i], &text)
			}
		}
	}
	after, e := stamp(sub)
	if e != nil {
		return row, e
	}
	if before != after {
		return row, errChanged
	}
	return row, nil
}
