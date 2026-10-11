//go:build windows

package windowspatchcontext

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"strconv"
	"unicode/utf16"
)

const versionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
const servicingKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
const sessionKey = `SYSTEM\CurrentControlSet\Control\Session Manager`

// Only fixed HKLM keys and named version values are queried. No enumeration,
// user hives, executable/path metadata or command execution is reachable here.
func NativeMachine(ctx context.Context) (OS, Reboot) {
	v := Value{Quality: "unavailable"}
	os := OS{v, v, v, v}
	r := Reboot{"unavailable", "unavailable", "unavailable"}
	if ctx == nil || ctx.Err() != nil {
		return os, r
	}
	key, e := openMachineKey(versionKey)
	if e != nil {
		q := registryQuality(e)
		v = Value{Quality: q}
		os = OS{v, v, v, v}
	} else {
		os.Edition = readVersionValue(key, "EditionID", 64, false, false)
		if ctx.Err() == nil {
			os.Release = readVersionValue(key, "DisplayVersion", 32, false, false)
		}
		if ctx.Err() == nil {
			os.Build = readVersionValue(key, "CurrentBuildNumber", 10, true, false)
		}
		if ctx.Err() == nil {
			os.Revision = readVersionValue(key, "UBR", 10, true, true)
		}
		if windows.RegCloseKey(key) != nil {
			v = Value{Quality: "unavailable"}
			os = OS{v, v, v, v}
		}
	}
	if ctx.Err() != nil {
		return os, r
	}
	key, e = openMachineKey(servicingKey)
	if e == nil {
		r.Servicing = "pending"
		if windows.RegCloseKey(key) != nil {
			r.Servicing = "unavailable"
		}
	} else if e == windows.ERROR_FILE_NOT_FOUND || e == windows.ERROR_PATH_NOT_FOUND {
		r.Servicing = "clear"
	} else {
		r.Servicing = registryQuality(e)
	}
	if ctx.Err() != nil {
		return os, r
	}
	key, e = openMachineKey(sessionKey)
	if e != nil {
		if e == windows.ERROR_ACCESS_DENIED {
			r.FileOperations = "denied"
		}
		return os, r
	}
	// lpData is deliberately nil. We never allocate or read the path-bearing
	// REG_MULTI_SZ payload. Presence/size is an indicator, not urgency or validity.
	var typ, size uint32
	e = windows.RegQueryValueEx(key, windows.StringToUTF16Ptr("PendingFileRenameOperations"), nil, &typ, nil, &size)
	r.FileOperations = fileOperationsState(typ, size, e == nil, e == windows.ERROR_FILE_NOT_FOUND, e == windows.ERROR_ACCESS_DENIED)
	if windows.RegCloseKey(key) != nil {
		r.FileOperations = "unavailable"
	}
	return os, r
}
func openMachineKey(path string) (windows.Handle, error) {
	var key windows.Handle
	e := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(path), 0, windows.KEY_QUERY_VALUE|windows.KEY_WOW64_64KEY, &key)
	return key, e
}
func registryQuality(e error) string {
	switch e {
	case windows.ERROR_ACCESS_DENIED:
		return "denied"
	case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND:
		return "absent"
	default:
		return "unavailable"
	}
}
func readVersionValue(key windows.Handle, name string, max int, numeric, dword bool) Value {
	// One fixed buffer, one call, no provider-sized allocation or retry. The only
	// admitted native types are REG_SZ and the fixed DWORD revision.
	var b [130]byte
	defer clear(b[:])
	size := uint32(len(b))
	var typ uint32
	e := windows.RegQueryValueEx(key, windows.StringToUTF16Ptr(name), nil, &typ, &b[0], &size)
	if e != nil {
		return Value{Quality: registryQuality(e)}
	}
	var text string
	if dword {
		if typ != windows.REG_DWORD || size != 4 {
			return Value{Quality: "unavailable"}
		}
		text = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[:4])), 10)
	} else {
		if typ != windows.REG_SZ || size < 2 || size > uint32(len(b)) || size%2 != 0 {
			return Value{Quality: "unavailable"}
		}
		units := make([]uint16, int(size)/2)
		defer clear(units)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
		}
		if units[len(units)-1] != 0 {
			return Value{Quality: "unavailable"}
		}
		units = units[:len(units)-1]
		for _, u := range units {
			if u == 0 || u > 127 {
				return Value{Quality: "unavailable"}
			}
		}
		text = string(utf16.Decode(units))
	}
	v := Value{Value: &text, Quality: "observed"}
	if !validValue(v, max, numeric) {
		return Value{Quality: "unavailable"}
	}
	return v
}
