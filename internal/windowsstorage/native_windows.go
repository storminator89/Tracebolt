//go:build windows

package windowsstorage

import (
	"context"
	"golang.org/x/sys/windows"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

var locatorID = windows.GUID{Data1: 0x76a64158, Data2: 0xcb41, Data3: 0x11d1, Data4: [8]byte{0x8b, 0x02, 0x00, 0x60, 0x08, 0x06, 0xd9, 0xb6}}
var enumID = windows.GUID{Data1: 0x00020404, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}

const storageNamespace = `Root\Microsoft\Windows\Storage`
const disksQuery = "SELECT DeviceId, FriendlyName, HealthStatus, OperationalStatus, BusType, MediaType, Size FROM MSFT_PhysicalDisk"

// One fixed local query. No caller-supplied WQL or remote authority.
func fixedDisks(ctx context.Context, read func(*automation, int) error) (int, bool, error) {
	if read == nil {
		return 0, false, ErrInvalid
	}
	locator, close, e := openAutomation(ctx, &locatorID)
	if e != nil {
		return 0, false, e
	}
	defer close()
	server, e := bstrArgument(".")
	if e != nil {
		return 0, false, e
	}
	defer server.clear()
	namespace, e := bstrArgument(storageNamespace)
	if e != nil {
		return 0, false, e
	}
	defer namespace.clear()
	service, e := locator.objectValue(ctx, "ConnectServer", dispatchMethod, namespace, server)
	if e != nil {
		return 0, false, e
	}
	defer service.close()
	query, e := bstrArgument(disksQuery)
	if e != nil {
		return 0, false, e
	}
	defer query.clear()
	language, e := bstrArgument("WQL")
	if e != nil {
		return 0, false, e
	}
	defer language.clear()
	rows, e := service.objectValue(ctx, "ExecQuery", dispatchMethod, intArgument(0x30), language, query)
	if e != nil {
		return 0, false, e
	}
	defer rows.close()
	enumeration, e := rows.invoke(ctx, "_NewEnum", dispatchGet)
	if e != nil {
		return 0, false, e
	}
	defer enumeration.clear()
	if enumeration.kind != 13 && enumeration.kind != vtDispatch || enumeration.data[0] == 0 {
		return 0, false, ErrMetadata
	}
	unknown := (*dispatchObject)(enumeration.pointer())
	var enumerator *dispatchObject
	hr, _, _ := syscall.SyscallN(unknown.table[0], uintptr(unsafe.Pointer(unknown)), uintptr(unsafe.Pointer(&enumID)), uintptr(unsafe.Pointer(&enumerator)))
	if e = hrError(hr); e != nil {
		return 0, false, e
	}
	if enumerator == nil {
		return 0, false, ErrMetadata
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

	for count := 0; count < MaxNativeDiskRows; count++ {
		value, n, e := next()
		if e != nil {
			return count, false, e
		}
		if n == 0 {
			value.clear()
			return count, true, nil
		}
		if value.kind != vtDispatch || value.data[0] == 0 {
			value.clear()
			return count, false, ErrMetadata
		}
		e = read(&automation{(*dispatchObject)(value.pointer())}, count)
		value.clear()
		if e != nil {
			return count + 1, false, e
		}
	}
	return MaxNativeDiskRows, false, ErrBounds
}
func nativeField(ctx context.Context, o *automation, name string, limit int) Field {
	v, e := o.text(ctx, name, limit)
	return observedField(v, e, limit)
}
func nativeDisks(ctx context.Context) (Disks, error) {
	s := Disks{Quality: "observed", Rows: []Disk{}}
	partial := false
	count, exact, e := fixedDisks(ctx, func(o *automation, index int) error {
		if index >= MaxDiskRows {
			return nil
		}
		r := Disk{Index: index, DeviceID: nativeField(ctx, o, "DeviceId", 64), FriendlyName: nativeField(ctx, o, "FriendlyName", 128), OperationalStatus: []uint16{}}
		number := func(name string) *uint16 {
			v, e := o.uint16Value(ctx, name)
			if e != nil {
				partial = true
				return nil
			}
			return &v
		}
		r.HealthStatus = number("HealthStatus")
		r.BusType = number("BusType")
		r.MediaType = number("MediaType")
		status, e := o.uint16Array(ctx, "OperationalStatus")
		if e != nil {
			partial = true
		} else {
			r.OperationalStatus = status
		}
		size, e := o.text(ctx, "Size", 20)
		if e != nil {
			partial = true
		} else if n, e := strconv.ParseUint(size, 10, 64); e != nil || strconv.FormatUint(n, 10) != size {
			partial = true
		} else {
			r.SizeBytes = &size
		}
		if r.DeviceID.Quality == "denied" || r.DeviceID.Quality == "unavailable" || r.FriendlyName.Quality == "denied" || r.FriendlyName.Quality == "unavailable" {
			partial = true
		}
		s.Rows = append(s.Rows, r)
		return ctx.Err()
	})
	if e != nil && len(s.Rows) == 0 {
		return Disks{}, e
	}
	s.ObservedCount = count
	s.CountExact = exact
	s.Complete = exact && count == len(s.Rows)
	s.Truncated = count > len(s.Rows) || !exact
	if e != nil || partial || !s.Complete {
		s.Quality = "partial"
		s.Reason = ErrPartial.Error()
		if e != nil {
			s.Reason = SafeReason(e)
		}
	}
	return s, nil
}
