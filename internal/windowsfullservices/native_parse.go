package windowsfullservices

import (
	"unicode/utf16"
	"unsafe"
)

// Every string is copied before the one buffer is reused. Invalid optional
// pointers yield field-unavailable; an invalid service identity fails capture.
func nativeString(buf []byte, p *uint16) (string, bool) {
	if len(buf) == 0 || p == nil {
		return "", false
	}
	base, addr := uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(p))
	if addr < base || addr-base >= uintptr(len(buf)) || (addr-base)%2 != 0 {
		return "", false
	}
	length := (uintptr(len(buf)) - (addr - base)) / 2
	if length > 257 {
		length = 257
	}
	values := unsafe.Slice(p, int(length))
	for i, v := range values {
		if v == 0 {
			units := values[:i]
			for j := 0; j < len(units); j++ {
				if units[j] >= 0xd800 && units[j] <= 0xdbff {
					if j+1 >= len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
						return "", false
					}
					j++
				} else if units[j] >= 0xdc00 && units[j] <= 0xdfff {
					return "", false
				}
			}
			return string(utf16.Decode(units)), true
		}
	}
	return "", false
}
func nativeState(state uint32) (string, bool) {
	switch state {
	case 1:
		return "stopped", true
	case 2:
		return "start_pending", true
	case 3:
		return "stop_pending", true
	case 4:
		return "running", true
	case 5:
		return "continue_pending", true
	case 6:
		return "pause_pending", true
	case 7:
		return "paused", true
	}
	return "", false
}
