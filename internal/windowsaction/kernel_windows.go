//go:build windows

package windowsaction

import (
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var getProcessIDOfThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")

func kernelACL(h windows.Handle, broker, kind, logon string) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() {
		return ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.IsValid() {
		return ErrBinding
	}
	entries := []serviceACE{}
	e = eachACE(sd, func(s string, m uint32, k, f byte) error {
		entries = append(entries, serviceACE{s, m, k, f})
		return nil
	})
	if e != nil {
		return e
	}
	return validateKernelACL(owner.String(), entries, broker, kind, logon)
}
func tokenInfo(t windows.Token, kind uint32) ([]byte, error) {
	var n uint32
	e := windows.GetTokenInformation(t, kind, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < 8 || n > 65536 {
		return nil, ErrBinding
	}
	b := make([]byte, n)
	if windows.GetTokenInformation(t, kind, &b[0], n, &n) != nil || n > uint32(len(b)) {
		return nil, ErrBinding
	}
	return b, nil
}
func pointedTokenBytes(b []byte) ([]byte, error) {
	if len(b) < int(unsafe.Sizeof(uintptr(0))) {
		return nil, ErrBinding
	}
	p := *(*uintptr)(unsafe.Pointer(&b[0]))
	base := uintptr(unsafe.Pointer(&b[0]))
	if p < base+unsafe.Sizeof(uintptr(0)) || p >= base+uintptr(len(b)) {
		return nil, ErrBinding
	}
	return b[p-base:], nil
}
func tokenDefaults(t windows.Token, broker string) error {
	raw, e := tokenInfo(t, windows.TokenOwner)
	if e != nil {
		return e
	}
	ownerBytes, e := pointedTokenBytes(raw)
	if e != nil || len(ownerBytes) < 8 || 8+4*int(ownerBytes[1]) > len(ownerBytes) {
		return ErrBinding
	}
	owner := (*windows.SID)(unsafe.Pointer(&ownerBytes[0]))
	if !owner.IsValid() {
		return ErrBinding
	}
	ownerString := owner.String()
	rawACL, e := tokenInfo(t, windows.TokenDefaultDacl)
	if e != nil {
		return e
	}
	acl, e := pointedTokenBytes(rawACL)
	if e != nil || len(acl) < 8 || acl[0] != 2 {
		return ErrBinding
	}
	size, count := int(binary.LittleEndian.Uint16(acl[2:4])), int(binary.LittleEndian.Uint16(acl[4:6]))
	if size < 8 || size > len(acl) || count > 64 {
		return ErrBinding
	}
	acl = acl[:size]
	offset := 8
	entries := []serviceACE{}
	for range count {
		if offset+8 > len(acl) {
			return ErrBinding
		}
		n := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if n < 16 || offset+n > len(acl) {
			return ErrBinding
		}
		sidBytes := acl[offset+8 : offset+n]
		if 8+4*int(sidBytes[1]) != len(sidBytes) {
			return ErrBinding
		}
		sid := (*windows.SID)(unsafe.Pointer(&sidBytes[0]))
		if !sid.IsValid() {
			return ErrBinding
		}
		entries = append(entries, serviceACE{sid.String(), binary.LittleEndian.Uint32(acl[offset+4 : offset+8]), acl[offset], acl[offset+1]})
		offset += n
	}
	if offset != len(acl) {
		return ErrBinding
	}
	e = validateKernelACL(ownerString, entries, broker, "default", "")
	runtime.KeepAlive(raw)
	runtime.KeepAlive(rawACL)
	return e
}
func validateBrokerKernelObjects(process windows.Handle, token windows.Token, pid uint32, broker, logon string) error {
	if kernelACL(process, broker, "process", "") != nil || kernelACL(windows.Handle(token), broker, "token", logon) != nil || tokenDefaults(token, broker) != nil {
		return ErrBinding
	}
	// Existing threads are independently securable. Future threads inherit only
	// the independently verified default owner/DACL; no impersonation is used.
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	e = windows.Thread32First(snapshot, &entry)
	total, own := 0, 0
	for e == nil {
		total++
		if total > 8192 {
			return ErrBinding
		}
		if entry.OwnerProcessID == pid {
			own++
			if own > 128 {
				return ErrBinding
			}
			h, err := windows.OpenThread(windows.READ_CONTROL|windows.THREAD_QUERY_LIMITED_INFORMATION, false, entry.ThreadID)
			if err != nil {
				return ErrBinding
			}
			actual, _, _ := getProcessIDOfThread.Call(uintptr(h))
			err = kernelACL(h, broker, "thread", "")
			closeErr := windows.CloseHandle(h)
			if actual != uintptr(pid) || err != nil || closeErr != nil {
				return ErrBinding
			}
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		e = windows.Thread32Next(snapshot, &entry)
	}
	if !errors.Is(e, windows.ERROR_NO_MORE_FILES) || own == 0 {
		return ErrBinding
	}
	return tokenDefaults(token, broker)
}
