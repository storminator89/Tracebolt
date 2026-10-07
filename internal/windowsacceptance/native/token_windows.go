//go:build windows

package native

import (
	"encoding/binary"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type nativeTokenGroup struct {
	SID        string
	Attributes uint32
}

type nativeTokenSnapshot struct {
	UserSID        string
	Groups         []nativeTokenGroup
	RestrictedSIDs []string
	Privileges     []windows.LUID
}

// validateProcessToken observes the actual process token. It never logs on,
// impersonates, duplicates a token, or enables a privilege, including SeDebug.
// An administrator unable to query the service token must report that blocker.
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
func validateProcessToken(pid uint32, expectedSID, forbiddenSID string) bool {
	if pid == 0 || !nativeServiceSID(expectedSID) || (forbiddenSID != "" && (!nativeServiceSID(forbiddenSID) || forbiddenSID == expectedSID)) {
		return false
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	observed, ok := readNativeToken(token)
	if !ok {
		return false
	}
	var allowed windows.LUID
	if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &allowed) != nil {
		return false
	}
	return validateNativeTokenSnapshot(observed, expectedSID, forbiddenSID, allowed)
}

func validateNativeTokenSnapshot(v nativeTokenSnapshot, expectedSID, forbiddenSID string, allowed windows.LUID) bool {
	// SCM removes unrequested privileges; even a disabled unexpected privilege
	// is refused. Service SID owner-capability is required independently.
	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow
	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info
	if v.UserSID != "S-1-5-19" || !nativeServiceSID(expectedSID) || (forbiddenSID != "" && (!nativeServiceSID(forbiddenSID) || expectedSID == forbiddenSID)) || len(v.Privileges) != 1 || v.Privileges[0] != allowed {
		return false
	}
	found := false
	for _, g := range v.Groups {
		if g.SID == "" || (forbiddenSID != "" && g.SID == forbiddenSID) {
			return false
		}
		if g.SID == "S-1-5-32-544" && g.Attributes&windows.SE_GROUP_ENABLED != 0 {
			return false
		}
		if g.SID == expectedSID {
			if found || g.Attributes&(windows.SE_GROUP_ENABLED|windows.SE_GROUP_OWNER) != windows.SE_GROUP_ENABLED|windows.SE_GROUP_OWNER || g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
				return false
			}
			found = true
		}
	}
	for _, sid := range v.RestrictedSIDs {
		if sid == "" || (forbiddenSID != "" && sid == forbiddenSID) {
			return false
		}
	}
	return found
}

func nativeServiceSID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 9 || strings.Join(parts[:4], "-") != "S-1-5-80" {
		return false
	}
	for _, part := range parts[4:] {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return false
		}
	}
	return true
}

func nativeTokenInformation(token windows.Token, kind uint32) ([]byte, bool) {
	var needed uint32
	err := windows.GetTokenInformation(token, kind, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < 4 || needed > 65536 {
		return nil, false
	}
	b := make([]byte, needed)
	if windows.GetTokenInformation(token, kind, &b[0], uint32(len(b)), &needed) != nil || needed < 4 || needed > uint32(len(b)) {
		return nil, false
	}
	return b[:needed], true
}

func readNativeToken(token windows.Token) (nativeTokenSnapshot, bool) {
	var v nativeTokenSnapshot
	u, ok := nativeTokenInformation(token, windows.TokenUser)
	if !ok || len(u) < int(unsafe.Sizeof(windows.Tokenuser{})) {
		return v, false
	}
	v.UserSID, ok = nativeTokenSID(u, (*windows.Tokenuser)(unsafe.Pointer(&u[0])).User.Sid)
	if !ok {
		return v, false
	}
	for _, kind := range []uint32{windows.TokenGroups, windows.TokenRestrictedSids} {
		b, valid := nativeTokenInformation(token, kind)
		if !valid {
			return v, false
		}
		groups, valid := nativeTokenGroups(b)
		if !valid {
			return v, false
		}
		if kind == windows.TokenGroups {
			v.Groups = groups
		} else {
			for _, group := range groups {
				v.RestrictedSIDs = append(v.RestrictedSIDs, group.SID)
			}
		}
	}
	p, ok := nativeTokenInformation(token, windows.TokenPrivileges)
	if !ok {
		return v, false
	}
	v.Privileges, ok = nativeTokenPrivileges(p)
	return v, ok
}

// Parse only bounded native records. SID pointers returned by Windows must point
// into the same query buffer; no unbounded SID pointer is dereferenced.
func nativeTokenSID(b []byte, sid *windows.SID) (string, bool) {
	if len(b) == 0 || sid == nil {
		return "", false
	}
	base, p := uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(sid))
	if p < base || p-base > uintptr(len(b)) || uintptr(len(b))-(p-base) < 8 {
		return "", false
	}
	s := b[int(p-base):]
	count := int(s[1])
	if s[0] != 1 || count > 15 || len(s) < 8+4*count {
		return "", false
	}
	var authority uint64
	for _, x := range s[2:8] {
		authority = authority<<8 | uint64(x)
	}
	out := "S-1-" + strconv.FormatUint(authority, 10)
	for i := 0; i < count; i++ {
		out += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(s[8+i*4:])), 10)
	}
	runtime.KeepAlive(b)
	return out, true
}

func nativeTokenGroups(b []byte) ([]nativeTokenGroup, bool) {
	offset := int(unsafe.Offsetof(windows.Tokengroups{}.Groups))
	size := int(unsafe.Sizeof(windows.SIDAndAttributes{}))
	if len(b) < 4 {
		return nil, false
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count == 0 {
		return []nativeTokenGroup{}, true
	}
	if count > 4096 || uint64(offset)+count*uint64(size) > uint64(len(b)) {
		return nil, false
	}
	groups := make([]nativeTokenGroup, 0, count)
	for i := 0; i < int(count); i++ {
		g := (*windows.SIDAndAttributes)(unsafe.Pointer(&b[offset+i*size]))
		sid, ok := nativeTokenSID(b, g.Sid)
		if !ok {
			return nil, false
		}
		groups = append(groups, nativeTokenGroup{SID: sid, Attributes: g.Attributes})
	}
	runtime.KeepAlive(b)
	return groups, true
}

func nativeTokenPrivileges(b []byte) ([]windows.LUID, bool) {
	const size = 12 // DWORD LowPart, LONG HighPart, DWORD Attributes.
	if len(b) < 4 {
		return nil, false
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	if count > 4096 || 4+count*size > uint64(len(b)) {
		return nil, false
	}
	privileges := make([]windows.LUID, 0, count)
	for i := 0; i < int(count); i++ {
		p := b[4+i*size:]
		privileges = append(privileges, windows.LUID{LowPart: binary.LittleEndian.Uint32(p), HighPart: int32(binary.LittleEndian.Uint32(p[4:]))})
	}
	return privileges, true
}
