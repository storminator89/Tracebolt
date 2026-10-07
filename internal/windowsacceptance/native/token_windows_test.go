//go:build windows

package native

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests use synthetic memory only: no process/token query, logon, file,
// service, privilege adjustment, ACL mutation, or endpoint key operation.
const tokenTestServiceSID = "S-1-5-80-1-2-3-4-5"
const tokenTestForbiddenSID = "S-1-5-80-6-7-8-9-10"

func tokenTestSnapshot() nativeTokenSnapshot {
	return nativeTokenSnapshot{UserSID: "S-1-5-19", Groups: []nativeTokenGroup{{SID: tokenTestServiceSID, Attributes: windows.SE_GROUP_ENABLED | windows.SE_GROUP_OWNER}}, Privileges: []windows.LUID{{LowPart: 23}}}
}

func TestNativeTokenPolicy(t *testing.T) {
	allowed := windows.LUID{LowPart: 23}
	if !validateNativeTokenSnapshot(tokenTestSnapshot(), tokenTestServiceSID, tokenTestForbiddenSID, allowed) {
		t.Fatal("limited service token rejected")
	}
	tests := map[string]func(*nativeTokenSnapshot){
		"system":            func(v *nativeTokenSnapshot) { v.UserSID = "S-1-5-18" },
		"ordinary user":     func(v *nativeTokenSnapshot) { v.UserSID = "S-1-5-21-100" },
		"no service SID":    func(v *nativeTokenSnapshot) { v.Groups = nil },
		"disabled SID":      func(v *nativeTokenSnapshot) { v.Groups[0].Attributes &^= windows.SE_GROUP_ENABLED },
		"not owner capable": func(v *nativeTokenSnapshot) { v.Groups[0].Attributes &^= windows.SE_GROUP_OWNER },
		"deny-only SID":     func(v *nativeTokenSnapshot) { v.Groups[0].Attributes |= windows.SE_GROUP_USE_FOR_DENY_ONLY },
		"duplicate SID":     func(v *nativeTokenSnapshot) { v.Groups = append(v.Groups, v.Groups[0]) },
		"admin enabled": func(v *nativeTokenSnapshot) {
			v.Groups = append(v.Groups, nativeTokenGroup{SID: "S-1-5-32-544", Attributes: windows.SE_GROUP_ENABLED})
		},
		"forbidden disabled": func(v *nativeTokenSnapshot) {
			v.Groups = append(v.Groups, nativeTokenGroup{SID: tokenTestForbiddenSID})
		},
		"forbidden deny-only": func(v *nativeTokenSnapshot) {
			v.Groups = append(v.Groups, nativeTokenGroup{SID: tokenTestForbiddenSID, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY})
		},
		"forbidden restricted":  func(v *nativeTokenSnapshot) { v.RestrictedSIDs = []string{tokenTestForbiddenSID} },
		"debug privilege":       func(v *nativeTokenSnapshot) { v.Privileges = append(v.Privileges, windows.LUID{LowPart: 20}) },
		"no required privilege": func(v *nativeTokenSnapshot) { v.Privileges = nil },
		"wrong privilege":       func(v *nativeTokenSnapshot) { v.Privileges[0].HighPart = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			v := tokenTestSnapshot()
			mutate(&v)
			if validateNativeTokenSnapshot(v, tokenTestServiceSID, tokenTestForbiddenSID, allowed) {
				t.Fatal("unsafe token accepted")
			}
		})
	}
	v := tokenTestSnapshot()
	v.Groups = append(v.Groups, nativeTokenGroup{SID: "S-1-5-32-544", Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY})
	if !validateNativeTokenSnapshot(v, tokenTestServiceSID, "", allowed) {
		t.Fatal("disabled deny-only administrator group is not enabled")
	}
	for _, invalid := range []string{"", "S-1-5-19", "S-1-5-80-1-2-3-4", "S-1-5-80-1-2-3-4-05", "S-1-5-80-1-2-3-4-4294967296", "S-1-5-80-1-2-3-4-+5"} {
		if validateNativeTokenSnapshot(tokenTestSnapshot(), invalid, "", allowed) {
			t.Fatalf("bad expected SID accepted: %q", invalid)
		}
	}
	if validateNativeTokenSnapshot(tokenTestSnapshot(), tokenTestServiceSID, tokenTestServiceSID, allowed) || validateNativeTokenSnapshot(tokenTestSnapshot(), tokenTestServiceSID, "invalid", allowed) {
		t.Fatal("invalid forbidden SID accepted")
	}
}

func TestNativeTokenPrivilegeBounds(t *testing.T) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, 1)
	binary.LittleEndian.PutUint32(b[4:], 23)
	p, ok := nativeTokenPrivileges(b)
	if !ok || len(p) != 1 || p[0].LowPart != 23 {
		t.Fatal("bounded fixture rejected")
	}
	for _, b := range [][]byte{nil, {1, 0, 0}, {1, 0, 0, 0}, {255, 255, 255, 255}} {
		if _, ok := nativeTokenPrivileges(b); ok {
			t.Fatal("unbounded/truncated privileges accepted")
		}
	}
}

func TestNativeTokenGroupAndSIDBounds(t *testing.T) {
	if groups, ok := nativeTokenGroups(make([]byte, 4)); !ok || len(groups) != 0 {
		t.Fatal("zero-group record rejected")
	}
	offset := int(unsafe.Offsetof(windows.Tokengroups{}.Groups))
	size := int(unsafe.Sizeof(windows.SIDAndAttributes{}))
	b := make([]byte, offset+size+12)
	binary.LittleEndian.PutUint32(b, 1)
	sidOffset := offset + size
	b[sidOffset], b[sidOffset+1], b[sidOffset+7] = 1, 1, 5
	binary.LittleEndian.PutUint32(b[sidOffset+8:], 19)
	g := (*windows.SIDAndAttributes)(unsafe.Pointer(&b[offset]))
	g.Sid = (*windows.SID)(unsafe.Pointer(&b[sidOffset]))
	g.Attributes = windows.SE_GROUP_ENABLED
	groups, ok := nativeTokenGroups(b)
	if !ok || len(groups) != 1 || groups[0].SID != "S-1-5-19" || groups[0].Attributes != windows.SE_GROUP_ENABLED {
		t.Fatal("bounded group rejected")
	}
	if _, ok := nativeTokenGroups(b[:sidOffset+11]); ok {
		t.Fatal("truncated SID accepted")
	}
	g.Sid = nil
	if _, ok := nativeTokenGroups(b); ok {
		t.Fatal("null SID accepted")
	}
	binary.LittleEndian.PutUint32(b, ^uint32(0))
	if _, ok := nativeTokenGroups(b); ok {
		t.Fatal("unbounded group count accepted")
	}
}
