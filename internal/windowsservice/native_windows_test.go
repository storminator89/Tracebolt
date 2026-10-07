//go:build windows

package windowsservice

import (
	"encoding/binary"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// All native fixtures below parse caller-owned memory only. They do not open SCM,
// create/start/stop/delete a service, change ACLs, or create endpoint credentials.
func multiStringFixture(words []string) []byte {
	units := []uint16{}
	for _, word := range words {
		units = append(units, windows.StringToUTF16(word)...)
	}
	units = append(units, 0)
	if len(units) == 1 {
		units = append(units, 0)
	}
	offset := int(unsafe.Sizeof(uintptr(0)))
	b := make([]byte, offset+len(units)*2)
	*(*uintptr)(unsafe.Pointer(&b[0])) = uintptr(unsafe.Pointer(&b[offset]))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[offset+i*2:], u)
	}
	return b
}
func TestNativeRequiredPrivilegeBufferFixtures(t *testing.T) {
	for _, want := range [][]string{{RequiredPrivilege}, {"SeChangeNotifyPrivilege", "SeDebugPrivilege"}, {}} {
		b := multiStringFixture(want)
		got, err := parseRequiredPrivileges(b)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal(got, err)
		}
	}
	for name, change := range map[string]func([]byte) []byte{
		"before buffer": func(b []byte) []byte {
			*(*uintptr)(unsafe.Pointer(&b[0])) = uintptr(unsafe.Pointer(&b[0])) - 2
			return b
		},
		"past buffer": func(b []byte) []byte {
			*(*uintptr)(unsafe.Pointer(&b[0])) = uintptr(unsafe.Pointer(&b[0])) + uintptr(len(b))
			return b
		},
		"odd pointer":              func(b []byte) []byte { *(*uintptr)(unsafe.Pointer(&b[0]))++; return b },
		"missing final terminator": func(b []byte) []byte { return b[:len(b)-2] },
		"short header":             func(b []byte) []byte { return b[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRequiredPrivileges(change(multiStringFixture([]string{RequiredPrivilege}))); err == nil {
				t.Fatal("malformed buffer accepted")
			}
		})
	}
}
func TestNativeTrustedACLMemoryFixtures(t *testing.T) {
	tests := []struct {
		name, sddl       string
		directory, allow bool
	}{
		{"trusted file", `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)(A;;FRFX;;;LS)`, false, true},
		{"world writable", `O:SYG:SYD:P(A;;FA;;;SY)(A;;FW;;;WD)`, false, false},
		{"shared LocalService owner", `O:LSG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`, false, false},
		{"LocalService can replace binary", `O:SYG:SYD:P(A;;FA;;;SY)(A;;FW;;;LS)`, false, false},
		{"null DACL", `O:SYG:SYD:NO_ACCESS_CONTROL`, false, false},
		{"untrusted parent delete child", `O:SYG:SYD:P(A;;FA;;;SY)(A;;0x40;;;WD)`, true, false},
		{"unrelated root subdirectory creation", `O:SYG:SYD:P(A;;FA;;;SY)(A;;0x4;;;BU)(A;;FX;;;LS)`, true, true},
		{"untrusted parent file creation", `O:SYG:SYD:P(A;;FA;;;SY)(A;;0x2;;;BU)`, true, false},
		{"untrusted ACL editor", `O:SYG:SYD:P(A;;FA;;;SY)(A;;WD;;;BU)`, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = validatePathDescriptor(sd, tt.directory)
			if (err == nil) != tt.allow {
				t.Fatal(err)
			}
		})
	}
}
func TestNativeSCMStructureABI(t *testing.T) {
	// SERVICE_REQUIRED_PRIVILEGES_INFOW is exactly one LPWSTR on both supported
	// architectures. SERVICE_SID_INFO is exactly one DWORD.
	if unsafe.Sizeof(struct{ Privileges *uint16 }{}) != unsafe.Sizeof(uintptr(0)) || unsafe.Sizeof(uint32(0)) != 4 {
		t.Fatal("unexpected Windows service configuration ABI")
	}
}
