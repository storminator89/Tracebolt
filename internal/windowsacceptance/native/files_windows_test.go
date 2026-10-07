//go:build windows

package native

import (
	"fmt"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
	"testing"
	"unsafe"
)

// In-memory SDDL conversion only. No filesystem ACL or object is created.
func TestOSAncestorsRequireTrustedPathsWithoutTokenClaims(t *testing.T) {
	const trusted = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, test := range []struct {
		name, sddl string
		want       bool
	}{
		{"admin only remains access-unverified", trusted, true},
		{"built-in read groups", trusted + "(A;;FRFX;;;BU)", true},
		{"inherited authenticated read", trusted + "(A;ID;FRFX;;;AU)", true},
		{"everyone generic reads", trusted + "(A;;GRGX;;;WD)", true},
		{"missing listing remains runtime decision", trusted + "(A;;0x001200a0;;;LS)", true},
		{"LocalService deny is runtime decision", trusted + "(D;;FR;;;LS)", true},
		{"unrelated group deny is runtime decision", trusted + "(D;;0x20;;;BU)", true},
		{"inherit-only read is not a proof", trusted + "(A;IO;FRFX;;;LS)", true},
		{"untrusted writer", trusted + "(A;;FA;;;BU)", false},
		{"untrusted delete child", trusted + "(A;;0x40;;;BU)", false},
		{"untrusted owner", "O:BUG:BAD:P(A;;FRFX;;;BU)", false},
		{"unsupported effective object ACE", trusted + "(OA;;FRFX;11111111-1111-1111-1111-111111111111;;LS)", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil || ancestorDescriptor(sd) != test.want {
				t.Fatal("unexpected trusted-ancestor policy decision")
			}
		})
	}
}
func TestOnlyNewAppDataParentIncludesRequiredDirectoryListing(t *testing.T) {
	// Creation descriptors remain unchanged; this inspects just the known local
	// service allow mask, never computes effective access for an invented token.
	for _, mask := range []uint32{directoryRead, stateDirectoryRead, executableRead} {
		sd, err := newDescriptor(mask)
		if err != nil || !ancestorDescriptor(sd) {
			t.Fatal("invalid new app descriptor")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatal("missing app DACL")
		}
		found := false
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(acl, i, &ace) != nil || ace == nil {
				t.Fatal("invalid app ACE")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.String() == windowsservice.LocalServiceSID {
				if found || uint32(ace.Mask) != mask {
					t.Fatal("app runtime mask changed")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("new app read grant missing")
		}
	}
}
func TestCanonicalFixedPathPolicy(t *testing.T) {
	for _, p := range []string{`C:\Program Files\Tracebolt`, `C:\ProgramData\Tracebolt`, `C:\`} {
		if !canonicalPath(p) {
			t.Fatal("canonical fixture refused")
		}
	}
	for _, p := range []string{`c:\ProgramData`, `\\server\share`, `C:\ProgramData\..\foreign`, `C:\ProgramData\Tracebolt:stream`, `C:\PROGRA~1`, `C:\ProgramData\Tracebolt.`, `C:\ProgramData\☃`} {
		if canonicalPath(p) {
			t.Fatal("unsafe fixture path admitted")
		}
	}
}

func TestProgramDataExceptionIsScopedAndCannotGrantChildReplacement(t *testing.T) {
	const base = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	// Every case constructs only an in-memory descriptor; no host ACL is touched.
	for _, mask := range []uint32{0x2, 0x10, 0x100, 0x112} {
		sd, err := windows.SecurityDescriptorFromString(base + fmt.Sprintf("(A;;0x%x;;;BU)", mask))
		if err != nil {
			t.Fatal("descriptor fixture invalid")
		}
		strict, _ := ancestorDescriptorForRole(sd, false)
		pd, _ := ancestorDescriptorForRole(sd, true)
		if strict != "untrusted-write-grant" || pd != "" {
			t.Fatal("ProgramData exception escaped its role")
		}
	}
	for _, mask := range []uint32{windows.GENERIC_ALL, windows.GENERIC_WRITE, windows.WRITE_OWNER, windows.WRITE_DAC, windows.DELETE, 0x40} {
		sd, err := windows.SecurityDescriptorFromString(base + fmt.Sprintf("(A;;0x%x;;;BU)", mask|0x112))
		if err != nil {
			t.Fatal("descriptor fixture invalid")
		}
		failure, rights := ancestorDescriptorForRole(sd, true)
		if failure != "untrusted-write-grant" || len(rights) != 1 {
			t.Fatal("destructive right admitted or diagnostic widened")
		}
	}
	for _, sddl := range []string{"O:BUG:BAD:P(A;;0x112;;;BU)", "O:BAG:BAD:NO_ACCESS_CONTROL", base + "(OA;;0x112;11111111-1111-1111-1111-111111111111;;BU)"} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal("descriptor fixture invalid")
		}
		failure, _ := ancestorDescriptorForRole(sd, true)
		if failure == "" {
			t.Fatal("invalid ProgramData ownership/descriptor accepted")
		}
	}
}
