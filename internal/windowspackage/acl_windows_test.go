//go:build windows

package windowspackage

import (
	"fmt"
	"golang.org/x/sys/windows"
	"testing"
)

// These tests construct descriptors in memory. They never inspect or mutate a
// host ACL, file, token, service, account, key, or runtime grant.
func TestAncestorDescriptorMemoryFixtures(t *testing.T) {
	const base = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, mask := range []uint32{0x2, 0x10, 0x100, 0x112} {
		sd, err := windows.SecurityDescriptorFromString(base + fmt.Sprintf("(A;;0x%x;;;BU)", mask))
		if err != nil {
			t.Fatal(err)
		}
		if ancestorDescriptor(sd, true) != nil || Code(ancestorDescriptor(sd, false)) != "ancestor-writer" {
			t.Fatal("shared ProgramData exception escaped role")
		}
	}
	for _, mask := range []uint32{windows.GENERIC_ALL, windows.GENERIC_WRITE, windows.WRITE_OWNER, windows.WRITE_DAC, windows.DELETE, 0x40} {
		sd, err := windows.SecurityDescriptorFromString(base + fmt.Sprintf("(A;;0x%x;;;BU)", mask|0x112))
		if err != nil {
			t.Fatal(err)
		}
		if Code(ancestorDescriptor(sd, true)) != "ancestor-writer" {
			t.Fatal("replacement right admitted")
		}
	}
	for _, sddl := range []string{"O:BUG:BAD:P(A;;FR;;;BU)", "O:BAG:BAD:NO_ACCESS_CONTROL", base + "(OA;;FR;11111111-1111-1111-1111-111111111111;;BU)"} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if ancestorDescriptor(sd, true) == nil {
			t.Fatal("unsafe descriptor admitted")
		}
	}
	for _, sddl := range []string{base, base + "(A;;FRFX;;;LS)", base + "(A;OICIIO;FA;;;BU)", base + "(D;;FA;;;BU)"} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := ancestorDescriptor(sd, false); err != nil {
			t.Fatal("trust-only policy treated ACEs as effective token read test", err)
		}
	}
	if ancestorDescriptor(nil, false) == nil {
		t.Fatal("nil descriptor admitted")
	}
}
func TestCreatedDescriptorsExactInMemory(t *testing.T) {
	for _, mask := range []uint32{0, executableRead, stateDirectoryRead} {
		sd, err := newDescriptor(mask)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner.String() != "S-1-5-32-544" {
			t.Fatal("owner incorrect")
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("DACL not protected")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatal("DACL unavailable")
		}
		count := uint16(2)
		if mask != 0 {
			count = 3
		}
		if acl.AceCount != count {
			t.Fatal("unexpected ACEs")
		}
		if err := ancestorDescriptor(sd, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newDescriptor(windows.FILE_GENERIC_WRITE); err == nil {
		t.Fatal("unsupported write mask accepted")
	}
}
func TestNativeRolePathsAndMasks(t *testing.T) {
	s := nativeState{}
	s.layout.ProgramFiles = `C:\Program Files`
	s.layout.ProgramData = `C:\ProgramData`
	s.layout.Executable = `C:\Program Files\Tracebolt\tracebolt-windows-service.exe`
	if s.BootstrapPath() != `C:\ProgramData\Tracebolt\windows-setup\bootstrap.json` || s.path(manifestFile) != `C:\ProgramData\Tracebolt\windows-setup\payload-manifest.json` {
		t.Fatal("bootstrap is not separate from runtime store")
	}
	if roleMask(setupDirectory) != 0 || roleMask(bootstrapFile) != 0 || roleMask(manifestFile) != 0 {
		t.Fatal("public setup material not admin-only")
	}
	if roleMask(programDataApp) != stateDirectoryRead || roleMask(serviceFile) != executableRead {
		t.Fatal("service runtime read rights differ")
	}
}

func TestOnlyDirectChildMissingIsFreshness(t *testing.T) {
	for _, err := range []error{windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_NO_SUCH_FILE} {
		if !missingDirectChild(err) {
			t.Fatal("direct child absence not admitted")
		}
	}
	for _, err := range []error{nil, windows.STATUS_OBJECT_PATH_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_ACCESS_DENIED, windows.STATUS_ACCESS_DENIED, windows.STATUS_REPARSE_POINT_ENCOUNTERED, windows.STATUS_NOT_A_DIRECTORY, windows.STATUS_SHARING_VIOLATION} {
		if missingDirectChild(err) {
			t.Fatal("uncertain or existing state treated as fresh")
		}
	}
}
