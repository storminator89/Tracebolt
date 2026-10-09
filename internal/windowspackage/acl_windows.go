//go:build windows

package windowspackage

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func trustedWriter(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == trustedInstallerSID
}
func newDescriptor(mask uint32) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	switch mask {
	case 0:
	case executableRead:
		sddl += "(A;;0x001200a9;;;LS)"
	case stateDirectoryRead:
		sddl += "(A;;0x001200a1;;;LS)"
	default:
		return nil, failure("descriptor-create")
	}
	return windows.SecurityDescriptorFromString(sddl)
}
func checkACL(b *binding) error {
	sd, err := windows.GetSecurityInfo(b.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return failure("descriptor-query")
	}
	if b.created {
		want, err := newDescriptor(b.mask)
		if err != nil || sd == nil || !sd.IsValid() || sd.String() != want.String() {
			return failure("created-descriptor")
		}
		return nil
	}
	return ancestorDescriptor(sd, b.programData)
}

// Existing ancestor checks prove path integrity only, not effective read access
// under a future SCM token. The narrow shared-ProgramData create-child exception
// never applies to a volume root, intermediate, ProgramFiles, or created child.
func ancestorDescriptor(sd *windows.SECURITY_DESCRIPTOR, programData bool) error {
	if sd == nil || !sd.IsValid() {
		return failure("ancestor-descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trustedWriter(owner.String()) {
		return failure("ancestor-owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return failure("ancestor-dacl")
	}
	writes := ancestorWriteMask(programData)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return failure("ancestor-ace")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return failure("ancestor-ace")
		}
		const offset = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < offset+8 {
			return failure("ancestor-ace")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if offset+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return failure("ancestor-ace")
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && uint32(ace.Mask)&writes != 0 && !trustedWriter(sid.String()) {
			return failure("ancestor-writer")
		}
	}
	return nil
}
