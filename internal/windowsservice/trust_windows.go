//go:build windows

package windowsservice

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func trustedWriter(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == trustedInstallerSID
}

// Hold every checked path open without delete sharing until the digest is
// complete, and deny write sharing on the executable. Reject reparse points and
// untrusted owner/replacement-capable ACEs. Existing ancestor admission is a
// path-integrity policy only: actual opens under the SCM token determine its
// read access, including enabled groups and ACE order. The final executable
// retains its explicit LocalService read/execute protection. Creation of unrelated
// children on volume roots does not allow replacing the existing locked chain;
// DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER are denied.
func verifyExecutable(l Layout) (string, error) {
	resolved, err := ResolveLayout()
	if err != nil {
		return "", err
	}
	if l != resolved {
		return "", ErrUnsafePath
	}
	if windows.GetDriveType(windows.StringToUTF16Ptr(l.Executable[:3])) != windows.DRIVE_FIXED {
		return "", ErrUnsafePath
	}
	parts := strings.Split(l.Executable[3:], `\`)
	paths := []string{l.Executable[:3]}
	path := strings.TrimSuffix(l.Executable[:3], `\`)
	for _, part := range parts {
		path += `\` + part
		paths = append(paths, path)
	}
	var held []windows.Handle
	defer func() {
		for _, h := range held {
			windows.CloseHandle(h)
		}
	}()
	var file windows.Handle
	for i, path := range paths {
		directory := i < len(paths)-1
		access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
		if !directory {
			access |= windows.GENERIC_READ
		}
		share := uint32(windows.FILE_SHARE_READ)
		if directory {
			share |= windows.FILE_SHARE_WRITE
		}
		h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return "", ErrUnsafePath
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil {
			return "", ErrUnsafePath
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
			return "", ErrUnsafePath
		}
		if !directory && info.NumberOfLinks != 1 {
			return "", ErrUnsafePath
		}
		if err = validatePathACL(h, directory); err != nil {
			return "", err
		}
		file = h
	}
	// Duplicate ownership into os.File while retaining the checked handle/chain.
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), file, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return "", ErrUnsafePath
	}
	f := os.NewFile(uintptr(duplicate), l.Executable)
	if f == nil {
		windows.CloseHandle(duplicate)
		return "", ErrUnsafePath
	}
	defer f.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func validatePathACL(h windows.Handle, directory bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrUnsafePath
	}
	return validatePathDescriptor(sd, directory)
}

func validatePathDescriptor(sd *windows.SECURITY_DESCRIPTOR, directory bool) error {
	if sd == nil || !sd.IsValid() {
		return ErrUnsafePath
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trustedWriter(owner.String()) {
		return ErrUnsafePath
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrUnsafePath
	}
	writes := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE)
	if directory {
		writes |= 0x40 | windows.FILE_WRITE_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES // FILE_DELETE_CHILD from winnt.h
	} else {
		writes |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	// Do not use descriptor-only ancestor scans as an effective-access test.
	// Windows decides each unchanged CreateFile request using the current token,
	// its enabled groups and ACE ordering. The installer has no future SCM token.
	// The final app-owned executable retains its conservative sufficient read
	// policy; its administrator-only/read-denied variants must still fail plan.
	// https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object
	required := runtimePathAccess(directory)
	var granted, denied uint32
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return ErrUnsafePath
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return ErrUnsafePath
		}
		// Both supported ACE layouts have Mask then SidStart. Bound the complete
		// SID before passing it to native SID helpers; no object/callback ACE is
		// interpreted as an ordinary allow or deny.
		const sidOffset = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < sidOffset+8 {
			return ErrUnsafePath
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sidHeader := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if sidOffset+8+4*uintptr(sidHeader[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return ErrUnsafePath
		}
		mask := uint32(ace.Mask)
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			denied |= mapFileGenericRights(mask)
			continue
		}
		trustee := sid.String()
		if mask&writes != 0 && !trustedWriter(trustee) {
			return ErrUnsafePath
		}
		if trustee == LocalServiceSID {
			granted |= mapFileGenericRights(mask)
		}
	}
	if !directory && (denied&required != 0 || granted&required != required) {
		return ErrRuntimeReadAccess
	}
	return nil
}

func runtimePathAccess(directory bool) uint32 {
	if directory {
		// These are runtime path capabilities, not a named-ACE admission rule.
		// Native opens remain authoritative; no token or privilege is fabricated.
		return windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE | windows.SYNCHRONIZE
	}
	// Includes READ_CONTROL, data/EA/attribute reads, synchronization, and
	// image execution. Installer read access alone does not establish this.
	return windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
}

func mapFileGenericRights(mask uint32) uint32 {
	// winnt.h file-object mapping applies to directories too. In particular,
	// GENERIC_WRITE denies READ_CONTROL and SYNCHRONIZE as well as writes.
	mapped := mask &^ (windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL)
	if mask&windows.GENERIC_READ != 0 {
		mapped |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		mapped |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		mapped |= windows.FILE_GENERIC_EXECUTE
	}
	if mask&windows.GENERIC_ALL != 0 {
		mapped |= windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff // FILE_ALL_ACCESS from winnt.h
	}
	return mapped
}
