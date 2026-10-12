//go:build windows

package windowsmanagedmsiipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
	"os"
	"strings"
	"unsafe"
)

// ServiceGuard pins the protected executable through the whole server life.
// It does not establish SCM executor identity: fresh signed nonce proofs do that.
type ServiceGuard struct {
	config     Config
	pins       []windows.Handle
	process    windows.Handle
	descriptor string
}

func OpenServiceGuard(ctx context.Context, c Config, allowQuery bool) (*ServiceGuard, error) {
	if ctx == nil || ctx.Err() != nil || c.Validate() != nil {
		return nil, ErrPeer
	}
	layout, e := windowsservice.ResolveLayout()
	if e != nil || c.Executable != layout.ProgramFiles+`\Tracebolt\tracebolt-windows-managed-msi-service.exe` || c.ObserverReceipt.Layout != layout {
		return nil, ErrPeer
	}
	exe, e := os.Executable()
	if e != nil || exe != c.Executable {
		return nil, ErrPeer
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil || sid != c.ObserverReceipt.ServiceSID {
		return nil, ErrPeer
	}
	snapshot, e := windowsservice.InspectOwned(ctx, c.ObserverReceipt)
	if e != nil || snapshot.State != windowsservice.Running || snapshot.ServiceSID != sid {
		return nil, ErrPeer
	}
	p := &ServiceGuard{config: c}
	p.pins, _, e = holdExecutable(c.Executable)
	fail := func() (*ServiceGuard, error) { p.Close(); return nil, ErrPeer }
	if e != nil {
		return fail()
	}
	hash, e := hashHandle(p.pins[len(p.pins)-1])
	if e != nil || hash != c.ExecutableDigest {
		return fail()
	}
	p.process, e = windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getpid()))
	if e != nil {
		return fail()
	}
	before, e := descriptorText(p.process)
	if e != nil || validateProcessDescriptor(before, sid) != nil {
		return fail()
	}
	found := false
	sd, _ := windows.SecurityDescriptorFromString(before)
	_ = eachACE(sd, func(principal string, mask uint32, k, f byte) error {
		if principal == sid {
			found = true
		}
		return nil
	})
	if !found {
		if !allowQuery || !c.ObserverProcessQueryAcknowledged {
			return fail()
		}
		after, e := windows.SecurityDescriptorFromString(before + fmt.Sprintf("(A;;0x%x;;;%s)", processQueryRights, sid))
		if e != nil {
			return fail()
		}
		// Compare again immediately before changing only this process's DACL.
		current, e := descriptorText(p.process)
		if e != nil || current != before {
			return fail()
		}
		acl, _, e := after.DACL()
		if e != nil || acl == nil {
			return fail()
		}
		control, _, e := after.Control()
		if e != nil {
			return fail()
		}
		info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		}
		if windows.SetSecurityInfo(p.process, windows.SE_KERNEL_OBJECT, info, nil, nil, acl, nil) != nil {
			return fail()
		}
		actual, e := descriptorText(p.process)
		if e != nil || actual != after.String() {
			return fail()
		}
		before = actual
	}
	p.descriptor = before
	if p.Check(ctx) != nil {
		return fail()
	}
	return p, nil
}
func (p *ServiceGuard) Check(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.process == 0 || !livePeerProcess(p.process) {
		return ErrPeer
	}
	current, e := descriptorText(p.process)
	if e != nil || current != p.descriptor || validateProcessDescriptor(current, p.config.ObserverReceipt.ServiceSID) != nil {
		return ErrPeer
	}
	if checkHeldExecutable(p.pins, p.config.Executable) != nil {
		return ErrPeer
	}
	snapshot, e := windowsservice.InspectOwned(ctx, p.config.ObserverReceipt)
	if e != nil || snapshot.State != windowsservice.Running {
		return ErrPeer
	}
	if e := checkDeploymentSCM(uint32(os.Getpid()), p.config.Executable); e != nil {
		return e
	}
	return ctx.Err()
}
func (p *ServiceGuard) Close() {
	if p == nil {
		return
	}
	for i := len(p.pins) - 1; i >= 0; i-- {
		windows.CloseHandle(p.pins[i])
	}
	p.pins = nil
	if p.process != 0 {
		windows.CloseHandle(p.process)
		p.process = 0
	}
}

const processQueryRights uint32 = 0x00101000 // Query limited + synchronize only.
func descriptorText(h windows.Handle) (string, error) {
	sd, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() || sd.Length() > 8192 {
		return "", ErrPeer
	}
	return sd.String(), nil
}
func validateProcessDescriptor(raw, sid string) error {
	sd, e := windows.SecurityDescriptorFromString(raw)
	if e != nil || !validSID(sid) {
		return ErrPeer
	}
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return ErrPeer
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil || user.User.Sid == nil {
		return ErrPeer
	}
	self := user.User.Sid.String()
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || owner.String() != self && !trustedWriter(owner.String()) {
		return ErrPeer
	}
	seen := false
	return eachACE(sd, func(principal string, mask uint32, k, f byte) error {
		if k != windows.ACCESS_ALLOWED_ACE_TYPE || f != 0 {
			return ErrPeer
		}
		if principal == sid {
			if seen || mask != processQueryRights {
				return ErrPeer
			}
			seen = true
			return nil
		}
		if principal == self || trustedWriter(principal) {
			return nil
		}
		// No arbitrary user's read/duplicate/VM/token rights on a signing process.
		return ErrPeer
	})
}
func untrustedPathWriteMask(directory bool) uint32 {
	mask := uint32(0x10000000 | 0x40000000 | 0x40000 | 0x80000 | 0x10000 | 0x2 | 0x10 | 0x100)
	if directory {
		mask |= 0x40
	} else {
		mask |= 0x4
	}
	return mask
}

func eachACE(sd *windows.SECURITY_DESCRIPTOR, visit func(string, uint32, byte, byte) error) error {
	if sd == nil || !sd.IsValid() || sd.Length() > 8192 {
		return ErrPeer
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount > 64 {
		return ErrPeer
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return ErrPeer
		}
		offset := unsafe.Offsetof(ace.SidStart)
		if uintptr(ace.Header.AceSize) < offset+8 {
			return ErrPeer
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if offset+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return ErrPeer
		}
		if e = visit(sid.String(), uint32(ace.Mask), ace.Header.AceType, ace.Header.AceFlags); e != nil {
			return e
		}
	}
	return nil
}
func trustedWriter(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func pathACL(h windows.Handle, directory bool) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrPeer
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedWriter(owner.String()) {
		return ErrPeer
	}
	writes := untrustedPathWriteMask(directory)
	return eachACE(sd, func(s string, mask uint32, kind, flags byte) error {
		if flags&windows.INHERIT_ONLY_ACE != 0 {
			return nil
		}
		if kind == windows.ACCESS_ALLOWED_ACE_TYPE && !trustedWriter(s) && mask&writes != 0 {
			return ErrPeer
		}
		return nil
	})
}
func holdExecutable(path string) (held []windows.Handle, file windows.Handle, err error) {
	if !windowspath.Canonical(path) || !strings.HasSuffix(strings.ToLower(path), ".exe") || windows.GetDriveType(windows.StringToUTF16Ptr(path[:3])) != windows.DRIVE_FIXED {
		return nil, 0, ErrPeer
	}
	parts := strings.Split(path[3:], `\`)
	current := path[:3]
	for i := 0; i <= len(parts); i++ {
		directory := i < len(parts)
		var h windows.Handle
		if i == 0 {
			h, err = windowspath.OpenRoot(current)
		} else {
			current = strings.TrimSuffix(current, `\`) + `\` + parts[i-1]
			access, share := uint32(windowspath.DirectoryAccess), uint32(windowspath.DirectoryShare)
			if !directory {
				access = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.GENERIC_READ
				share = windows.FILE_SHARE_READ
			}
			h, err = windowspath.OpenChild(held[len(held)-1], parts[i-1], directory, access, share)
		}
		if err != nil {
			return held, 0, ErrPeer
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
			return held, 0, ErrPeer
		}
		var final [512]uint16
		n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
		if e != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+current {
			return held, 0, ErrPeer
		}
		if directory {
			var flags uint32
			var ios windows.IO_STATUS_BLOCK
			if windows.NtQueryInformationFile(h, &ios, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
				return held, 0, ErrPeer
			}
		}
		if e = pathACL(h, directory); e != nil {
			return held, 0, e
		}
		file = h
	}
	return held, file, nil
}
func hashHandle(h windows.Handle) (string, error) {
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return "", ErrPeer
	}
	f := os.NewFile(uintptr(duplicate), "protected executable")
	if f == nil {
		windows.CloseHandle(duplicate)
		return "", ErrPeer
	}
	defer f.Close()
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return "", ErrPeer
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 256<<20+1))
	if e != nil || n == 0 || n > 256<<20 {
		return "", ErrPeer
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// Sharing pins byte identity but does not freeze attributes or directory case
// semantics. Repeat the full structural proof on the original held handles.
func checkHeldExecutable(held []windows.Handle, path string) error {
	if !windowspath.Canonical(path) || windows.GetDriveType(windows.StringToUTF16Ptr(path[:3])) != windows.DRIVE_FIXED {
		return ErrPeer
	}
	parts := strings.Split(path[3:], `\`)
	if len(held) != len(parts)+1 {
		return ErrPeer
	}
	current := path[:3]
	for i, h := range held {
		directory := i < len(held)-1
		if i > 0 {
			current = strings.TrimSuffix(current, `\`) + `\` + parts[i-1]
		}
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
			return ErrPeer
		}
		var final [512]uint16
		n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
		if e != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+current {
			return ErrPeer
		}
		if directory {
			var flags uint32
			var ios windows.IO_STATUS_BLOCK
			if windows.NtQueryInformationFile(h, &ios, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
				return ErrPeer
			}
		}
		if pathACL(h, directory) != nil {
			return ErrPeer
		}
	}
	return nil
}
