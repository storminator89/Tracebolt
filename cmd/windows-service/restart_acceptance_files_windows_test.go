//go:build windows && tracebolt_restart_acceptance && !tracebolt_fresh_native && !tracebolt_setup_native

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
)

// Only fixed public endpoint artifacts, installer ownership records, and
// source-pinned executables reach this reader.
// Every path component is opened relative to an already retained directory.
// No live enrollment/sender Store is opened, and no existing ACL is modified.
type restartPinned struct {
	handle     windows.Handle
	path       string
	directory  bool
	id         [3]uint32
	descriptor string
	digest     string
	bound      int64
	parent     windows.Handle
	owner      *restartPins
	access     uint32
	share      uint32
}
type restartPins struct {
	all             []*restartPinned
	dataReaders     int
	dataCloseFailed bool
}

func (p *restartPins) close() error {
	var failed bool
	for i := len(p.all) - 1; i >= 0; i-- {
		f := p.all[i]
		e := windows.CloseHandle(f.handle)
		if e != nil {
			failed = true
		}
	}
	p.all = nil
	if failed {
		return restartAcceptanceRejected
	}
	return nil
}
func (p *restartPins) verify() error {
	for _, f := range p.all {
		if f.check() != nil {
			return restartAcceptanceRejected
		}
	}
	return nil
}
func (p *restartPins) open(path string, directory bool, operator, runtimeSID string, bound int64) (*restartPinned, error) {
	if !windowspath.Canonical(path) || (!directory && (bound <= 0 || bound > 128<<20)) {
		return nil, restartAcceptanceRejected
	}
	parts := strings.Split(path[3:], `\`)
	chain := []string{path[:3]}
	current := strings.TrimSuffix(path[:3], `\`)
	if len(path) > 3 {
		for _, part := range parts {
			current += `\` + part
			chain = append(chain, current)
		}
	}
	var parent windows.Handle
	for i, name := range chain {
		last := i == len(chain)-1
		dir := !last || directory
		var h windows.Handle
		var e error
		if i == 0 {
			h, e = windowspath.OpenRoot(name)
			if e == nil {
				var fs [32]uint16
				var flags uint32
				if windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))) != nil || windows.UTF16ToString(fs[:]) != "NTFS" || flags&windows.FILE_PERSISTENT_ACLS == 0 {
					windows.CloseHandle(h)
					return nil, restartAcceptanceRejected
				}
			}
		} else {
			access := uint32(restartFilePinRights)
			share := uint32(restartFilePinShare)
			if dir {
				access = windowspath.DirectoryAccess
				share = windowspath.DirectoryShare
			}
			h, e = windowspath.OpenChild(parent, filepath.Base(name), dir, access, share)
		}
		if e != nil {
			return nil, restartAcceptanceRejected
		}
		f := &restartPinned{handle: h, path: name, directory: dir, parent: parent, owner: p, access: restartFilePinRights, share: restartFilePinShare}
		// Once opened, the handle is always retained or closed exactly once.
		p.all = append(p.all, f)
		id, descriptor, e := restartFileMetadata(f)
		if e != nil || !restartSafeACL(h, operator, runtimeSID, dir) {
			return nil, restartAcceptanceRejected
		}
		f.id = id
		f.descriptor = descriptor
		if last && !directory {
			f.bound = bound
			b, e := f.read(bound)
			if e != nil {
				return nil, restartAcceptanceRejected
			}
			f.digest = restartHash(b)
			clear(b)
		}
		if f.check() != nil {
			return nil, restartAcceptanceRejected
		}
		parent = h
		if last {
			return f, nil
		}
	}
	return nil, restartAcceptanceRejected
}

// A metadata-only retained file handle is compatible with production's
// exclusive share=0 content readers. Data handles exist only within this call,
// never across a CLI launch or the service stop/start interval.
func (f *restartPinned) read(max int64) (raw []byte, err error) {
	if f.directory || f.parent == 0 || f.owner == nil || max <= 0 || max > 128<<20 {
		return nil, restartAcceptanceRejected
	}
	h, e := windowspath.OpenChild(f.parent, filepath.Base(f.path), false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if e != nil {
		return nil, restartAcceptanceRejected
	}
	f.owner.dataReaders++
	file := os.NewFile(uintptr(h), "<temporary bounded public read>")
	if file == nil {
		e := windows.CloseHandle(h)
		f.owner.dataReaders--
		if e != nil {
			f.owner.dataCloseFailed = true
		}
		return nil, restartAcceptanceRejected
	}
	defer func() {
		if file.Close() != nil {
			f.owner.dataCloseFailed = true
			clear(raw)
			raw = nil
			err = restartAcceptanceRejected
		}
		f.owner.dataReaders--
	}()
	temporary := &restartPinned{handle: h, path: f.path}
	id, descriptor, e := restartFileMetadata(temporary)
	if e != nil || !restartSameFile(id, f.id, descriptor, f.descriptor, "", "") {
		return nil, restartAcceptanceRejected
	}
	raw, e = io.ReadAll(io.LimitReader(file, max+1))
	if e != nil || len(raw) == 0 || int64(len(raw)) > max {
		clear(raw)
		return nil, restartAcceptanceRejected
	}
	after, afterDescriptor, e := restartFileMetadata(temporary)
	if e != nil || !restartSameFile(after, id, afterDescriptor, descriptor, "", "") {
		clear(raw)
		return nil, restartAcceptanceRejected
	}
	return raw, nil
}
func (p *restartPins) launchReady() bool {
	if p.dataReaders != 0 || p.dataCloseFailed {
		return false
	}
	for _, f := range p.all {
		if !f.directory && (f.access != restartFilePinRights || f.share != restartFilePinShare) {
			return false
		}
	}
	return true
}
func (f *restartPinned) check() error {
	id, descriptor, e := restartFileMetadata(f)
	if e != nil || !restartSameFile(id, f.id, descriptor, f.descriptor, f.digest, f.digest) {
		return restartAcceptanceRejected
	}
	if !f.directory && f.digest != "" {
		b, e := f.read(f.bound)
		if e != nil {
			return restartAcceptanceRejected
		}
		digest := restartHash(b)
		clear(b)
		if digest != f.digest {
			return restartAcceptanceRejected
		}
	}
	return nil
}
func restartFileMetadata(f *restartPinned) ([3]uint32, string, error) {
	var info windows.ByHandleFileInformation
	fail := func() ([3]uint32, string, error) { return [3]uint32{}, "", restartAcceptanceRejected }
	if windows.GetFileInformationByHandle(f.handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != f.directory || (!f.directory && info.NumberOfLinks != 1) {
		return fail()
	}
	var name [512]uint16
	n, e := windows.GetFinalPathNameByHandle(f.handle, &name[0], uint32(len(name)), 0)
	if e != nil || n == 0 || n >= uint32(len(name)) || windows.UTF16ToString(name[:n]) != `\\?\`+f.path {
		return fail()
	}
	if f.directory {
		var flags uint32
		var iosb windows.IO_STATUS_BLOCK
		if windows.NtQueryInformationFile(f.handle, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
			return fail()
		}
	}
	sd, e := windows.GetSecurityInfo(f.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() {
		return fail()
	}
	descriptor := sd.String()
	if descriptor == "" || len(descriptor) > 64<<10 {
		return fail()
	}
	return [3]uint32{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, descriptor, nil
}
func restartTrusted(s, operator, runtimeSID string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" || operator != "" && s == operator || runtimeSID != "" && s == runtimeSID
}
func restartSafeACL(h windows.Handle, operator, runtimeSID string, directory bool) bool {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() {
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !owner.IsValid() || !restartTrusted(owner.String(), operator, runtimeSID) {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return false
	}
	writes := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
	// Creation of an unrelated child does not replace a pinned existing child.
	// Delete-child is still rejected, as are writes to directory EA/attributes.
	if directory {
		writes &^= uint32(0x0002 | 0x0004)
		writes |= uint32(0x0040)
	}
	return restartACLRejects(acl, writes, func(s string) bool { return restartTrusted(s, operator, runtimeSID) })
}
func restartPrivateACL(h windows.Handle, operator string) bool {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() {
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !restartTrusted(owner.String(), operator, "") {
		return false
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return false
	}
	return restartACLRejects(acl, ^uint32(0), func(s string) bool { return s == operator || s == "S-1-5-18" || s == "S-1-5-32-544" })
}
func restartACLRejects(acl *windows.ACL, mask uint32, trusted func(string) bool) bool {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return false
		}
		const off = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < off+8 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if header[0] != 1 || header[1] > 15 || off+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return false
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && uint32(ace.Mask)&mask != 0 && !trusted(sid.String()) {
			return false
		}
	}
	return true
}
