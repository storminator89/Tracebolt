//go:build windows

package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
)

const maxArtifactBytes = 128 << 20
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
const directoryRead = uint32(0x001200a0)
const executableRead = uint32(0x001200a9)
const stateDirectoryRead = uint32(0x001200a1)

type objectID struct{ Volume, High, Low uint32 }
type ownedObject struct {
	path      string
	id        objectID
	hash      string
	directory bool
}
type nativeState struct {
	layout           windowsservice.Layout
	anchors          []windows.Handle
	objects          []ownedObject
	probeCreated     bool
	probeComplete    bool
	probeDescription string
	probeSID         string
	probeDeleted     bool
	claimBinding     [32]byte
	sender           senderContinuity
}

func (*nativeState) platformState() {}
func (d *Driver) native() (*nativeState, bool) {
	s, ok := d.state.(*nativeState)
	return s, ok && s != nil
}
func closeHandles(h []windows.Handle) {
	for i := len(h) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(h[i])
	}
}
func canonicalPath(p string) bool {
	if len(p) < 3 || len(p) > 240 || p[0] < 'A' || p[0] > 'Z' || p[1:3] != `:\` || strings.ContainsAny(p, "/\x00\r\n\"") {
		return false
	}
	for _, r := range p {
		if r < 32 || r > 126 {
			return false
		}
	}
	if len(p) == 3 {
		return true
	}
	for _, s := range strings.Split(p[3:], `\`) {
		if s == "" || s == "." || s == ".." || strings.Contains(s, ":") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") || strings.Contains(s, "~") {
			return false
		}
	}
	return true
}
func trusted(s string) bool { return s == "S-1-5-18" || s == "S-1-5-32-544" || s == trustedInstaller }

// Existing ancestor admission establishes trusted path integrity only. It does
// not guess future service token groups or substitute a named-SID scan for
// Windows effective access checks. Real runtime opens retain their full masks.
func ancestorDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil || !sd.IsValid() {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trusted(owner.String()) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	writes := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | 0x40 | windows.FILE_WRITE_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES)
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
		const offset = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < offset+8 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if offset+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return false
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&writes != 0 && !trusted(sid.String()) {
			return false
		}
	}
	return true
}
func info(h windows.Handle, directory bool) (objectID, error) {
	var f windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &f) != nil || f.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (f.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && f.NumberOfLinks != 1) {
		return objectID{}, ErrAcceptance
	}
	return objectID{f.VolumeSerialNumber, f.FileIndexHigh, f.FileIndexLow}, nil
}
func openChecked(p string, directory bool, access, share uint32) (windows.Handle, objectID, error) {
	if !canonicalPath(p) {
		return 0, objectID{}, ErrAcceptance
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, objectID{}, err
	}
	id, err := info(h, directory)
	var final [512]uint16
	n, pathErr := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
	if err != nil || pathErr != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+p {
		windows.CloseHandle(h)
		return 0, objectID{}, ErrAcceptance
	}
	if directory {
		// Match the protected store's supported directory semantics before any
		// creation: unsupported or case-sensitive ancestors fail read-only.
		var flags uint32
		var iosb windows.IO_STATUS_BLOCK
		if windows.NtQueryInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
			windows.CloseHandle(h)
			return 0, objectID{}, ErrAcceptance
		}
	}
	return h, id, nil
}
func physicalVolumePath(root string) bool {
	var target [1024]uint16
	n, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(root[:2]), &target[0], uint32(len(target)))
	if err != nil || n == 0 || n >= uint32(len(target)) {
		return false
	}
	const prefix = `\Device\HarddiskVolume`
	device := windows.UTF16ToString(target[:])
	if !strings.HasPrefix(device, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(device, prefix)
	if suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func pathChain(p string) []string {
	out := []string{p[:3]}
	current := strings.TrimSuffix(p[:3], `\`)
	for _, part := range strings.Split(p[3:], `\`) {
		current += `\` + part
		out = append(out, current)
	}
	return out
}
func absent(p string) bool {
	_, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(p))
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}
func (d *Driver) preflight(ctx context.Context) error {
	if d.state != nil {
		return d.fail(ReasonState)
	}
	d.prerequisiteCheck = "layout"
	l, err := windowsservice.ResolveLayout()
	if err != nil || !canonicalPath(l.ProgramFiles) || !canonicalPath(l.ProgramData) {
		return d.fail(ReasonPrerequisite)
	}
	d.prerequisiteCheck = "elevation"
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return d.fail(ReasonPrerequisite)
	}
	elevated := t.IsElevated()
	t.Close()
	if !elevated {
		return d.fail(ReasonPrerequisite)
	}
	s := &nativeState{layout: l}
	success := false
	defer func() {
		if !success {
			closeHandles(s.anchors)
		}
	}()
	for _, base := range []string{l.ProgramFiles, l.ProgramData} {
		d.prerequisiteCheck = "filesystem"
		if windows.GetDriveType(windows.StringToUTF16Ptr(base[:3])) != windows.DRIVE_FIXED || !physicalVolumePath(base[:3]) {
			return d.fail(ReasonPrerequisite)
		}
		var fs [32]uint16
		var flags uint32
		if windows.GetVolumeInformation(windows.StringToUTF16Ptr(base[:3]), nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))) != nil || windows.UTF16ToString(fs[:]) != "NTFS" || flags&windows.FILE_PERSISTENT_ACLS == 0 {
			return d.fail(ReasonPrerequisite)
		}
		d.prerequisiteCheck = "ancestor-policy"
		for _, p := range pathChain(base) {
			h, _, err := openChecked(p, true, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			if err != nil {
				return d.fail(ReasonPrerequisite)
			}
			s.anchors = append(s.anchors, h)
			sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil || !ancestorDescriptor(sd) {
				return d.fail(ReasonPrerequisite)
			}
		}
	}
	if ctx.Err() != nil {
		return d.fail(ReasonTimeout)
	}
	d.prerequisiteCheck = "resource-absence"
	if !absent(filepath.Dir(l.Executable)) || !absent(filepath.Dir(l.StateRoot)) {
		return d.fail(ReasonExisting)
	}
	main, err := windowsservice.Inspect(ctx)
	if err != nil {
		return d.fail(ReasonPrerequisite)
	}
	if main.Exists {
		return d.fail(ReasonExisting)
	}
	if !probeAbsent() {
		return d.fail(ReasonExisting)
	}
	d.state = s
	d.evidence.Prerequisites = true
	d.prerequisiteCheck = "complete"
	success = true
	return nil
}
func newDescriptor(mask uint32) (*windows.SECURITY_DESCRIPTOR, error) {
	// Both new app-owned parents and public images use explicit protected ACLs.
	// No existing object ever reaches a SetSecurityInfo/SetNamedSecurityInfo call.
	if mask == stateDirectoryRead {
		return windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a1;;;LS)")
	}
	if mask == directoryRead {
		return windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a0;;;LS)")
	}
	return windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a9;;;LS)")
}
func attributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
}
func (s *nativeState) createParent(path string, mask uint32) error {
	sd, err := newDescriptor(mask)
	if err != nil {
		return ErrAcceptance
	}
	if err = windows.CreateDirectory(windows.StringToUTF16Ptr(path), attributes(sd)); err != nil {
		return ErrAcceptance
	}
	h, id, err := openChecked(path, true, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return ErrAcceptance
	}
	windows.CloseHandle(h)
	s.objects = append(s.objects, ownedObject{path: path, id: id, directory: true})
	return nil
}
func readArtifact(path, digest string) ([]byte, error) {
	if !canonicalPath(path) {
		return nil, ErrAcceptance
	}
	h, _, err := openChecked(path, false, windows.GENERIC_READ, windows.FILE_SHARE_READ)
	if err != nil {
		return nil, ErrAcceptance
	}
	f := os.NewFile(uintptr(h), "<artifact>")
	if f == nil {
		windows.CloseHandle(h)
		return nil, ErrAcceptance
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxArtifactBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxArtifactBytes {
		return nil, ErrAcceptance
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != digest {
		clear(b)
		return nil, ErrAcceptance
	}
	return b, nil
}
func (s *nativeState) createArtifact(path string, b []byte, digest string) error {
	sd, err := newDescriptor(executableRead)
	if err != nil {
		return ErrAcceptance
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, attributes(sd), windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return ErrAcceptance
	}
	f := os.NewFile(uintptr(h), "<created artifact>")
	if f == nil {
		windows.CloseHandle(h)
		return ErrAcceptance
	}
	defer f.Close()
	id, err := info(h, false)
	if err != nil {
		return ErrAcceptance
	}
	s.objects = append(s.objects, ownedObject{path: path, id: id, hash: digest})
	if _, err = f.Write(b); err != nil {
		return ErrAcceptance
	}
	if f.Sync() != nil {
		return ErrAcceptance
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return ErrAcceptance
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrAcceptance
	}
	return nil
}
func (d *Driver) provision(ctx context.Context, g Guard) error {
	if d.evidence.Provisioned || d.state == nil {
		return d.fail(ReasonState)
	}
	s, ok := d.native()
	if !ok {
		return d.fail(ReasonState)
	}
	service, err := readArtifact(d.options.ServiceArtifact, d.options.ServiceSHA256)
	if err != nil {
		return d.fail(ReasonArtifact)
	}
	defer clear(service)
	controller, err := readArtifact(d.options.ControllerArtifact, d.options.ControllerSHA256)
	if err != nil {
		return d.fail(ReasonArtifact)
	}
	defer clear(controller)
	if !g.Check() || ctx.Err() != nil {
		return d.fail(ReasonGuard)
	}
	if !absent(filepath.Dir(s.layout.Executable)) || !absent(filepath.Dir(s.layout.StateRoot)) || !probeAbsent() {
		return d.fail(ReasonExisting)
	}
	current, err := windowsservice.Inspect(ctx)
	if err != nil || current.Exists {
		return d.fail(ReasonExisting)
	}
	d.evidence.CleanupRetained = true
	for _, item := range []struct {
		path string
		mask uint32
	}{{filepath.Dir(s.layout.Executable), executableRead}, {filepath.Dir(s.layout.StateRoot), stateDirectoryRead}} {
		if !g.Check() || ctx.Err() != nil {
			return d.fail(ReasonGuard)
		}
		if s.createParent(item.path, item.mask) != nil {
			return d.fail(ReasonOperation)
		}
	}
	if !g.Check() || ctx.Err() != nil {
		return d.fail(ReasonGuard)
	}
	if s.createArtifact(s.layout.Executable, service, d.options.ServiceSHA256) != nil {
		return d.fail(ReasonOperation)
	}
	if !g.Check() || ctx.Err() != nil {
		return d.fail(ReasonGuard)
	}
	if s.createArtifact(filepath.Join(filepath.Dir(s.layout.Executable), probeExecutableName), controller, d.options.ControllerSHA256) != nil {
		return d.fail(ReasonOperation)
	}
	d.evidence.Provisioned = true
	return nil
}

// releasePrerequisiteHandles only releases read handles owned by the standalone
// read-only observation. It never performs acceptance cleanup or changes a file.
func (d *Driver) releasePrerequisiteHandles() {
	if s, ok := d.native(); ok {
		closeHandles(s.anchors)
		s.anchors = nil
	}
}
