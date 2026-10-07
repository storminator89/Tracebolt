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
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
)

const maxArtifactBytes = 128 << 20
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
const directoryRead = uint32(0x001200a0)
const executableRead = uint32(0x001200a9)
const stateDirectoryRead = uint32(0x001200a1)

type directoryBinding struct {
	handle windows.Handle
	id     objectID
}
type nativeState struct {
	directories      map[string]directoryBinding
	objectPins       map[string]windows.Handle
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
func canonicalPath(p string) bool { return windowspath.Canonical(p) }
func trusted(s string) bool       { return s == "S-1-5-18" || s == "S-1-5-32-544" || s == trustedInstaller }

// Existing ancestor admission establishes trusted path integrity only. It does
// not guess future service token groups or substitute a named-SID scan for
// Windows effective access checks. Real runtime opens retain their full masks.
func ancestorDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	failure, _ := ancestorDescriptorDiagnostic(sd)
	return failure == ""
}
func ancestorDescriptorDiagnostic(sd *windows.SECURITY_DESCRIPTOR) (string, []string) {
	return ancestorDescriptorForRole(sd, false)
}

// The exception is limited to the resolved ProgramData leaf. No volume root,
// intermediate path, ProgramFiles directory, or app-owned child gets it.
func ancestorDescriptorForRole(sd *windows.SECURITY_DESCRIPTOR, programData bool) (string, []string) {
	if sd == nil || !sd.IsValid() {
		return "descriptor-invalid", nil
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return "owner-unavailable", nil
	}
	if !trusted(owner.String()) {
		return "owner-untrusted", nil
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return "dacl-unavailable", nil
	}
	if acl == nil {
		return "dacl-missing", nil
	}
	writes := ancestorWriteMask(programData)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return "ace-malformed", nil
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return "ace-type-unsupported", nil
		}
		const offset = unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)
		if uintptr(ace.Header.AceSize) < offset+8 {
			return "ace-malformed", nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if offset+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return "ace-malformed", nil
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&writes != 0 && !trusted(sid.String()) {
			return "untrusted-write-grant", replacementRights(uint32(ace.Mask) & writes)
		}
	}
	return "", nil
}
func info(h windows.Handle, directory bool) (objectID, error) {
	id, _, err := infoDiagnostic(h, directory)
	return id, err
}
func infoDiagnostic(h windows.Handle, directory bool) (objectID, string, error) {
	var f windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &f) != nil {
		return objectID{}, "metadata-query-failed", ErrAcceptance
	}
	failure := fileInformationFailure(f, directory)
	if failure != "" {
		return objectID{}, failure, ErrAcceptance
	}
	return objectID{f.VolumeSerialNumber, f.FileIndexHigh, f.FileIndexLow}, "", nil
}
func fileInformationFailure(f windows.ByHandleFileInformation, directory bool) string {
	if f.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "reparse-point"
	}
	if (f.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return "object-kind"
	}
	if !directory && f.NumberOfLinks != 1 {
		return "multiple-links"
	}
	return ""
}
func openChecked(p string, directory bool, access, share uint32) (windows.Handle, objectID, error) {
	h, id, _, err := openCheckedDiagnostic(p, directory, access, share)
	return h, id, err
}
func openFailure(err error) string {
	if errors.Is(err, windows.STATUS_REPARSE_POINT_ENCOUNTERED) {
		return "reparse-point"
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.STATUS_ACCESS_DENIED) {
		return "open-access-denied"
	}
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.STATUS_SHARING_VIOLATION) {
		return "open-sharing-violation"
	}
	return "open-failed"
}
func caseQueryFailure(err error, flags uint32) string {
	if err != nil {
		if errors.Is(err, windows.STATUS_ACCESS_DENIED) {
			return "case-query-denied"
		}
		if errors.Is(err, windows.STATUS_INVALID_INFO_CLASS) || errors.Is(err, windows.STATUS_NOT_SUPPORTED) {
			return "case-query-unsupported"
		}
		if errors.Is(err, windows.STATUS_INVALID_PARAMETER) {
			return "case-query-invalid"
		}
		return "case-query-failed"
	}
	if flags != 0 {
		return "case-sensitive-directory"
	}
	return ""
}
func openCheckedDiagnostic(p string, directory bool, access, share uint32) (windows.Handle, objectID, string, error) {
	if !canonicalPath(p) {
		return 0, objectID{}, "path-syntax", ErrAcceptance
	}
	chain := pathChain(p)
	var held []windows.Handle
	defer func() { closeHandles(held) }()
	for i, path := range chain {
		last := i == len(chain)-1
		isDir, wantAccess, wantShare := true, uint32(windowspath.DirectoryAccess), uint32(windowspath.DirectoryShare)
		if last {
			isDir, wantAccess, wantShare = directory, access, share
		}
		var h windows.Handle
		var err error
		if i == 0 {
			h, err = windowspath.OpenRoot(path)
		} else {
			h, err = windowspath.OpenChild(held[len(held)-1], filepath.Base(path), isDir, wantAccess, wantShare)
		}
		if err != nil {
			return 0, objectID{}, openFailure(err), err
		}
		_, id, failure, err := checkHandleDiagnostic(h, path, isDir)
		if err != nil {
			windows.CloseHandle(h)
			return 0, objectID{}, failure, err
		}
		if last {
			return h, id, "", nil
		}
		held = append(held, h)
	}
	return 0, objectID{}, "path-syntax", ErrAcceptance
}
func checkHandleDiagnostic(h windows.Handle, p string, directory bool) (windows.Handle, objectID, string, error) {
	id, failure, err := infoDiagnostic(h, directory)
	var final [512]uint16
	n, pathErr := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
	if err != nil || pathErr != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+p {
		if failure == "" {
			if pathErr != nil || n == 0 || n >= uint32(len(final)) {
				failure = "final-path-query-failed"
			} else {
				failure = "final-path-mismatch"
			}
		}
		return 0, objectID{}, failure, ErrAcceptance
	}
	if directory {
		var flags uint32
		var iosb windows.IO_STATUS_BLOCK
		err = windows.NtQueryInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation)
		if failure = caseQueryFailure(err, flags); failure != "" {
			return 0, objectID{}, failure, ErrAcceptance
		}
	}
	return h, id, "", nil
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
	if len(p) == 3 {
		return out
	}
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
	s := &nativeState{layout: l, directories: make(map[string]directoryBinding), objectPins: make(map[string]windows.Handle)}
	success := false
	defer func() {
		if !success {
			closeHandles(s.anchors)
		}
	}()
	for baseIndex, base := range []string{l.ProgramFiles, l.ProgramData} {
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
		chain := pathChain(base)
		for index, p := range chain {
			location := ancestorLocation(index, len(chain), baseIndex == 0)
			var h windows.Handle
			var openErr error
			if index == 0 {
				h, openErr = windowspath.OpenRoot(p)
			} else {
				parent, known := s.directories[chain[index-1]]
				if !known {
					return d.fail(ReasonPrerequisite)
				}
				h, openErr = windowspath.OpenChild(parent.handle, filepath.Base(p), true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
			}
			failure := ""
			var id objectID
			err := openErr
			if err != nil {
				failure = openFailure(err)
			} else {
				_, id, failure, err = checkHandleDiagnostic(h, p, true)
				if err != nil {
					windows.CloseHandle(h)
				}
			}
			if err != nil {
				d.prerequisiteDiagnostic = &PrerequisiteDiagnostic{Location: location, Failure: failure, Rights: []string{}}
				return d.fail(ReasonPrerequisite)
			}
			s.anchors = append(s.anchors, h)
			s.directories[p] = directoryBinding{h, id}
			sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			rights := []string{}
			if err != nil {
				failure = "descriptor-query-failed"
			} else {
				failure, rights = ancestorDescriptorForRole(sd, location == "program-data")
				if rights == nil {
					rights = []string{}
				}
			}
			if failure != "" {
				d.prerequisiteDiagnostic = &PrerequisiteDiagnostic{Location: location, Failure: failure, Rights: rights}
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

// checkDirectory revalidates an already held object, never an absolute name.
func (s *nativeState) checkDirectory(path string) error {
	binding, ok := s.directories[path]
	if !ok || binding.handle == 0 {
		return ErrAcceptance
	}
	_, id, _, err := checkHandleDiagnostic(binding.handle, path, true)
	if err != nil || id != binding.id {
		return ErrAcceptance
	}
	sd, err := windows.GetSecurityInfo(binding.handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrAcceptance
	}
	failure, _ := ancestorDescriptorForRole(sd, path == s.layout.ProgramData)
	if failure != "" {
		return ErrAcceptance
	}
	return nil
}
func (s *nativeState) createParent(path string, mask uint32) error {
	parentPath := filepath.Dir(path)
	parent, ok := s.directories[parentPath]
	if !ok || !canonicalPath(path) {
		return ErrAcceptance
	}
	sd, err := newDescriptor(mask)
	if err != nil {
		return ErrAcceptance
	}
	var h windows.Handle
	return windowspath.CreatedBinding(func() error { return s.checkDirectory(parentPath) }, func() error {
		var err error
		h, err = windowspath.CreateChild(parent.handle, filepath.Base(path), true, sd)
		return err
	}, func() {
		// Retain the creation handle even if a subsequent validation fails. Never
		// adopt an existing child or recover by reopening an absolute path.
		s.objectPins[path] = h
	}, func() error {
		_, id, _, err := checkHandleDiagnostic(h, path, true)
		if err != nil || !objectACLMatches(h, mask) {
			return ErrAcceptance
		}
		s.directories[path] = directoryBinding{h, id}
		s.objects = append(s.objects, ownedObject{path: path, id: id, directory: true})
		// A protected, pinned child now makes the shared ancestor nonempty. The
		// ancestor rejects untrusted delete-child and the child rejects untrusted
		// delete/write/ACL changes, so that binding survives other users' creation.
		return s.checkDirectory(parentPath)
	})
}
func (s *nativeState) releaseObjectPins() {
	for path, h := range s.objectPins {
		_ = windows.CloseHandle(h)
		delete(s.objectPins, path)
		delete(s.directories, path)
	}
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
	parentPath := filepath.Dir(path)
	parent, ok := s.directories[parentPath]
	if !ok || !canonicalPath(path) || s.checkDirectory(parentPath) != nil {
		return ErrAcceptance
	}
	h, err := windowspath.CreateChild(parent.handle, filepath.Base(path), false, sd)
	if err != nil {
		return ErrAcceptance
	}
	f := os.NewFile(uintptr(h), "<created artifact>")
	if f == nil {
		windows.CloseHandle(h)
		return ErrAcceptance
	}
	defer f.Close()
	_, id, _, err := checkHandleDiagnostic(h, path, false)
	if err != nil || s.checkDirectory(parentPath) != nil || !objectACLMatches(h, executableRead) {
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
	// Close the exclusive writer only after verification. Reopen through the
	// still-pinned protected parent with read-only/no-write/no-delete sharing.
	// Untrusted principals cannot alter that child during this transition.
	if f.Close() != nil {
		return ErrAcceptance
	}
	pin, err := windowspath.OpenChild(parent.handle, filepath.Base(path), false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return ErrAcceptance
	}
	s.objectPins[path] = pin
	_, after, _, err := checkHandleDiagnostic(pin, path, false)
	if err != nil || after != id || !objectACLMatches(pin, executableRead) {
		return ErrAcceptance
	}
	return s.checkDirectory(parentPath)
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
		s.directories = nil
	}
}
