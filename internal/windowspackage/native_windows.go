//go:build windows

package windowspackage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
const executableRead = uint32(0x001200a9)
const stateDirectoryRead = uint32(0x001200a1)

type objectID struct{ volume, high, low uint32 }
type binding struct {
	handle      windows.Handle
	path        string
	id          objectID
	directory   bool
	created     bool
	programData bool
	mask        uint32
	size        int
	digest      [32]byte
}
type nativeState struct {
	layout      windowsservice.Layout
	held        []*binding
	directories map[string]*binding
	objects     map[objectRole]*binding
	closed      bool
}

func (s *nativeState) Layout() windowsservice.Layout { return s.layout }
func (s *nativeState) BootstrapPath() string         { return s.path(bootstrapFile) }
func (s *nativeState) path(role objectRole) string {
	switch role {
	case programFilesApp:
		return s.layout.ProgramFiles + `\Tracebolt`
	case programDataApp:
		return s.layout.ProgramData + `\Tracebolt`
	case setupDirectory:
		return s.layout.ProgramData + `\Tracebolt\windows-setup`
	case serviceFile:
		return s.layout.Executable
	case bootstrapFile:
		return s.layout.ProgramData + `\Tracebolt\windows-setup\bootstrap.json`
	case manifestFile:
		return s.layout.ProgramData + `\Tracebolt\windows-setup\payload-manifest.json`
	}
	return ""
}
func roleMask(role objectRole) uint32 {
	switch role {
	case programFilesApp, serviceFile:
		return executableRead
	case programDataApp:
		return stateDirectoryRead
	}
	return 0
}
func nativeSession(ctx context.Context) (result session, err error) {
	if cancelled(ctx) {
		return nil, failure("cancelled")
	}
	layout, err := windowsservice.ResolveLayout()
	if err != nil || !windowspath.Canonical(layout.ProgramFiles) || !windowspath.Canonical(layout.ProgramData) || layout.ProgramFiles == layout.ProgramData || strings.HasPrefix(layout.ProgramFiles, layout.ProgramData+`\`) || strings.HasPrefix(layout.ProgramData, layout.ProgramFiles+`\`) {
		return nil, failure("layout-invalid")
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, failure("elevation-unverified")
	}
	elevated := token.IsElevated()
	if token.Close() != nil {
		return nil, failure("close-failed")
	}
	if !elevated {
		return nil, failure("elevation-required")
	}
	s := &nativeState{layout: layout, directories: map[string]*binding{}, objects: map[objectRole]*binding{}}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	for role := programFilesApp; role <= manifestFile; role++ {
		if !windowspath.Canonical(s.path(role)) {
			return nil, failure("layout-invalid")
		}
	}
	for _, base := range []string{layout.ProgramFiles, layout.ProgramData} {
		chain := pathChain(base)
		for i, path := range chain {
			if cancelled(ctx) {
				return nil, failure("cancelled")
			}
			if _, exists := s.directories[path]; exists {
				continue
			}
			var h windows.Handle
			if i == 0 {
				h, err = windowspath.OpenRoot(path)
			} else {
				parent := s.directories[chain[i-1]]
				if parent == nil {
					return nil, failure("path-binding")
				}
				h, err = windowspath.OpenChild(parent.handle, filepath.Base(path), true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
			}
			if err != nil {
				return nil, failure("ancestor-open")
			}
			b := &binding{handle: h, path: path, directory: true, programData: path == layout.ProgramData}
			s.held = append(s.held, b)
			if i == 0 {
				// Query the pinned native volume, never a mutable DOS drive mapping.
				var fs [32]uint16
				var flags uint32
				if windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))) != nil || windows.UTF16ToString(fs[:]) != "NTFS" || flags&windows.FILE_PERSISTENT_ACLS == 0 {
					return nil, failure("filesystem-unsupported")
				}
			}
			b.id, err = inspectHandle(h, path, true)
			if err != nil {
				return nil, err
			}
			if err = checkACL(b); err != nil {
				return nil, err
			}
			s.directories[path] = b
		}
	}
	return s, nil
}
func pathChain(path string) []string {
	out := []string{path[:3]}
	current := path[:2]
	for _, part := range strings.Split(path[3:], `\`) {
		current += `\` + part
		out = append(out, current)
	}
	return out
}
func (s *nativeState) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	var failed bool
	for i := len(s.held) - 1; i >= 0; i-- {
		if windows.CloseHandle(s.held[i].handle) != nil {
			failed = true
		}
	}
	s.held, s.directories, s.objects = nil, nil, nil
	if failed {
		return failure("close-failed")
	}
	return nil
}
func (s *nativeState) checkBindings(ctx context.Context) error {
	if s.closed {
		return failure("path-binding")
	}
	for _, b := range s.held {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		id, err := inspectHandle(b.handle, b.path, b.directory)
		if err != nil {
			return err
		}
		if id != b.id {
			return failure("path-binding")
		}
		if err = checkACL(b); err != nil {
			return err
		}
	}
	return nil
}
func (s *nativeState) CheckFresh(ctx context.Context) error {
	if len(s.objects) != 0 {
		return failure("existing-resource")
	}
	if err := s.checkBindings(ctx); err != nil {
		return err
	}
	for _, base := range []string{s.layout.ProgramFiles, s.layout.ProgramData} {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		parent := s.directories[base]
		if parent == nil {
			return failure("path-binding")
		}
		h, err := windowspath.OpenChild(parent.handle, "Tracebolt", true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
		if err == nil {
			_ = windows.CloseHandle(h)
			return failure("existing-resource")
		}
		// Only a missing direct child is freshness. A lost parent, denied access,
		// malformed/reparse object, or any other uncertain result blocks creation.
		if !missingDirectChild(err) {
			return failure("absence-unverified")
		}
	}
	if cancelled(ctx) {
		return failure("cancelled")
	}
	snapshot, err := windowsservice.Inspect(ctx)
	if err != nil {
		return failure("service-inspection")
	}
	if snapshot.Exists {
		return failure("existing-service")
	}
	return s.checkBindings(ctx)
}
func missingDirectChild(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_NO_SUCH_FILE)
}
func (s *nativeState) CreateDirectory(ctx context.Context, role objectRole) error {
	if role != programFilesApp && role != programDataApp && role != setupDirectory {
		return failure("object-role")
	}
	path := s.path(role)
	parent := s.directories[filepath.Dir(path)]
	if parent == nil || s.objects[role] != nil {
		return failure("path-binding")
	}
	if err := s.checkBindings(ctx); err != nil {
		return err
	}
	sd, err := newDescriptor(roleMask(role))
	if err != nil {
		return failure("descriptor-create")
	}
	h, err := windowspath.CreateChild(parent.handle, filepath.Base(path), true, sd)
	if err != nil {
		return failure("directory-create")
	}
	// Retain the create handle before validation. No error removes the object.
	b := &binding{handle: h, path: path, directory: true, created: true, mask: roleMask(role)}
	s.held = append(s.held, b)
	b.id, err = inspectHandle(h, path, true)
	if err != nil {
		return err
	}
	if err = checkACL(b); err != nil {
		return err
	}
	s.directories[path], s.objects[role] = b, b
	return s.checkBindings(ctx)
}
func (s *nativeState) WriteFile(ctx context.Context, role objectRole, bytes []byte) error {
	if role != serviceFile && role != bootstrapFile && role != manifestFile {
		return failure("object-role")
	}
	limit := MaxBootstrapBytes
	if role == serviceFile {
		limit = MaxPayloadBytes
	}
	if len(bytes) == 0 || len(bytes) > limit {
		return failure("file-size")
	}
	path := s.path(role)
	parent := s.directories[filepath.Dir(path)]
	if parent == nil || s.objects[role] != nil {
		return failure("path-binding")
	}
	if err := s.checkBindings(ctx); err != nil {
		return err
	}
	sd, err := newDescriptor(roleMask(role))
	if err != nil {
		return failure("descriptor-create")
	}
	h, err := windowspath.CreateChild(parent.handle, filepath.Base(path), false, sd)
	if err != nil {
		return failure("file-create")
	}
	f := os.NewFile(uintptr(h), "<new package file>")
	if f == nil {
		_ = windows.CloseHandle(h)
		return failure("file-handle")
	}
	defer f.Close()
	b := &binding{handle: h, path: path, created: true, mask: roleMask(role), size: len(bytes), digest: sha256.Sum256(bytes)}
	b.id, err = inspectHandle(h, path, false)
	if err != nil {
		return err
	}
	if err = checkACL(b); err != nil {
		return err
	}
	if err = s.checkBindings(ctx); err != nil {
		return err
	}
	for offset := 0; offset < len(bytes); {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		end := min(offset+(1<<20), len(bytes))
		n, err := f.Write(bytes[offset:end])
		if err != nil || n != end-offset {
			return failure("file-write")
		}
		offset = end
	}
	if f.Sync() != nil {
		return failure("file-flush")
	}
	if err = verifyFile(ctx, f, b); err != nil {
		return err
	}
	if err = checkACL(b); err != nil {
		return err
	}
	if f.Close() != nil {
		return failure("close-failed")
	}
	// Transition from the exclusive creation writer to a read-only pin through
	// the same still-held protected parent. Reject substitution by object ID/hash.
	pin, err := windowspath.OpenChild(parent.handle, filepath.Base(path), false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return failure("file-pin")
	}
	b.handle = pin
	s.held = append(s.held, b)
	id, err := inspectHandle(pin, path, false)
	if err != nil {
		return err
	}
	if id != b.id {
		return failure("path-binding")
	}
	if err = checkACL(b); err != nil {
		return err
	}
	if err = hashBinding(ctx, b); err != nil {
		return err
	}
	s.objects[role] = b
	return s.checkBindings(ctx)
}
func (s *nativeState) Verify(ctx context.Context) error {
	if len(s.objects) != 6 {
		return failure("package-incomplete")
	}
	if err := s.checkBindings(ctx); err != nil {
		return err
	}
	for _, role := range []objectRole{serviceFile, bootstrapFile, manifestFile} {
		if err := hashBinding(ctx, s.objects[role]); err != nil {
			return err
		}
	}
	if err := s.checkBindings(ctx); err != nil {
		return err
	}
	// ReadProtectedInstaller deliberately opens bootstrap with exclusive sharing.
	// Release this one content handle after its final verification so that reader
	// can obtain its own pin. Its exact admin-only ACL and pinned protected parent
	// prohibit an untrusted replacement; the executable and all ancestors stay held.
	bootstrap := s.objects[bootstrapFile]
	for i, b := range s.held {
		if b == bootstrap {
			s.held = append(s.held[:i], s.held[i+1:]...)
			h := b.handle
			b.handle = 0
			if windows.CloseHandle(h) != nil {
				return failure("close-failed")
			}
			return nil
		}
	}
	return failure("path-binding")
}
func hashBinding(ctx context.Context, b *binding) error {
	if b == nil || b.handle == 0 {
		return failure("path-binding")
	}
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), b.handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return failure("file-duplicate")
	}
	f := os.NewFile(uintptr(duplicate), "<package verification>")
	if f == nil {
		_ = windows.CloseHandle(duplicate)
		return failure("file-handle")
	}
	err := verifyFile(ctx, f, b)
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = failure("close-failed")
	}
	return err
}
func verifyFile(ctx context.Context, f *os.File, b *binding) error {
	if !onlyDefaultStream(b.handle) {
		return failure("file-streams")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failure("file-read")
	}
	hash := sha256.New()
	var buffer [64 << 10]byte
	total := 0
	for {
		if cancelled(ctx) {
			return failure("cancelled")
		}
		n, err := f.Read(buffer[:])
		total += n
		if total > b.size {
			return failure("file-digest")
		}
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return failure("file-read")
		}
	}
	if total != b.size || string(hash.Sum(nil)) != string(b.digest[:]) {
		return failure("file-digest")
	}
	return nil
}
func onlyDefaultStream(h windows.Handle) bool {
	var aligned [256]uint64
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(&aligned[0])), 2048)
	if windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &bytes[0], uint32(len(bytes))) != nil {
		return false
	}
	if binary.LittleEndian.Uint32(bytes[:4]) != 0 || binary.LittleEndian.Uint32(bytes[4:8]) != 14 {
		return false
	}
	want := windows.StringToUTF16("::$DATA")[:7]
	for i, u := range want {
		if binary.LittleEndian.Uint16(bytes[24+i*2:26+i*2]) != u {
			return false
		}
	}
	return true
}
func inspectHandle(h windows.Handle, path string, directory bool) (objectID, error) {
	kind, kindErr := windows.GetFileType(h)
	if kindErr != nil || kind != windows.FILE_TYPE_DISK {
		return objectID{}, failure("object-kind")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil {
		return objectID{}, failure("object-metadata")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return objectID{}, failure("object-reparse")
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DEVICE|windows.FILE_ATTRIBUTE_OFFLINE) != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
		return objectID{}, failure("object-kind")
	}
	var final [512]uint16
	n, err := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
	if err != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+path {
		return objectID{}, failure("path-binding")
	}
	if directory {
		var flags uint32
		var iosb windows.IO_STATUS_BLOCK
		if windows.NtQueryInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
			return objectID{}, failure("directory-case")
		}
	}
	id := objectID{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}
	if id == (objectID{}) {
		return objectID{}, failure("object-metadata")
	}
	return id, nil
}
