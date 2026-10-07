//go:build windows

package windowsstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	readAccess      = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_DATA | windows.SYNCHRONIZE
	directoryAccess = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.SYNCHRONIZE
	writeAccess     = readAccess | windows.FILE_WRITE_DATA | windows.FILE_WRITE_ATTRIBUTES
)

type nativePin struct {
	h         windows.Handle
	id        fileID
	path      string
	protected bool
}
type nativeStore struct {
	path           string
	options        Options
	pins           []nativePin
	lock, temp     windows.Handle
	lockID, tempID fileID
	sd             *windows.SECURITY_DESCRIPTOR
}

func openNative(path string, o Options) (backend, error) {
	// A root missing on an existing-store open is the only native failure that
	// becomes fs.ErrNotExist. Ancestor loss, files missing inside a used store,
	// unsupported filesystems, access errors and wrong ACLs are never freshness.
	pins, e := pinPath(path, o, o.Create)
	if e != nil {
		return nil, e
	}
	b := &nativeStore{path: path, options: o, pins: pins}
	if e = b.initializeHandles(); e != nil {
		_ = b.close()
		return nil, e
	}
	return b, nil
}
func (b *nativeStore) rootID() fileID       { return b.pins[len(b.pins)-1].id }
func (b *nativeStore) root() windows.Handle { return b.pins[len(b.pins)-1].h }

func protectedDescriptor(o Options) (*windows.SECURITY_DESCRIPTOR, error) {
	owner, e := creationOwner(o)
	if e != nil {
		return nil, e
	}
	dacl := "O:" + owner + "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if !o.InstallerOnly {
		dacl += "(A;;FA;;;" + o.RuntimeSID + ")"
	}
	sd, e := windows.SecurityDescriptorFromString(dacl)
	if e != nil {
		return nil, ErrPolicy
	}
	return sd, nil
}
func creationOwner(o Options) (string, error) {
	// This queries the effective token; it never enables privileges or changes
	// the token. Service SID owners are supported by SE_GROUP_OWNER, documented
	// on SERVICE_SID_INFO. A generic LocalService owner is deliberately rejected.
	token := windows.GetCurrentThreadEffectiveToken()
	u, e := token.GetTokenUser()
	if e != nil {
		return "", ErrPolicy
	}
	if u.User.Sid.String() == systemSID {
		return systemSID, nil
	}
	g, e := token.GetTokenGroups()
	if e != nil {
		return "", ErrPolicy
	}
	for _, wanted := range []string{o.RuntimeSID, administratorsSID} {
		if wanted == "" {
			continue
		}
		for _, group := range g.AllGroups() {
			if group.Sid.String() == wanted && group.Attributes&windows.SE_GROUP_OWNER != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
				return wanted, nil
			}
		}
	}
	return "", ErrPolicy
}
func (b *nativeStore) initializeHandles() error {
	var e error
	b.sd, e = protectedDescriptor(b.options)
	if e != nil {
		return e
	}
	disposition := uint32(windows.FILE_OPEN)
	if b.options.Create {
		disposition = windows.FILE_CREATE
	}
	b.lock, e = ntOpen(b.root(), b.options.LockName, writeAccess, 0, disposition, false, b.sd)
	if e != nil {
		return ErrIntegrity
	}
	if e = windows.LockFileEx(b.lock, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, &windows.Overlapped{}); e != nil {
		return ErrIntegrity
	}
	b.lockID, e = validateHandle(b.lock, false, b.options, true)
	if e != nil {
		return e
	}
	b.temp, e = ntOpen(b.root(), b.options.TempName, writeAccess|windows.DELETE, 0, disposition, false, b.sd)
	if e != nil {
		return ErrIntegrity
	}
	b.tempID, e = validateHandle(b.temp, false, b.options, true)
	if e != nil {
		return e
	}
	if b.options.Create {
		if e = windows.FlushFileBuffers(b.temp); e != nil {
			return ErrStorage
		}
		if e = windows.FlushFileBuffers(b.lock); e != nil {
			return ErrStorage
		}
	}
	return nil
}

func ntOpen(parent windows.Handle, name string, access, share, disposition uint32, directory bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	unicode, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return 0, ErrPolicy
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: unicode, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if disposition == windows.FILE_CREATE {
		oa.SecurityDescriptor = sd
	}
	flags := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_OPEN_NO_RECALL)
	attributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if directory {
		flags |= windows.FILE_DIRECTORY_FILE
		attributes = windows.FILE_ATTRIBUTE_DIRECTORY
	} else {
		flags |= windows.FILE_NON_DIRECTORY_FILE | windows.FILE_WRITE_THROUGH
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&h, access, &oa, &iosb, nil, attributes, share, disposition, flags, 0, 0)
	runtime.KeepAlive(unicode)
	runtime.KeepAlive(sd)
	if e != nil {
		return 0, e
	}
	return h, nil
}
func missing(e error) bool {
	return errors.Is(e, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(e, windows.STATUS_OBJECT_PATH_NOT_FOUND) || errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND)
}

func pinPath(path string, o Options, create bool) (pins []nativePin, err error) {
	parts, e := splitPath(path)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			for i := len(pins) - 1; i >= 0; i-- {
				_ = windows.CloseHandle(pins[i].h)
			}
			pins = nil
		}
	}()
	rootName := path[:3]
	rootUTF, _ := windows.UTF16PtrFromString(rootName)
	if windows.GetDriveType(rootUTF) != windows.DRIVE_FIXED {
		return nil, ErrPolicy
	}
	drive, _ := windows.UTF16PtrFromString(path[:2])
	target := make([]uint16, 1024)
	n, e := windows.QueryDosDevice(drive, &target[0], uint32(len(target)))
	if e != nil || n == 0 || n >= uint32(len(target)) {
		return nil, ErrPolicy
	}
	device := windows.UTF16ToString(target)
	// Reject SUBST, network redirectors and arbitrary DOS device targets. Open
	// the physical local volume object rather than resolving a mutable DOS link
	// while traversing the input path.
	if !strings.HasPrefix(device, `\Device\HarddiskVolume`) {
		return nil, ErrPolicy
	}
	suffix := strings.TrimPrefix(device, `\Device\HarddiskVolume`)
	if len(suffix) == 0 {
		return nil, ErrPolicy
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return nil, ErrPolicy
		}
	}
	h, e := ntOpen(0, device+`\`, directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, true, nil)
	if e != nil {
		return nil, ErrPolicy
	}
	pins = append(pins, nativePin{h: h, path: rootName})
	id, e := validateHandle(h, true, o, false)
	if e != nil {
		return pins, e
	}
	pins[0].id = id
	if e = validateVolume(h); e != nil {
		return pins, e
	}
	if e = validateFinalPath(h, rootName); e != nil {
		return pins, e
	}
	current := rootName[:2]
	for i, part := range parts {
		current += `\` + part
		last := i == len(parts)-1
		disposition := uint32(windows.FILE_OPEN)
		var sd *windows.SECURITY_DESCRIPTOR
		if last && create {
			disposition = windows.FILE_CREATE
			sd, e = protectedDescriptor(o)
			if e != nil {
				return pins, e
			}
		}
		next, e := ntOpen(h, part, directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition, true, sd)
		if e != nil {
			if last && !create && missing(e) {
				return pins, fs.ErrNotExist
			}
			return pins, ErrPolicy
		}
		pins = append(pins, nativePin{h: next, path: current, protected: last})
		id, e = validateHandle(next, true, o, last)
		if e != nil {
			return pins, e
		}
		pins[len(pins)-1].id = id
		if e = validateFinalPath(next, current); e != nil {
			return pins, e
		}
		h = next
	}
	return pins, nil
}
func validateVolume(h windows.Handle) error {
	var flags, serial, max uint32
	var fsName [32]uint16
	if e := windows.GetVolumeInformationByHandle(h, nil, 0, &serial, &max, &flags, &fsName[0], uint32(len(fsName))); e != nil {
		return ErrPolicy
	}
	if windows.UTF16ToString(fsName[:]) != "NTFS" || flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return ErrPolicy
	}
	return nil
}
func validateFinalPath(h windows.Handle, path string) error {
	var buf [512]uint16
	n, e := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if e != nil || n >= uint32(len(buf)) || windows.UTF16ToString(buf[:n]) != `\\?\`+path {
		return ErrPolicy
	}
	return nil
}

// Some GetFileInformationByHandleEx structures require 8-byte alignment even
// on 32-bit Windows. Align the returned slice explicitly, without assuming Go
// gives a byte array native structure alignment.
func alignedBytes(size int) []byte {
	raw := make([]byte, size+7)
	offset := int((-uintptr(unsafe.Pointer(&raw[0]))) & 7)
	return raw[offset : offset+size]
}

func validateHandle(h windows.Handle, directory bool, o Options, protected bool) (fileID, error) {
	var zero fileID
	kind, e := windows.GetFileType(h)
	if e != nil || kind != windows.FILE_TYPE_DISK {
		return zero, ErrPolicy
	}
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return zero, ErrPolicy
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE|windows.FILE_ATTRIBUTE_OFFLINE) != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return zero, ErrPolicy
	}
	if !directory && info.NumberOfLinks != 1 {
		return zero, ErrPolicy
	}
	if directory {
		// Case-sensitive NTFS directories can give multiple spellings different
		// identities. Reject them rather than relaxing the canonical-name schema.
		flags := alignedBytes(4)
		var iosb windows.IO_STATUS_BLOCK
		if e = windows.NtQueryInformationFile(h, &iosb, &flags[0], uint32(len(flags)), windows.FileCaseSensitiveInformation); e != nil || binary.LittleEndian.Uint32(flags[:]) != 0 {
			return zero, ErrPolicy
		}
	}
	idBytes := alignedBytes(24)
	if e = windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, &idBytes[0], uint32(len(idBytes))); e != nil {
		return zero, ErrPolicy
	}
	var id fileID
	copy(id[:], idBytes)
	if id == (fileID{}) {
		return zero, ErrPolicy
	}
	if protected {
		sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil || sd == nil || !sd.IsValid() {
			return zero, ErrPolicy
		}
		size := sd.Length()
		if size < 20 || size > 65536 {
			return zero, ErrPolicy
		}
		p, e := parseDescriptor(unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(size)))
		runtime.KeepAlive(sd)
		if e != nil || validateSecurity(p, o.RuntimeSID, o.InstallerOnly) != nil {
			return zero, ErrPolicy
		}
	}
	if !directory {
		stream := alignedBytes(4096)
		if e = windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &stream[0], uint32(len(stream))); e != nil || validateDefaultStream(stream[:]) != nil {
			return zero, ErrPolicy
		}
	}
	return id, nil
}
func (b *nativeStore) verify() error {
	for _, p := range b.pins {
		id, e := validateHandle(p.h, true, b.options, p.protected)
		if e != nil || id != p.id {
			return ErrIntegrity
		}
		if e = validateFinalPath(p.h, p.path); e != nil {
			return ErrIntegrity
		}
	}
	return nil
}
func (b *nativeStore) list() ([]string, error) {
	var out []string
	class := uint32(windows.FileIdBothDirectoryRestartInfo)
	// Every supported directory has <= 38 entries (+ dot names). Hard-bound the
	// number of enumeration buffers even if a privileged writer floods it.
	for range maxNames + maxDirectories + 4 {
		buf := alignedBytes(16384)
		e := windows.GetFileInformationByHandleEx(b.root(), class, &buf[0], uint32(len(buf)))
		if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
			return out, nil
		}
		if e != nil {
			return nil, ErrIntegrity
		}
		names, e := parseDirectoryBuffer(buf[:])
		if e != nil {
			return nil, e
		}
		out = append(out, names...)
		if len(out) > maxNames+maxDirectories+2 {
			return nil, ErrIntegrity
		}
		class = windows.FileIdBothDirectoryInfo
	}
	return nil, ErrIntegrity
}
func (b *nativeStore) read(name string, max int64) ([]byte, fileID, error) {
	var h windows.Handle
	var expected fileID
	switch name {
	case b.options.LockName:
		h = b.lock
		expected = b.lockID
	case b.options.TempName:
		h = b.temp
		expected = b.tempID
	default:
		var e error
		h, e = ntOpen(b.root(), name, readAccess, 0, windows.FILE_OPEN, false, nil)
		if e != nil {
			if missing(e) {
				return nil, fileID{}, fs.ErrNotExist
			}
			return nil, fileID{}, ErrIntegrity
		}
		defer windows.CloseHandle(h)
	}
	id, e := validateHandle(h, false, b.options, true)
	if e != nil || expected != (fileID{}) && id != expected {
		return nil, fileID{}, ErrIntegrity
	}
	if e = validateFinalPath(h, b.path+`\`+name); e != nil {
		return nil, fileID{}, ErrIntegrity
	}
	first, e := readHandle(h, max)
	if e != nil {
		return nil, fileID{}, e
	}
	// An exclusive share-mode handle blocks writers/deletion. Recheck identity,
	// descriptor and bytes nevertheless; failures never release partial bytes.
	second, e := readHandle(h, max)
	if e != nil {
		clear(first)
		return nil, fileID{}, e
	}
	after, e := validateHandle(h, false, b.options, true)
	if e != nil || after != id || sha256.Sum256(first) != sha256.Sum256(second) {
		clear(first)
		clear(second)
		return nil, fileID{}, ErrIntegrity
	}
	clear(second)
	return first, id, nil
}
func readHandle(h windows.Handle, max int64) ([]byte, error) {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return nil, ErrStorage
	}
	n := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if max < 0 || n > uint64(max) {
		return nil, ErrIntegrity
	}
	if _, e := windows.Seek(h, 0, 0); e != nil {
		return nil, ErrStorage
	}
	buf := make([]byte, int(n))
	off := 0
	for off < len(buf) {
		var read uint32
		if e := windows.ReadFile(h, buf[off:], &read, nil); e != nil || read == 0 {
			clear(buf)
			return nil, ErrStorage
		}
		off += int(read)
	}
	var tail [1]byte
	var count uint32
	e := windows.ReadFile(h, tail[:], &count, nil)
	if (e != nil && !errors.Is(e, windows.ERROR_HANDLE_EOF)) || count != 0 {
		clear(buf)
		return nil, ErrIntegrity
	}
	return buf, nil
}
func writeHandle(h windows.Handle, data []byte) error {
	if _, e := windows.Seek(h, 0, 0); e != nil {
		return ErrStorage
	}
	for off := 0; off < len(data); {
		var written uint32
		if e := windows.WriteFile(h, data[off:], &written, nil); e != nil || written == 0 {
			return ErrStorage
		}
		off += int(written)
	}
	if e := windows.SetEndOfFile(h); e != nil {
		return ErrStorage
	}
	if e := windows.FlushFileBuffers(h); e != nil {
		return ErrStorage
	}
	return nil
}
func (b *nativeStore) writeLock(data []byte) error {
	if int64(len(data)) > maxManifestBytes {
		return ErrPolicy
	}
	id, e := validateHandle(b.lock, false, b.options, true)
	if e != nil || id != b.lockID {
		return ErrIntegrity
	}
	if e = writeHandle(b.lock, data); e != nil {
		return e
	}
	got, e := readHandle(b.lock, maxManifestBytes)
	if e != nil || !bytes.Equal(got, data) {
		return ErrIntegrity
	}
	return nil
}

// FileRenameInformation's BOOLEAN/HANDLE/ULONG/WCHAR layout uses pointer
// alignment. The flexible-array data begins at 20 on 64-bit and 12 on 32-bit.
type renameHeader struct {
	Replace   uint32
	Root      windows.Handle
	NameBytes uint32
	Name      [1]uint16
}

func renameRelative(h, root windows.Handle, name string) error {
	if !validName(name) {
		return ErrPolicy
	}
	u, e := windows.UTF16FromString(name)
	if e != nil {
		return ErrPolicy
	}
	u = u[:len(u)-1]
	var header renameHeader
	offset := int(unsafe.Offsetof(header.Name))
	size := int(unsafe.Sizeof(header)) + len(u)*2
	// uintptr storage gives native HANDLE alignment; the allocation stays alive
	// through NtSetInformationFile. The extra WCHAR/padding satisfies the SDK's
	// sizeof(FILE_RENAME_INFORMATION) + FileNameLength sizing requirement.
	words := make([]uintptr, (size+int(unsafe.Sizeof(uintptr(0)))-1)/int(unsafe.Sizeof(uintptr(0))))
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*int(unsafe.Sizeof(uintptr(0))))
	r := (*renameHeader)(unsafe.Pointer(&words[0]))
	r.Replace = 1
	r.Root = root
	r.NameBytes = uint32(len(u) * 2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(raw[offset+i*2:offset+i*2+2], v)
	}
	var iosb windows.IO_STATUS_BLOCK
	e = windows.NtSetInformationFile(h, &iosb, &raw[0], uint32(size), windows.FileRenameInformation)
	runtime.KeepAlive(words)
	if e != nil {
		return ErrStorage
	}
	return nil
}
func (b *nativeStore) replace(name string, data []byte) (fileID, fileID, error) {
	id, e := validateHandle(b.temp, false, b.options, true)
	if e != nil || id != b.tempID {
		return fileID{}, fileID{}, ErrIntegrity
	}
	if e = writeHandle(b.temp, data); e != nil {
		return fileID{}, fileID{}, e
	}
	got, e := readHandle(b.temp, b.options.MaxBytes)
	if e != nil || !bytes.Equal(got, data) {
		clear(got)
		return fileID{}, fileID{}, ErrIntegrity
	}
	clear(got)
	if e = renameRelative(b.temp, b.root(), name); e != nil {
		return fileID{}, fileID{}, e
	}
	// Flush renamed handle too. FILE_WRITE_THROUGH + file flushes do not promise
	// a physical-power-loss directory ordering guarantee on every storage stack.
	// The manifest's pending marker makes detectable interruption fail closed.
	if e = windows.FlushFileBuffers(b.temp); e != nil {
		return fileID{}, fileID{}, ErrStorage
	}
	if e = windows.CloseHandle(b.temp); e != nil {
		b.temp = 0
		return fileID{}, fileID{}, ErrStorage
	}
	b.temp = 0
	// Create-only: a stray pre-existing temp is never opened or truncated.
	b.temp, e = ntOpen(b.root(), b.options.TempName, writeAccess|windows.DELETE, 0, windows.FILE_CREATE, false, b.sd)
	if e != nil {
		return fileID{}, fileID{}, ErrStorage
	}
	b.tempID, e = validateHandle(b.temp, false, b.options, true)
	if e != nil {
		return fileID{}, fileID{}, e
	}
	if e = windows.FlushFileBuffers(b.temp); e != nil {
		return fileID{}, fileID{}, ErrStorage
	}
	return id, b.tempID, nil
}
func (b *nativeStore) directoryID(name string) (fileID, error) {
	h, e := ntOpen(b.root(), name, directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, true, nil)
	if e != nil {
		if missing(e) {
			return fileID{}, fs.ErrNotExist
		}
		return fileID{}, ErrIntegrity
	}
	defer windows.CloseHandle(h)
	id, e := validateHandle(h, true, b.options, true)
	if e != nil {
		return fileID{}, e
	}
	if e = validateFinalPath(h, b.path+`\`+name); e != nil {
		return fileID{}, e
	}
	return id, nil
}
func (b *nativeStore) createChild(name string, o Options) (backend, error) {
	sd, e := protectedDescriptor(o)
	if e != nil {
		return nil, e
	}
	h, e := ntOpen(b.root(), name, directoryAccess, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE, true, sd)
	if e != nil {
		return nil, ErrStorage
	}
	child := &nativeStore{path: b.path + `\` + name, options: o}
	// Duplicate the parent pins so the returned child remains pinned even after
	// its parent Store closes. No caller receives these native handles.
	for _, p := range b.pins {
		var dup windows.Handle
		if e = windows.DuplicateHandle(windows.CurrentProcess(), p.h, windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); e != nil {
			_ = windows.CloseHandle(h)
			_ = child.close()
			return nil, ErrStorage
		}
		p.h = dup
		child.pins = append(child.pins, p)
	}
	child.pins = append(child.pins, nativePin{h: h, path: child.path, protected: true})
	id, e := validateHandle(h, true, o, true)
	if e != nil {
		_ = child.close()
		return nil, e
	}
	child.pins[len(child.pins)-1].id = id
	if e = child.initializeHandles(); e != nil {
		_ = child.close()
		return nil, e
	}
	return child, nil
}
func (b *nativeStore) close() error {
	var result error
	for _, h := range []windows.Handle{b.temp, b.lock} {
		if h != 0 {
			if e := windows.CloseHandle(h); e != nil {
				result = ErrStorage
			}
		}
	}
	b.temp = 0
	b.lock = 0
	for i := len(b.pins) - 1; i >= 0; i-- {
		if e := windows.CloseHandle(b.pins[i].h); e != nil {
			result = ErrStorage
		}
	}
	b.pins = nil
	b.sd = nil
	return result
}

// ReadProtected performs a non-mutating bounded read with pinned ancestors and
// the same strict descriptor, no-reparse and single-link checks as Store. The
// private flag never weakens file protection. This is not a manifest/rollback
// check; a caller needing persistent state must use Store instead.
func ReadProtected(path, runtimeSID string, private bool, maxBytes int64) ([]byte, error) {
	if !validRuntimeSID(runtimeSID) {
		return nil, ErrPolicy
	}
	return readProtected(path, Options{RuntimeSID: runtimeSID}, maxBytes)
}

// ReadProtectedInstaller uses the explicit SYSTEM/Administrators-only policy.
// It is intended for pre-service bootstrap input, never runtime private state.
func ReadProtectedInstaller(path string, private bool, maxBytes int64) ([]byte, error) {
	return readProtected(path, Options{InstallerOnly: true}, maxBytes)
}
func readProtected(path string, o Options, maxBytes int64) ([]byte, error) {
	parts, e := splitPath(path)
	if e != nil || len(parts) < 2 || maxBytes <= 0 || maxBytes > maxFileBytes {
		return nil, ErrPolicy
	}
	at := strings.LastIndex(path, `\`)
	parent := path[:at]
	name := path[at+1:]
	if !validName(name) {
		return nil, ErrPolicy
	}
	pins, e := pinPath(parent, o, false)
	if e != nil {
		return nil, e
	}
	b := &nativeStore{path: parent, options: o, pins: pins}
	defer b.close()
	data, _, e := b.read(name, maxBytes)
	if e != nil {
		return nil, e
	}
	if e = b.verify(); e != nil {
		clear(data)
		return nil, e
	}
	return data, nil
}
