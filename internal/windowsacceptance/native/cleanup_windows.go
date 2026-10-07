//go:build windows

package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// There is no recursive path deletion or ACL repair. Cleanup freezes a bounded
// allowlisted tree, then deletes only its still-matching open handles bottom-up.
// A failed verification, incomplete receipt, unknown child or changed hash/ID
// retains resources for administrator review rather than expanding its scope.
type heldObject struct {
	object ownedObject
	handle windows.Handle
}

func onlyDefaultStream(h windows.Handle) bool {
	var aligned [256]uint64
	b := unsafe.Slice((*byte)(unsafe.Pointer(&aligned[0])), 2048)
	if windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &b[0], uint32(len(b))) != nil {
		return false
	}
	const header = 24
	if binary.LittleEndian.Uint32(b[:4]) != 0 || binary.LittleEndian.Uint32(b[4:8]) != 14 {
		return false
	}
	want := windows.StringToUTF16("::$DATA")[:7]
	for i, u := range want {
		if binary.LittleEndian.Uint16(b[header+i*2:header+i*2+2]) != u {
			return false
		}
	}
	return true
}
func hashHandle(h windows.Handle, max int64) (string, error) {
	if !onlyDefaultStream(h) {
		return "", ErrAcceptance
	}
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return "", ErrAcceptance
	}
	f := os.NewFile(uintptr(duplicate), "<owned object>")
	if f == nil {
		windows.CloseHandle(duplicate)
		return "", ErrAcceptance
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", ErrAcceptance
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, max+1))
	if err != nil || n > max {
		return "", ErrAcceptance
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func objectACLMatches(h windows.Handle, mask uint32) bool {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	want, err := newDescriptor(mask)
	return err == nil && sd.String() == want.String()
}
func (d *Driver) objectMatches(path string) bool {
	s, ok := d.native()
	if !ok {
		return false
	}
	for _, o := range s.objects {
		if o.path != path {
			continue
		}
		access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
		if !o.directory {
			access |= windows.GENERIC_READ
		}
		h, id, err := openChecked(o.path, o.directory, access, windows.FILE_SHARE_READ)
		if err != nil {
			return false
		}
		defer windows.CloseHandle(h)
		if id != o.id {
			return false
		}
		if !o.directory {
			hash, err := hashHandle(h, maxArtifactBytes)
			return err == nil && hash == o.hash && objectACLMatches(h, executableRead)
		}
		mask := executableRead
		if o.path == filepath.Dir(s.layout.StateRoot) {
			mask = stateDirectoryRead
		}
		return objectACLMatches(h, mask)
	}
	return false
}
func (s *nativeState) recordedRoot(path string) (objectID, bool) {
	for _, o := range s.objects {
		if o.path == path && o.directory {
			return o.id, true
		}
	}
	return objectID{}, false
}
func directoryHasOnly(path string, names []string) bool {
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(names) {
		return false
	}
	expected := slices.Clone(names)
	slices.Sort(expected)
	for i, e := range entries {
		if e.Name() != expected[i] || e.Type()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}
func snapshotFile(path string, directory bool) (ownedObject, error) {
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if !directory {
		access |= windows.GENERIC_READ
	}
	share := uint32(windows.FILE_SHARE_READ)
	if directory {
		share |= windows.FILE_SHARE_WRITE
	}
	h, id, err := openChecked(path, directory, access, share)
	if err != nil {
		return ownedObject{}, ErrAcceptance
	}
	defer windows.CloseHandle(h)
	o := ownedObject{path: path, id: id, directory: directory}
	if !directory {
		o.hash, err = hashHandle(h, 2<<20)
		if err != nil {
			return ownedObject{}, ErrAcceptance
		}
	}
	return o, nil
}
func snapshotStore(path string, o windowsstate.Options) ([]ownedObject, error) {
	store, err := windowsstate.Open(path, o)
	if err != nil {
		return nil, ErrAcceptance
	}
	names, err := store.Entries()
	if err != nil || store.Verify() != nil {
		store.Close()
		return nil, ErrAcceptance
	}
	if store.Close() != nil {
		return nil, ErrAcceptance
	}
	names = append(names, o.LockName, o.TempName)
	if !directoryHasOnly(path, names) {
		return nil, ErrAcceptance
	}
	root, err := snapshotFile(path, true)
	if err != nil {
		return nil, err
	}
	out := []ownedObject{root}
	for _, name := range names {
		if slices.Contains(o.Directories, name) {
			var child windowsstate.Options
			switch name {
			case "enrollment":
				child = windowsagentconfig.Enrollment(o.RuntimeSID, false)
			case "telemetry":
				child = windowsagentconfig.Sender(o.RuntimeSID, false)
			default:
				return nil, ErrAcceptance
			}
			children, err := snapshotStore(filepath.Join(path, name), child)
			if err != nil {
				return nil, err
			}
			out = append(out, children...)
		} else {
			item, err := snapshotFile(filepath.Join(path, name), false)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
	}
	return out, nil
}
func (d *Driver) cleanupSnapshot() ([]ownedObject, error) {
	s, _ := d.native()
	var out []ownedObject
	pf, pd := filepath.Dir(s.layout.Executable), filepath.Dir(s.layout.StateRoot)
	if !directoryHasOnly(pf, []string{windowsservice.ExecutableName, probeExecutableName}) {
		return nil, ErrAcceptance
	}
	pdNames := []string{filepath.Base(s.layout.StateRoot), filepath.Base(s.layout.StateRoot) + "-installer"}
	if s.probeCreated {
		pdNames = append(pdNames, "windows-acceptance")
	}
	if !directoryHasOnly(pd, pdNames) {
		return nil, ErrAcceptance
	}
	for _, o := range s.objects {
		if o.path == pf || o.path == pd || !o.directory {
			if !d.objectMatches(o.path) {
				return nil, ErrAcceptance
			}
			out = append(out, o)
		}
	}
	stores := []struct {
		path    string
		options windowsstate.Options
	}{{s.layout.StateRoot, windowsagentconfig.RuntimeRoot(d.receipt.ServiceSID, false)}, {s.layout.StateRoot + "-installer", windowsagentconfig.Installer(false)}}
	if s.probeCreated {
		stores = append(stores, struct {
			path    string
			options windowsstate.Options
		}{s.acceptancePath(), acceptanceStoreOptions(false)})
	}
	for _, store := range stores {
		records, err := snapshotStore(store.path, store.options)
		if err != nil {
			return nil, err
		}
		id, known := s.recordedRoot(store.path)
		if !known || records[0].id != id {
			return nil, ErrAcceptance
		}
		out = append(out, records...)
	}
	if len(out) > 64 {
		return nil, ErrAcceptance
	}
	return out, nil
}
func (s *nativeState) freezeObjects(objects []ownedObject) ([]heldObject, error) {
	anchors := make(map[string]uintptr, len(s.directories))
	for path, binding := range s.directories {
		anchors[path] = uintptr(binding.handle)
	}
	pins, err := freezeTree(objects, anchors, func(parent uintptr, o ownedObject) (uintptr, error) {
		access := uint32(windows.DELETE | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
		if !o.directory {
			access |= windows.GENERIC_READ
		}
		share := uint32(windows.FILE_SHARE_READ)
		if o.directory {
			share |= windows.FILE_SHARE_WRITE
		}
		// The direct parent is the frozen DELETE handle or a retained OS anchor.
		// Never re-open that parent through openChecked's full-chain traversal.
		h, err := windowspath.OpenChild(windows.Handle(parent), filepath.Base(o.path), o.directory, access, share)
		if err != nil {
			return 0, ErrAcceptance
		}
		_, id, _, err := checkHandleDiagnostic(h, o.path, o.directory)
		if err != nil || id != o.id {
			windows.CloseHandle(h)
			return 0, ErrAcceptance
		}
		if !o.directory {
			max := int64(2 << 20)
			if strings.HasSuffix(o.path, ".exe") {
				max = maxArtifactBytes
			}
			sum, err := hashHandle(h, max)
			if err != nil || sum != o.hash {
				windows.CloseHandle(h)
				return 0, ErrAcceptance
			}
		}
		return uintptr(h), nil
	}, func(h uintptr) { _ = windows.CloseHandle(windows.Handle(h)) })
	if err != nil {
		return nil, err
	}
	held := make([]heldObject, 0, len(pins))
	for _, pin := range pins {
		held = append(held, heldObject{pin.object, windows.Handle(pin.handle)})
	}
	return held, nil
}
func (d *Driver) cleanup(ctx context.Context, g Guard) error {
	s, ok := d.native()
	if !ok || !d.evidence.Uninstalled || !d.verifyReceipt() {
		return d.fail(ReasonOwnership)
	}
	defer func() { s.releaseObjectPins(); closeHandles(s.anchors); s.anchors = nil; s.directories = nil }()
	main, err := windowsservice.Inspect(ctx)
	if err != nil || main.Exists {
		return d.fail(ReasonOwnership)
	}
	if s.probeCreated {
		if err = d.deleteProbe(ctx, g); err != nil {
			return err
		}
	} else if !probeAbsent() {
		return d.fail(ReasonExisting)
	}
	objects, err := d.cleanupSnapshot()
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	// Receipt/hash/ACL snapshots have succeeded. Release only this driver's
	// normal-lifetime no-delete pins before obtaining cleanup DELETE handles.
	// App ACLs and the retained OS ancestors still prohibit untrusted replacement;
	// freezeObjects opens from the retained direct parent and rechecks every ID.
	s.releaseObjectPins()
	held, err := s.freezeObjects(objects)
	if err != nil {
		return d.fail(ReasonOwnership)
	}
	defer func() {
		for _, o := range held {
			if o.handle != 0 {
				windows.CloseHandle(o.handle)
			}
		}
	}()
	// Longest paths first means descendants precede their parent. Unknown new
	// children make directory disposition fail; they are never discovered/deleted.
	slices.SortFunc(held, func(a, b heldObject) int {
		if len(a.object.path) > len(b.object.path) {
			return -1
		}
		if len(a.object.path) < len(b.object.path) {
			return 1
		}
		return strings.Compare(a.object.path, b.object.path)
	})
	for i := range held {
		if !approved(ctx, g) {
			return d.fail(ReasonGuard)
		}
		id, err := info(held[i].handle, held[i].object.directory)
		if err != nil || id != held[i].object.id {
			return d.fail(ReasonOwnership)
		}
		if !held[i].object.directory {
			max := int64(2 << 20)
			if strings.HasSuffix(held[i].object.path, ".exe") {
				max = maxArtifactBytes
			}
			sum, err := hashHandle(held[i].handle, max)
			if err != nil || sum != held[i].object.hash {
				return d.fail(ReasonOwnership)
			}
		}
		// FILE_DISPOSITION_INFO contains one BOOLEAN. This marks this exact opened
		// object for deletion; no later path lookup can redirect the deletion.
		remove := byte(1)
		if windows.SetFileInformationByHandle(held[i].handle, windows.FileDispositionInfo, &remove, 1) != nil {
			return d.fail(ReasonOperation)
		}
		if windows.CloseHandle(held[i].handle) != nil {
			return d.fail(ReasonOperation)
		}
		held[i].handle = 0
	}
	if !absent(filepath.Dir(s.layout.Executable)) || !absent(filepath.Dir(s.layout.StateRoot)) || !probeAbsent() {
		return d.fail(ReasonOperation)
	}
	d.evidence.Cleaned = true
	d.evidence.CleanupRetained = false
	return nil
}
