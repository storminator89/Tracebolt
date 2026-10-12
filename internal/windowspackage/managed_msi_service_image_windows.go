//go:build windows

package windowspackage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
)

type nativeManagedMSIImage struct {
	state    *nativeState
	observer windowsservice.Receipt
	parent   *binding
	file     *binding
	deleting bool
}

func nativeManagedMSIImageBackend(ctx context.Context, observer windowsservice.Receipt) (result managedMSIImageBackend, err error) {
	if cancelled(ctx) {
		return nil, failure("cancelled")
	}
	base, err := nativeSession(ctx)
	if err != nil {
		return nil, err
	}
	s := &nativeManagedMSIImage{state: base.(*nativeState), observer: observer}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	if observer.Layout != s.state.layout {
		return nil, failure("layout-invalid")
	}
	if err = s.Check(ctx); err != nil {
		return nil, err
	}
	parent := s.state.directories[s.state.layout.ProgramFiles]
	if parent == nil {
		return nil, failure("path-binding")
	}
	h, err := windowspath.OpenChild(parent.handle, "Tracebolt", true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if err != nil {
		return nil, failure("ancestor-open")
	}
	b := &binding{handle: h, path: s.state.layout.ProgramFiles + `\Tracebolt`, directory: true}
	s.state.held = append(s.state.held, b)
	b.id, err = inspectHandle(h, b.path, true)
	if err != nil {
		return nil, err
	}
	if err = checkACL(b); err != nil {
		return nil, err
	}
	s.parent = b
	s.state.directories[b.path] = b
	if !windowspath.Canonical(s.Path()) {
		return nil, failure("layout-invalid")
	}
	if err = s.Check(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *nativeManagedMSIImage) Path() string {
	return s.state.layout.ProgramFiles + `\Tracebolt\` + ManagedMSIServiceImageName
}

func (s *nativeManagedMSIImage) Check(ctx context.Context) error {
	if err := s.state.checkBindings(ctx); err != nil {
		return err
	}
	snapshot, err := windowsservice.InspectOwned(ctx, s.observer)
	if err != nil || !snapshot.Exists || snapshot.State != windowsservice.Stopped {
		return failure("observer-not-owned-stopped")
	}
	return s.state.checkBindings(ctx)
}

func (s *nativeManagedMSIImage) CheckAbsent(ctx context.Context) error {
	if err := s.Check(ctx); err != nil {
		return err
	}
	if s.parent == nil || s.file != nil {
		return failure("existing-resource")
	}
	h, err := windowspath.OpenChild(s.parent.handle, ManagedMSIServiceImageName, false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err == nil {
		if windows.CloseHandle(h) != nil {
			return failure("close-failed")
		}
		return failure("existing-resource")
	}
	if !missingDirectChild(err) {
		return failure("absence-unverified")
	}
	return s.Check(ctx)
}

func (s *nativeManagedMSIImage) Create(ctx context.Context, payload []byte) (result ManagedMSIServiceImageReceipt, err error) {
	if err = s.CheckAbsent(ctx); err != nil {
		return result, err
	}
	sd, err := newDescriptor(0) // SYSTEM/Administrators only; no parent ACL edit.
	if err != nil {
		return result, failure("descriptor-create")
	}
	h, err := windowspath.CreateChild(s.parent.handle, ManagedMSIServiceImageName, false, sd)
	if err != nil {
		return result, failure("file-create")
	}
	f := os.NewFile(uintptr(h), "<new managed MSI service image>")
	if f == nil {
		_ = windows.CloseHandle(h)
		return result, failure("file-handle")
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := f.Close(); err == nil && closeErr != nil {
				err = failure("close-failed")
			}
		}
	}()
	b := &binding{handle: h, path: s.Path(), created: true, size: len(payload), digest: sha256.Sum256(payload)}
	b.id, err = inspectHandle(h, b.path, false)
	if err != nil {
		return result, err
	}
	if err = checkACL(b); err != nil {
		return result, err
	}
	if err = s.Check(ctx); err != nil {
		return result, err
	}
	for offset := 0; offset < len(payload); {
		if cancelled(ctx) {
			return result, failure("cancelled")
		}
		end := min(offset+(1<<20), len(payload))
		n, writeErr := f.Write(payload[offset:end])
		if writeErr != nil || n != end-offset {
			return result, failure("file-write")
		}
		offset = end
	}
	if f.Sync() != nil {
		return result, failure("file-flush")
	}
	if err = verifyFile(ctx, f, b); err != nil {
		return result, err
	}
	id, err := inspectHandle(h, b.path, false)
	if err != nil || id != b.id {
		return result, failure("path-binding")
	}
	if err = checkACL(b); err != nil {
		return result, err
	}
	closed = true
	if f.Close() != nil {
		return result, failure("close-failed")
	}
	// Transition only through the same pinned parent. Compare the original
	// creation ID and bytes; an identically hashed replacement is still foreign.
	observed, err := s.Read(ctx, false)
	if err != nil {
		return result, err
	}
	if observed.VolumeSerialNumber != b.id.volume || observed.FileIndexHigh != b.id.high || observed.FileIndexLow != b.id.low || observed.Size != int64(len(payload)) || observed.SHA256 != "sha256:"+hex.EncodeToString(b.digest[:]) {
		return result, failure("image-identity")
	}
	return observed, nil
}

func (s *nativeManagedMSIImage) closeFile() error {
	if s.file == nil {
		return nil
	}
	h := s.file.handle
	s.file = nil
	if windows.CloseHandle(h) != nil {
		return failure("close-failed")
	}
	return nil
}

func (s *nativeManagedMSIImage) Read(ctx context.Context, deleting bool) (result ManagedMSIServiceImageReceipt, err error) {
	if err = s.Check(ctx); err != nil {
		return result, err
	}
	if s.parent == nil {
		return result, failure("path-binding")
	}
	if s.file != nil && s.deleting != deleting {
		if err = s.closeFile(); err != nil {
			return result, err
		}
	}
	if s.file == nil {
		access, share := uint32(windows.GENERIC_READ|windows.READ_CONTROL), uint32(windows.FILE_SHARE_READ)
		if deleting {
			access |= windows.DELETE
			share = 0
		}
		h, openErr := windowspath.OpenChild(s.parent.handle, ManagedMSIServiceImageName, false, access, share)
		if openErr != nil {
			return result, failure("file-pin")
		}
		s.file = &binding{handle: h, path: s.Path(), created: true}
		s.deleting = deleting
		s.file.id, err = inspectHandle(h, s.Path(), false)
		if err != nil {
			return result, err
		}
	}
	b := s.file
	id, err := inspectHandle(b.handle, b.path, false)
	if err != nil || id != b.id {
		return result, failure("path-binding")
	}
	if err = checkACL(b); err != nil {
		return result, err
	}
	if !onlyDefaultStream(b.handle) {
		return result, failure("file-streams")
	}
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), b.handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return result, failure("file-duplicate")
	}
	f := os.NewFile(uintptr(duplicate), "<managed MSI service image verification>")
	if f == nil {
		_ = windows.CloseHandle(duplicate)
		return result, failure("file-handle")
	}
	size, digest, readErr := readManagedMSIImage(ctx, f)
	closeErr := f.Close()
	if readErr != nil {
		return result, readErr
	}
	if closeErr != nil {
		return result, failure("close-failed")
	}
	id, err = inspectHandle(b.handle, b.path, false)
	if err != nil || id != b.id {
		return result, failure("path-binding")
	}
	if err = checkACL(b); err != nil {
		return result, err
	}
	if !onlyDefaultStream(b.handle) {
		return result, failure("file-streams")
	}
	if err = s.Check(ctx); err != nil {
		return result, err
	}
	return ManagedMSIServiceImageReceipt{Version: ManagedMSIServiceImageVersion, Path: b.path, SHA256: digest, Size: size, VolumeSerialNumber: id.volume, FileIndexHigh: id.high, FileIndexLow: id.low}, nil
}

func readManagedMSIImage(ctx context.Context, f *os.File) (int64, string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", failure("file-read")
	}
	hash := sha256.New()
	var buffer [64 << 10]byte
	var total int64
	for {
		if cancelled(ctx) {
			return 0, "", failure("cancelled")
		}
		n, err := f.Read(buffer[:])
		total += int64(n)
		if total > MaxPayloadBytes {
			return 0, "", failure("file-size")
		}
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return 0, "", failure("file-read")
		}
	}
	if total < 512 {
		return 0, "", failure("file-size")
	}
	return total, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *nativeManagedMSIImage) Delete(ctx context.Context, original ManagedMSIServiceImageReceipt) error {
	// Rehash and recheck the same exclusive DELETE-capable handle immediately
	// before disposition. No pathname deletion, recursive removal or repair.
	observed, err := s.Read(ctx, true)
	if err != nil {
		return err
	}
	if original.Validate() != nil || observed != original || s.file == nil || !s.deleting {
		return failure("image-identity")
	}
	if cancelled(ctx) {
		return failure("cancelled")
	}
	remove := byte(1)
	if windows.SetFileInformationByHandle(s.file.handle, windows.FileDispositionInfo, &remove, 1) != nil {
		return failure("image-remove")
	}
	return s.closeFile()
}

func (s *nativeManagedMSIImage) Close() error {
	return errors.Join(s.closeFile(), s.state.Close())
}
