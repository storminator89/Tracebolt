//go:build windows

package windowspackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"os"

	"golang.org/x/sys/windows"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowspath"
)

// ManagedMSIPayload is exclusively held by the dedicated service. It uses the
// same handle-relative/NTFS/ACL checks as prepared custody, in a fresh namespace
// and without a stopped-observer requirement. It cannot adopt prepared-v1 files.
type ManagedMSIPayload struct {
	pin       *nativeManagedMSI
	file      *os.File
	hash      hash.Hash
	offset    int64
	selection managed.Selection
	failed    bool
}

func NewManagedMSIPayload() managed.Payload { return &ManagedMSIPayload{} }
func (m *ManagedMSIPayload) Close() error {
	var e error
	if m.file != nil {
		e = m.file.Close()
		m.file = nil
	}
	if m.pin != nil {
		p := m.pin.Close()
		m.pin = nil
		if e == nil {
			e = p
		}
	}
	return e
}
func (m *ManagedMSIPayload) check(ctx context.Context) error {
	if m.failed || m.pin == nil || m.file == nil || cancelled(ctx) {
		return managed.ErrIntegrity
	}
	if e := m.pin.state.checkBindings(ctx); e != nil {
		return e
	}
	if !onlyDefaultStream(m.pin.file.handle) {
		return managed.ErrIntegrity
	}
	return nil
}
func (m *ManagedMSIPayload) Create(ctx context.Context, s managed.Selection) (json.RawMessage, error) {
	if m.pin != nil || !managed.ValidSelection(s) {
		return nil, managed.ErrInvalid
	}
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return nil, e
	}
	m.pin = p
	m.selection = s
	sd, e := newDescriptor(0)
	if e != nil {
		return nil, e
	}
	h, e := windowspath.CreateChild(p.parent.handle, managedMSIDirectory, true, sd)
	if e != nil {
		return nil, e
	}
	p.directory, e = p.retain(h, managedMSIDirectory, true)
	if e != nil {
		return nil, e
	}
	h, e = windowspath.CreateChild(p.directory.handle, managedMSIName, false, sd)
	if e != nil {
		return nil, e
	}
	p.file, e = p.retain(h, managedMSIName, false)
	if e != nil {
		return nil, e
	}
	if e = m.attachFile(); e != nil {
		return nil, e
	}
	m.hash = sha256.New()
	if e = m.file.Sync(); e != nil {
		return nil, e
	}
	if e = m.check(ctx); e != nil {
		return nil, e
	}
	return json.Marshal(p.receipt(s))
}
func (m *ManagedMSIPayload) attachFile() error {
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), m.pin.file.handle, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return managed.ErrIntegrity
	}
	m.file = os.NewFile(uintptr(duplicate), "<managed MSI custody>")
	if m.file == nil {
		windows.CloseHandle(duplicate)
		return managed.ErrIntegrity
	}
	return nil
}
func (m *ManagedMSIPayload) Open(ctx context.Context, raw json.RawMessage, offset int64, digest string, pending *managed.ChunkIntent) error {
	var r ManagedMSIReceipt
	if managed.Canonical(raw, &r, 4096) != nil || r.Validate() != nil || m.pin != nil || offset < 0 || offset > r.Package.Size || !managed.ValidDigest(digest) {
		return managed.ErrIntegrity
	}
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	m.pin = p
	m.selection = r.Package
	h, e := windowspath.OpenChild(p.parent.handle, managedMSIDirectory, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e != nil {
		return e
	}
	p.directory, e = p.retain(h, managedMSIDirectory, true)
	if e != nil {
		return e
	}
	h, e = windowspath.OpenChild(p.directory.handle, managedMSIName, false, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if e != nil {
		return e
	}
	p.file, e = p.retain(h, managedMSIName, false)
	if e != nil {
		return e
	}
	if p.receipt(r.Package) != r {
		return managed.ErrIntegrity
	}
	if e = m.attachFile(); e != nil {
		return e
	}
	if e = m.check(ctx); e != nil {
		return e
	}
	stat, e := m.file.Stat()
	if e != nil || stat.Size() < offset || stat.Size() > r.Package.Size {
		return managed.ErrIntegrity
	}
	tail := stat.Size() - offset
	if tail > 0 && (pending == nil || tail != int64(pending.Size) || int64(pending.Index)*managed.MaxChunkBytes != offset) {
		return managed.ErrIntegrity
	}
	m.hash = sha256.New()
	if _, e = m.file.Seek(0, io.SeekStart); e != nil {
		return e
	}
	var buf [managed.MaxChunkBytes]byte
	remaining := offset
	for remaining > 0 {
		if e = m.check(ctx); e != nil {
			return e
		}
		n := int(min(remaining, int64(len(buf))))
		if _, e = io.ReadFull(m.file, buf[:n]); e != nil {
			return e
		}
		m.hash.Write(buf[:n])
		remaining -= int64(n)
	}
	if "sha256:"+hex.EncodeToString(m.hash.Sum(nil)) != digest {
		return managed.ErrIntegrity
	}
	if tail > 0 {
		b := make([]byte, int(tail))
		if _, e = io.ReadFull(m.file, b); e != nil || managed.Digest(b) != pending.Digest {
			return managed.ErrIntegrity
		}
	}
	m.offset = offset
	return m.check(ctx)
}
func (m *ManagedMSIPayload) Append(ctx context.Context, offset int64, data []byte) (string, error) {
	if e := m.check(ctx); e != nil {
		return "", e
	}
	if len(data) == 0 || len(data) > managed.MaxChunkBytes || offset < 0 || offset+int64(len(data)) > m.selection.Size {
		return "", managed.ErrInvalid
	}
	stat, e := m.file.Stat()
	if e != nil {
		return "", e
	}
	end := offset + int64(len(data))
	if offset < m.offset {
		if end != m.offset || stat.Size() != m.offset {
			return "", managed.ErrConflict
		}
		b := make([]byte, len(data))
		if _, e = m.file.ReadAt(b, offset); e != nil || !bytes.Equal(b, data) {
			return "", managed.ErrIntegrity
		}
		return "sha256:" + hex.EncodeToString(m.hash.Sum(nil)), m.check(ctx)
	}
	if offset != m.offset || stat.Size() != offset && stat.Size() != end {
		return "", managed.ErrIntegrity
	}
	if stat.Size() == end {
		b := make([]byte, len(data))
		if _, e = m.file.ReadAt(b, offset); e != nil || !bytes.Equal(b, data) {
			return "", managed.ErrIntegrity
		}
	} else {
		n, e := m.file.WriteAt(data, offset)
		if e != nil || n != len(data) {
			m.failed = true
			return "", managed.ErrUncertain
		}
	}
	if e = m.file.Sync(); e != nil {
		m.failed = true
		return "", managed.ErrUncertain
	}
	if e = m.check(ctx); e != nil {
		return "", e
	}
	m.hash.Write(data)
	m.offset = end
	return "sha256:" + hex.EncodeToString(m.hash.Sum(nil)), nil
}
func (m *ManagedMSIPayload) Complete(ctx context.Context, s managed.Selection) (out json.RawMessage, err error) {
	if e := m.check(ctx); e != nil {
		return nil, e
	}
	if s != m.selection || m.offset != s.Size || "sha256:"+hex.EncodeToString(m.hash.Sum(nil)) != s.SHA256 {
		return nil, managed.ErrIntegrity
	}
	// Close the write handles before acquiring the immutable read-only custody
	// pin used by the MSI APIs. Compare the original NTFS receipt after reopening.
	r := m.pin.receipt(s)
	if e := m.Close(); e != nil {
		return nil, e
	}
	pin, e := openManagedMSINative(ctx, r)
	if e != nil {
		return nil, e
	}
	defer func() {
		if e := pin.Close(); e != nil {
			out = nil
			err = e
		}
	}()
	if e = pin.Verify(ctx, r); e != nil {
		return nil, e
	}
	return json.Marshal(r)
}
