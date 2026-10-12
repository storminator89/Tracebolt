//go:build windows

package windowspackage

import (
	"context"
	"crypto/sha256"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowssoftwarejob"
)

type nativePreparedMSI struct {
	state                   *nativeState
	parent, directory, file *binding
}

func (p *nativePreparedMSI) Path() string {
	return p.parent.path + `\` + preparedMSIDirectory + `\` + preparedMSIName
}
func (p *nativePreparedMSI) Close() error { return p.state.Close() }
func openPreparedMSIParents(ctx context.Context) (p *nativePreparedMSI, err error) {
	if runtime.GOARCH != "amd64" {
		return nil, failure("architecture-mismatch")
	}
	base, e := nativeSession(ctx)
	if e != nil {
		return nil, e
	}
	p = &nativePreparedMSI{state: base.(*nativeState)}
	held := p
	defer func() {
		if err != nil {
			_ = held.Close()
		}
	}()
	parent := p.state.directories[p.state.layout.ProgramData]
	if parent == nil {
		return nil, failure("path-binding")
	}
	h, e := windowspath.OpenChild(parent.handle, "Tracebolt", true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e != nil {
		return nil, failure("ancestor-open")
	}
	b := &binding{handle: h, path: parent.path + `\Tracebolt`, directory: true}
	p.state.held = append(p.state.held, b)
	b.id, err = inspectHandle(h, b.path, true)
	if err != nil {
		return nil, err
	}
	if err = checkACL(b); err != nil {
		return nil, err
	}
	p.parent = b
	if err = p.state.checkBindings(ctx); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *nativePreparedMSI) retain(h windows.Handle, name string, directory bool) (*binding, error) {
	parent := p.parent
	if !directory {
		parent = p.directory
	}
	b := &binding{handle: h, path: parent.path + `\` + name, directory: directory, created: true}
	p.state.held = append(p.state.held, b)
	var e error
	b.id, e = inspectHandle(h, b.path, directory)
	if e != nil {
		return nil, e
	}
	if e = checkACL(b); e != nil {
		return nil, e
	}
	return b, nil
}
func (p *nativePreparedMSI) receipt(s job.Selection) PreparedMSIReceipt {
	return PreparedMSIReceipt{Version: PreparedMSIVersion, Package: s, VolumeSerialNumber: p.file.id.volume, FileIndexHigh: p.file.id.high, FileIndexLow: p.file.id.low, DirectoryVolumeSerialNumber: p.directory.id.volume, DirectoryFileIndexHigh: p.directory.id.high, DirectoryFileIndexLow: p.directory.id.low}
}
func stagePreparedMSINative(ctx context.Context, observer windowsservice.Receipt, payload []byte, s job.Selection) (r PreparedMSIReceipt, err error) {
	p, err := openPreparedMSIParents(ctx)
	if err != nil {
		return r, err
	}
	defer func() {
		if e := p.Close(); err == nil {
			err = e
		}
	}()
	check := func() error {
		if observer.Layout != p.state.layout {
			return failure("layout-invalid")
		}
		snap, e := windowsservice.InspectOwned(ctx, observer)
		if e != nil || !snap.Exists || snap.State != windowsservice.Stopped {
			return failure("observer-not-owned-stopped")
		}
		return p.state.checkBindings(ctx)
	}
	if err = check(); err != nil {
		return r, err
	}
	sd, err := newDescriptor(0)
	if err != nil {
		return r, err
	}
	h, err := windowspath.CreateChild(p.parent.handle, preparedMSIDirectory, true, sd)
	if err != nil {
		return r, failure("directory-create")
	}
	p.directory, err = p.retain(h, preparedMSIDirectory, true)
	if err != nil {
		return r, err
	}
	if err = check(); err != nil {
		return r, err
	}
	h, err = windowspath.CreateChild(p.directory.handle, preparedMSIName, false, sd)
	if err != nil {
		return r, failure("file-create")
	}
	f := os.NewFile(uintptr(h), "<prepared MSI creation>")
	if f == nil {
		_ = windows.CloseHandle(h)
		return r, failure("file-handle")
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	b := &binding{handle: h, path: p.Path(), created: true, size: len(payload), digest: sha256.Sum256(payload)}
	b.id, err = inspectHandle(h, b.path, false)
	if err != nil {
		return r, err
	}
	if err = checkACL(b); err != nil {
		return r, err
	}
	for offset := 0; offset < len(payload); {
		if cancelled(ctx) {
			return r, failure("cancelled")
		}
		end := min(offset+(1<<20), len(payload))
		n, e := f.Write(payload[offset:end])
		if e != nil || n != end-offset {
			return r, failure("file-write")
		}
		offset = end
	}
	if f.Sync() != nil {
		return r, failure("file-flush")
	}
	if err = verifyFile(ctx, f, b); err != nil {
		return r, err
	}
	if err = checkACL(b); err != nil {
		return r, err
	}
	closed = true
	if f.Close() != nil {
		return r, failure("close-failed")
	}
	pin, err := windowspath.OpenChild(p.directory.handle, preparedMSIName, false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return r, failure("file-pin")
	}
	p.file, err = p.retain(pin, preparedMSIName, false)
	if err != nil {
		return r, err
	}
	if p.file.id != b.id {
		return r, failure("msi-identity")
	}
	r = p.receipt(s)
	if err = p.Verify(ctx, r); err != nil {
		return PreparedMSIReceipt{}, err
	}
	if err = check(); err != nil {
		return PreparedMSIReceipt{}, err
	}
	return r, nil
}
func openPreparedMSINative(ctx context.Context, r PreparedMSIReceipt) (out preparedMSIPin, err error) {
	p, err := openPreparedMSIParents(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	h, e := windowspath.OpenChild(p.parent.handle, preparedMSIDirectory, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e != nil {
		return nil, failure("directory-open")
	}
	p.directory, err = p.retain(h, preparedMSIDirectory, true)
	if err != nil {
		return nil, err
	}
	h, e = windowspath.OpenChild(p.directory.handle, preparedMSIName, false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if e != nil {
		return nil, failure("file-pin")
	}
	p.file, err = p.retain(h, preparedMSIName, false)
	if err != nil {
		return nil, err
	}
	if err = p.Verify(ctx, r); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *nativePreparedMSI) Verify(ctx context.Context, r PreparedMSIReceipt) error {
	if r.Validate() != nil || p.file == nil || p.directory == nil || p.receipt(r.Package) != r {
		return failure("msi-identity")
	}
	if e := p.state.checkBindings(ctx); e != nil {
		return e
	}
	p.file.size = int(r.Package.Size)
	raw := r.Package.SHA256[len("sha256:"):]
	for i := range p.file.digest {
		p.file.digest[i] = hexByte(raw[2*i])<<4 | hexByte(raw[2*i+1])
	}
	if e := hashBinding(ctx, p.file); e != nil {
		return e
	}
	if e := verifyMSIDatabase(ctx, p.PinnedPath(), r.Package); e != nil {
		return e
	}
	return p.state.checkBindings(ctx)
}
func hexByte(b byte) byte {
	if b >= '0' && b <= '9' {
		return b - '0'
	}
	return b - 'a' + 10
}

// The MSI API requires a name, so resolve it from the pinned file with a volume
// GUID rather than reopening through a mutable drive-letter mapping. Custody
// remains held throughout the native call. Unsupported native paths fail closed.
func (p *nativePreparedMSI) PinnedPath() string {
	if p.file == nil {
		return ""
	}
	var buffer [512]uint16
	count, err := windows.GetFinalPathNameByHandle(p.file.handle, &buffer[0], uint32(len(buffer)), 1)
	if err != nil || count == 0 || count >= uint32(len(buffer)) {
		return ""
	}
	path := windows.UTF16ToString(buffer[:count])
	const prefix = `\\?\Volume{`
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	end := strings.Index(path, "}")
	if end != len(prefix)+36 || path[end+1:] != p.Path()[2:] {
		return ""
	}
	for _, c := range path[len(prefix):end] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-') {
			return ""
		}
	}
	return path
}
func checkPreparedMSIAbsentNative(ctx context.Context, observer windowsservice.Receipt) (err error) {
	p, err := openPreparedMSIParents(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if e := p.Close(); err == nil {
			err = e
		}
	}()
	if observer.Layout != p.state.layout {
		return failure("layout-invalid")
	}
	snap, e := windowsservice.InspectOwned(ctx, observer)
	if e != nil || !snap.Exists || snap.State != windowsservice.Stopped {
		return failure("observer-not-owned-stopped")
	}
	h, e := windowspath.OpenChild(p.parent.handle, preparedMSIDirectory, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e == nil {
		_ = windows.CloseHandle(h)
		return failure("existing-resource")
	}
	if !missingDirectChild(e) {
		return failure("absence-unverified")
	}
	return p.state.checkBindings(ctx)
}
