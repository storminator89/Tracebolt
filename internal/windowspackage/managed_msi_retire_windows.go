//go:build windows

package windowspackage

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/windows"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowspath"
)

// Retire uses only the fixed namespace and original successful import receipt.
// Unknown/failed deletion remains fenced by the endpoint's durable intent; this
// code never retries a partially completed retirement or adopts replacement data.
func (m *ManagedMSIPayload) Retire(ctx context.Context, raw json.RawMessage, final func() error) (err error) {
	var r ManagedMSIReceipt
	if m.failed || m.pin != nil || m.file != nil || final == nil || managed.Canonical(raw, &r, 4096) != nil || r.Validate() != nil {
		return managed.ErrIntegrity
	}
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer func() {
		if e := p.Close(); e != nil {
			err = managed.ErrUncertain
		}
		if err != nil {
			m.failed = true
		}
	}()
	h, e := windowspath.OpenChild(p.parent.handle, managedMSIDirectory, true, windowspath.DirectoryAccess|windows.DELETE, windowspath.DirectoryShare)
	if e != nil {
		return e
	}
	p.directory, e = p.retain(h, managedMSIDirectory, true)
	if e != nil {
		return e
	}
	h, e = windowspath.OpenChild(p.directory.handle, managedMSIName, false, windows.GENERIC_READ|windows.READ_CONTROL|windows.DELETE, 0)
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
	// The import receipt already records verified MSI metadata. Retirement
	// rehashes exact protected bytes without reopening the package in MSI.
	if !onlyDefaultStream(p.file.handle) {
		return managed.ErrIntegrity
	}
	p.file.size = int(r.Package.Size)
	encoded := r.Package.SHA256[len("sha256:"):]
	for i := range p.file.digest {
		p.file.digest[i] = hexByte(encoded[2*i])<<4 | hexByte(encoded[2*i+1])
	}
	if e = hashBinding(ctx, p.file); e != nil {
		return e
	}
	if e = p.state.checkBindings(ctx); e != nil {
		return e
	}
	if e = final(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	// Both dispositions operate on exclusively pinned objects; the directory
	// operation fails if unexpected children are present. No path deletion.
	remove := byte(1)
	if windows.SetFileInformationByHandle(p.file.handle, windows.FileDispositionInfo, &remove, 1) != nil {
		return managed.ErrUncertain
	}
	if windows.CloseHandle(p.file.handle) != nil {
		return managed.ErrUncertain
	}
	p.state.held = p.state.held[:len(p.state.held)-1]
	p.file = nil
	if e = p.state.checkBindings(ctx); e != nil {
		return e
	}
	if e = final(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if windows.SetFileInformationByHandle(p.directory.handle, windows.FileDispositionInfo, &remove, 1) != nil {
		return managed.ErrUncertain
	}
	if windows.CloseHandle(p.directory.handle) != nil {
		return managed.ErrUncertain
	}
	p.state.held = p.state.held[:len(p.state.held)-1]
	p.directory = nil
	if e = p.state.checkBindings(ctx); e != nil {
		return e
	}
	h, e = windowspath.OpenChild(p.parent.handle, managedMSIDirectory, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e == nil {
		windows.CloseHandle(h)
		return managed.ErrUncertain
	}
	if e != windows.STATUS_OBJECT_NAME_NOT_FOUND {
		return managed.ErrUncertain
	}
	if e = final(); e != nil {
		return e
	}
	m.offset = 0
	m.selection = managed.Selection{}
	m.hash = nil
	return nil
}
