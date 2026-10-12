//go:build windows

package windowspackage

import (
	"context"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
	job "localrmm/internal/windowssoftwarejob"
)

type nativeManagedMSI struct {
	state                   *nativeState
	parent, directory, file *binding
}

func (p *nativeManagedMSI) Path() string {
	return p.parent.path + `\` + managedMSIDirectory + `\` + managedMSIName
}
func (p *nativeManagedMSI) Close() error { return p.state.Close() }
func openManagedMSIParents(ctx context.Context) (p *nativeManagedMSI, err error) {
	if runtime.GOARCH != "amd64" {
		return nil, failure("architecture-mismatch")
	}
	base, e := nativeSession(ctx)
	if e != nil {
		return nil, e
	}
	p = &nativeManagedMSI{state: base.(*nativeState)}
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
func (p *nativeManagedMSI) retain(h windows.Handle, name string, directory bool) (*binding, error) {
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
func (p *nativeManagedMSI) receipt(s job.Selection) ManagedMSIReceipt {
	return ManagedMSIReceipt{Version: ManagedMSIVersion, Package: s, VolumeSerialNumber: p.file.id.volume, FileIndexHigh: p.file.id.high, FileIndexLow: p.file.id.low, DirectoryVolumeSerialNumber: p.directory.id.volume, DirectoryFileIndexHigh: p.directory.id.high, DirectoryFileIndexLow: p.directory.id.low}
}
func openManagedMSINative(ctx context.Context, r ManagedMSIReceipt) (out managedMSIPin, err error) {
	p, err := openManagedMSIParents(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	h, e := windowspath.OpenChild(p.parent.handle, managedMSIDirectory, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e != nil {
		return nil, failure("directory-open")
	}
	p.directory, err = p.retain(h, managedMSIDirectory, true)
	if err != nil {
		return nil, err
	}
	h, e = windowspath.OpenChild(p.directory.handle, managedMSIName, false, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if e != nil {
		return nil, failure("file-pin")
	}
	p.file, err = p.retain(h, managedMSIName, false)
	if err != nil {
		return nil, err
	}
	if err = p.Verify(ctx, r); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *nativeManagedMSI) Verify(ctx context.Context, r ManagedMSIReceipt) error {
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

// The MSI API requires a name, so resolve it from the pinned file with a volume
// GUID rather than reopening through a mutable drive-letter mapping. Custody
// remains held throughout the native call. Unsupported native paths fail closed.
func (p *nativeManagedMSI) PinnedPath() string {
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
