//go:build windows

package windowsservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

// ObservationPeer trusts the protected SCM service object, its exact public
// configuration, and the held running process's fixed image path. It does NOT
// read/hash the executable: fresh service file ACLs intentionally exclude normal
// users. The service independently checks its own protected image before serving.
// No foreign token, private receipt, file, enrollment state or key is opened.
// Default SCM rights include READ_CONTROL and config/status queries for local
// authenticated users; query-limited process denial still fails closed.
// https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
type ObservationPeer struct {
	process             windows.Handle
	service             *nativeService
	pid                 uint32
	layout              Layout
	configurationSHA256 string
	descriptorSHA256    [32]byte
}

func OpenObservationPeer(ctx context.Context, pid uint32) (*ObservationPeer, error) {
	if ctx == nil || ctx.Err() != nil || pid == 0 {
		return nil, ErrMismatch
	}
	l, e := ResolveLayout()
	if e != nil {
		return nil, e
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return nil, ErrUnsafeIdentity
	}
	p := &ObservationPeer{process: process, pid: pid, layout: l}
	fail := func() (*ObservationPeer, error) { p.Close(); return nil, ErrUnsafeIdentity }
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return fail()
	}
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(Name), windows.READ_CONTROL|windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	windows.CloseServiceHandle(scm)
	if e != nil {
		return fail()
	}
	p.service = &nativeService{handle: h}
	p.descriptorSHA256, e = observationServiceDescriptor(h)
	if e != nil {
		return fail()
	}
	snapshot, e := p.service.Inspect()
	if e != nil || snapshot.State != Running || snapshot.ProcessID != pid {
		return fail()
	}
	p.configurationSHA256 = digestConfig(snapshot.Configuration)
	if e = p.Check(ctx); e != nil {
		return fail()
	}
	return p, nil
}
func (p *ObservationPeer) Check(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.process == 0 || p.service == nil {
		return ErrUnsafeIdentity
	}
	var code uint32
	if windows.GetExitCodeProcess(p.process, &code) != nil || code != 259 {
		return ErrUnsafeIdentity
	}
	var path [512]uint16
	n := uint32(len(path))
	if windows.QueryFullProcessImageName(p.process, 0, &path[0], &n) != nil || n == 0 || n >= uint32(len(path)) || !strings.EqualFold(windows.UTF16ToString(path[:n]), p.layout.Executable) {
		return ErrUnsafeIdentity
	}
	descriptor, e := observationServiceDescriptor(p.service.handle)
	if e != nil || descriptor != p.descriptorSHA256 {
		return ErrUnsafeIdentity
	}
	snapshot, e := p.service.Inspect()
	if e != nil || digestConfig(snapshot.Configuration) != p.configurationSHA256 || observationPublicConfiguration(p.layout, snapshot, p.pid, windows.UTF16ToString(path[:n])) != nil {
		return ErrUnsafeIdentity
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
func (p *ObservationPeer) Close() {
	if p == nil {
		return
	}
	if p.service != nil {
		p.service.Close()
		p.service = nil
	}
	if p.process != 0 {
		windows.CloseHandle(p.process)
		p.process = 0
	}
}

var queryObservationSecurity = windows.NewLazySystemDLL("advapi32.dll").NewProc("QueryServiceObjectSecurity")

// QueryServiceObjectSecurity has a documented maximum 8-KiB descriptor.
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity
func observationServiceDescriptor(h windows.Handle) ([32]byte, error) {
	if queryObservationSecurity.Find() != nil {
		return [32]byte{}, ErrUnsafeIdentity
	}
	var raw [8192]byte
	var n uint32
	ok, _, _ := queryObservationSecurity.Call(uintptr(h), uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		return [32]byte{}, ErrUnsafeIdentity
	}
	// pcbBytesNeeded is documented only on failure; never trust it on success.
	extent, err := observationDescriptorExtent(raw[:])
	if err != nil {
		return [32]byte{}, err
	}
	if e := observationDescriptorBytes(raw[:extent]); e != nil {
		return [32]byte{}, e
	}
	return sha256.Sum256(raw[:extent]), nil
}
func observationDescriptorBytes(raw []byte) error {
	if len(raw) < 20 || len(raw) > 8192 || raw[0] != 1 {
		return ErrUnsafeIdentity
	}
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&0x8004 != 0x8004 {
		return ErrUnsafeIdentity
	}
	ownerOffset := int(binary.LittleEndian.Uint32(raw[4:8]))
	if ownerOffset < 20 {
		return ErrUnsafeIdentity
	}
	owner, e := observationSID(raw, ownerOffset)
	if e != nil {
		return e
	}
	offset := int(binary.LittleEndian.Uint32(raw[16:20]))
	if offset < 20 || offset > len(raw)-8 {
		return ErrUnsafeIdentity
	}
	if raw[offset] != 2 && raw[offset] != 4 {
		return ErrUnsafeIdentity
	}
	size := int(binary.LittleEndian.Uint16(raw[offset+2 : offset+4]))
	count := int(binary.LittleEndian.Uint16(raw[offset+4 : offset+6]))
	if size < 8 || size > len(raw)-offset || count > 1024 {
		return ErrUnsafeIdentity
	}
	end := offset + size
	position := offset + 8
	aces := make([]observationServiceACE, 0, count)
	for i := 0; i < count; i++ {
		if position > end-8 {
			return ErrUnsafeIdentity
		}
		n := int(binary.LittleEndian.Uint16(raw[position+2 : position+4]))
		if n < 16 || n > end-position {
			return ErrUnsafeIdentity
		}
		kind, flags := raw[position], raw[position+1]
		if kind != 0 && kind != 1 {
			return ErrUnsafeIdentity
		}
		sid, e := observationSID(raw[position:position+n], 8)
		if e != nil {
			return e
		}
		aces = append(aces, observationServiceACE{sid, binary.LittleEndian.Uint32(raw[position+4 : position+8]), kind, flags})
		position += n
	}
	return observationServicePolicy(owner, aces)
}
func observationSID(raw []byte, offset int) (string, error) {
	if offset < 0 || offset > len(raw)-8 {
		return "", ErrUnsafeIdentity
	}
	size := 8 + 4*int(raw[offset+1])
	if size > len(raw)-offset {
		return "", ErrUnsafeIdentity
	}
	sid := (*windows.SID)(unsafe.Pointer(&raw[offset]))
	if !sid.IsValid() {
		return "", ErrUnsafeIdentity
	}
	return sid.String(), nil
}
