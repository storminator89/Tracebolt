//go:build windows

package windowsservice

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsBackend struct{}

func nativeBackend() backend { return windowsBackend{} }
func ResolveLayout() (Layout, error) {
	// KF_FLAG_DONT_VERIFY avoids creating or redirecting folders during planning.
	const dontVerify = windows.KF_FLAG_DONT_VERIFY
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, dontVerify)
	if err != nil {
		return Layout{}, setupStageError("service_layout_program_files", "failed", err)
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, dontVerify)
	if err != nil {
		return Layout{}, setupStageError("service_layout_program_data", "failed", err)
	}
	return layoutFromRoots(pf, pd)
}
func (windowsBackend) Layout() (Layout, error) { return ResolveLayout() }
func LookupServiceSID() (string, error) {
	sid, _, _, err := windows.LookupSID("", ServiceAccount)
	if err != nil {
		return "", setupStageError("service_sid_lookup", "failed", err)
	}
	if !sid.IsValid() || !validServiceSID(sid.String()) {
		return "", setupStageError("service_sid_validate", "invalid", ErrUnsafeIdentity)
	}
	return sid.String(), nil
}
func (windowsBackend) LookupSID() (string, error)                { return LookupServiceSID() }
func (windowsBackend) VerifyExecutable(l Layout) (string, error) { return verifyExecutable(l) }

type nativeService struct{ handle windows.Handle }

func (s *nativeService) Close() error               { return windows.CloseServiceHandle(s.handle) }
func openSCM(rights uint32) (windows.Handle, error) { return windows.OpenSCManager(nil, nil, rights) }
func (windowsBackend) Open(a access) (service, error) {
	rights := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	switch a {
	case readAccess:
	case startAccess:
		rights |= windows.SERVICE_START
	case stopAccess:
		rights |= windows.SERVICE_STOP
	case deleteAccess:
		rights |= windows.DELETE
	case configureAccess:
		rights |= windows.SERVICE_CHANGE_CONFIG
	default:
		return nil, setupStageError("service_open_access", "invalid", ErrMismatch)
	}
	scm, err := openSCM(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, setupStageError("service_open_scm", "failed", err)
	}
	defer windows.CloseServiceHandle(scm)
	name := windows.StringToUTF16Ptr(Name)
	h, err := windows.OpenService(scm, name, rights)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, setupStageError("service_open_service", "missing", ErrNotInstalled)
	}
	if err != nil {
		return nil, setupStageError("service_open_service", "failed", err)
	}
	return &nativeService{h}, nil
}
func (windowsBackend) Create(c Configuration) (service, error) {
	if c.StartType != windows.SERVICE_AUTO_START && c.StartType != windows.SERVICE_DISABLED {
		return nil, setupStageError("service_create_start_type", "invalid", ErrMismatch)
	}
	scm, err := openSCM(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return nil, setupStageError("service_create_scm", "failed", err)
	}
	defer windows.CloseServiceHandle(scm)
	// Create disabled. No startup is possible until all limiting configuration has
	// succeeded. Failures retain the created object and never invoke DeleteService.
	h, err := windows.CreateService(scm, windows.StringToUTF16Ptr(Name), windows.StringToUTF16Ptr(c.DisplayName), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_CHANGE_CONFIG, c.ServiceType, windows.SERVICE_DISABLED, c.ErrorControl, windows.StringToUTF16Ptr(c.BinaryPath), nil, nil, nil, windows.StringToUTF16Ptr(Account), nil)
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_DUPLICATE_SERVICE_NAME) {
		return nil, setupStageError("service_create_service", "existing", ErrExisting)
	}
	if err != nil {
		return nil, setupStageError("service_create_service", "failed", err)
	}
	s := &nativeService{h}
	desc := windows.SERVICE_DESCRIPTION{Description: windows.StringToUTF16Ptr(c.Description)}
	if err = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&desc))); err != nil {
		return s, setupStageError("service_create_description", "failed", err)
	}
	sidType := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED)
	if err = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType))); err != nil {
		return s, setupStageError("service_create_sid", "failed", err)
	}
	privileges := append(windows.StringToUTF16(RequiredPrivilege), 0)
	required := struct{ Privileges *uint16 }{&privileges[0]}
	err = windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&required)))
	runtime.KeepAlive(privileges)
	if err != nil {
		return s, setupStageError("service_create_privileges", "failed", err)
	}
	if c.StartType == windows.SERVICE_AUTO_START {
		if err = windows.ChangeServiceConfig(h, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil); err != nil {
			return s, setupStageError("service_create_automatic", "failed", err)
		}
	}
	return s, nil
}
func (s *nativeService) SetAutomatic() error {
	return windows.ChangeServiceConfig(s.handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil)
}
func (s *nativeService) Start() error { return windows.StartService(s.handle, 0, nil) }
func (s *nativeService) Stop() error {
	var status windows.SERVICE_STATUS
	return windows.ControlService(s.handle, windows.SERVICE_CONTROL_STOP, &status)
}
func (s *nativeService) Delete() error { return windows.DeleteService(s.handle) }
func (s *nativeService) Inspect() (Snapshot, error) {
	c, err := (&mgr.Service{Name: Name, Handle: s.handle}).Config()
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_configuration", "failed", err)
	}
	required, err := queryConfig2(s.handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_privileges", "failed", err)
	}
	privileges, err := parseRequiredPrivileges(required)
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_privilege_parse", "invalid", err)
	}
	failure, err := queryConfig2(s.handle, windows.SERVICE_CONFIG_FAILURE_ACTIONS)
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_failure_actions", "failed", err)
	}
	if len(failure) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
		return Snapshot{}, setupStageError("service_snapshot_failure_size", "invalid", ErrMismatch)
	}
	f := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&failure[0]))
	hasFailure := f.ActionsCount != 0 || (f.RebootMsg != nil && *f.RebootMsg != 0) || (f.Command != nil && *f.Command != 0)
	triggers, err := queryConfig2(s.handle, windows.SERVICE_CONFIG_TRIGGER_INFO)
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_triggers", "failed", err)
	}
	if len(triggers) < 4 {
		return Snapshot{}, setupStageError("service_snapshot_trigger_size", "invalid", ErrMismatch)
	}
	hasTriggers := *(*uint32)(unsafe.Pointer(&triggers[0])) != 0
	var st windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err = windows.QueryServiceStatusEx(s.handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &needed); err != nil {
		return Snapshot{}, setupStageError("service_snapshot_status", "failed", err)
	}
	sid, err := LookupServiceSID()
	if err != nil {
		return Snapshot{}, setupStageError("service_snapshot_sid", "failed", err)
	}
	deps := append([]string{}, c.Dependencies...)
	result := Snapshot{Exists: true, State: State(st.CurrentState), ServiceSID: sid, ProcessID: st.ProcessId, Win32ExitCode: st.Win32ExitCode, ServiceSpecificExitCode: st.ServiceSpecificExitCode, Configuration: Configuration{Name: Name, DisplayName: c.DisplayName, BinaryPath: c.BinaryPathName, Account: c.ServiceStartName, ServiceType: c.ServiceType, StartType: c.StartType, ErrorControl: c.ErrorControl, SIDType: c.SidType, RequiredPrivileges: privileges, Dependencies: deps, LoadOrderGroup: c.LoadOrderGroup, DelayedAutoStart: c.DelayedAutoStart, FailureActions: hasFailure, Triggers: hasTriggers, Description: c.Description}}
	runtime.KeepAlive(failure)
	runtime.KeepAlive(triggers)
	runtime.KeepAlive(required)
	return result, nil
}
func queryConfig2(h windows.Handle, kind uint32) ([]byte, error) {
	var needed uint32
	err := windows.QueryServiceConfig2(h, kind, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		if err == nil {
			return nil, setupQueryError(kind, "probe_invalid", ErrMismatch)
		}
		return nil, setupQueryError(kind, "probe_failed", err)
	}
	if needed < 4 || needed > 1024*1024 {
		return nil, setupQueryError(kind, "size_invalid", ErrMismatch)
	}
	b := make([]byte, needed)
	if err = windows.QueryServiceConfig2(h, kind, &b[0], uint32(len(b)), &needed); err != nil {
		return nil, setupQueryError(kind, "read_failed", err)
	}
	if needed > uint32(len(b)) {
		return nil, setupQueryError(kind, "result_invalid", ErrMismatch)
	}
	return b, nil
}

// The SCM gives a pointer into this buffer. Validate its range before decoding;
// fixtures exercise null, out-of-range, odd and missing-terminator cases.
func parseRequiredPrivileges(b []byte) ([]string, error) {
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	if len(b) < ptrSize {
		return nil, ErrMismatch
	}
	p := *(*uintptr)(unsafe.Pointer(&b[0]))
	if p == 0 {
		return []string{}, nil
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	if p < base+uintptr(ptrSize) || p >= base+uintptr(len(b)) || (p-base)%2 != 0 {
		return nil, ErrMismatch
	}
	data := b[int(p-base):]
	out := []string{}
	start := 0
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] != 0 || data[i+1] != 0 {
			continue
		}
		if i == start {
			return out, nil
		}
		units := make([]uint16, (i-start)/2)
		for j := range units {
			units[j] = uint16(data[start+j*2]) | uint16(data[start+j*2+1])<<8
		}
		out = append(out, windows.UTF16ToString(units))
		start = i + 2
	}
	return nil, ErrMismatch
}

// setupQueryError identifies the existing query and substep without retaining
// the native kind or result code in public metadata.
func setupQueryError(kind uint32, category string, err error) error {
	switch kind {
	case windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO:
		return setupStageError("service_query_privileges", category, err)
	case windows.SERVICE_CONFIG_FAILURE_ACTIONS:
		return setupStageError("service_query_failure_actions", category, err)
	case windows.SERVICE_CONFIG_TRIGGER_INFO:
		return setupStageError("service_query_triggers", category, err)
	default:
		return setupStageError("unknown", "unknown", err)
	}
}
