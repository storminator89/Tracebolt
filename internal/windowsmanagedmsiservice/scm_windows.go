//go:build windows

package windowsmanagedmsiservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"os"
)

func CheckAbsent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return managed.ErrAuthority
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(windowsmanagedmsiipc.ServiceName)
	if e == nil {
		s.Close()
		return managed.ErrConflict
	}
	if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return e
	}
	return ctx.Err()
}
func CreateDisabled(ctx context.Context, c windowsmanagedmsiipc.Config) error {
	if c.Validate() != nil || CheckAbsent(ctx) != nil {
		return managed.ErrAuthority
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.CreateService(windowsmanagedmsiipc.ServiceName, c.Executable, mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartDisabled, ErrorControl: mgr.ErrorNormal, DisplayName: "Tracebolt Windows Deployment", ServiceStartName: "LocalSystem", Description: Marker(c), Dependencies: []string{"TraceboltWindowsAgent"}}, "--run-service")
	if e != nil {
		return e
	}
	defer s.Close()
	// Fixed service-object rights: only SYSTEM/Administrators can modify/control;
	// the exact observer SID receives query/config/status/read-control, no start.
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)(A;;0x20005;;;" + c.ObserverReceipt.ServiceSID + ")")
	if e != nil {
		return e
	}
	if e = setServiceSecurity(s.Handle, sd); e != nil {
		return e
	}
	return checkService(ctx, s, c, mgr.StartDisabled, false)
}
func checkService(ctx context.Context, s *mgr.Service, c windowsmanagedmsiipc.Config, start uint32, running bool) error {
	if ctx == nil || ctx.Err() != nil || c.Validate() != nil {
		return managed.ErrAuthority
	}
	if windowsmanagedmsiipc.CheckServiceDescriptor(s.Handle) != nil {
		return managed.ErrAuthority
	}
	actions, e := s.RecoveryActions()
	if e != nil || len(actions) != 0 {
		return managed.ErrAuthority
	}
	cfg, e := s.Config()
	if e != nil || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || cfg.StartType != start || cfg.ServiceStartName != "LocalSystem" || cfg.BinaryPathName != `"`+c.Executable+`" --run-service` || cfg.Description != Marker(c) || len(cfg.Dependencies) != 1 || cfg.Dependencies[0] != "TraceboltWindowsAgent" || cfg.DelayedAutoStart {
		return managed.ErrAuthority
	}
	status, e := s.Query()
	if e != nil {
		return e
	}
	if running && (status.State != svc.Running && status.State != svc.StartPending || status.ProcessId != uint32(os.Getpid())) {
		return managed.ErrAuthority
	}
	return ctx.Err()
}
func CheckInstalled(ctx context.Context, c windowsmanagedmsiipc.Config, active bool) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(windowsmanagedmsiipc.ServiceName)
	if e != nil {
		return e
	}
	defer s.Close()
	start := uint32(mgr.StartDisabled)
	if active {
		start = mgr.StartAutomatic
	}
	return checkService(ctx, s, c, start, active)
}

// Activate is a separately approved one-time service action, after complete
// setup and manager registration. Failed/uncertain calls are never retried.
func Activate(ctx context.Context, c windowsmanagedmsiipc.Config) error {
	if CheckInstalled(ctx, c, false) != nil || CheckExclusive(ctx) != nil {
		return managed.ErrAuthority
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(windowsmanagedmsiipc.ServiceName)
	if e != nil {
		return e
	}
	defer s.Close()
	cfg, e := s.Config()
	if e != nil {
		return e
	}
	cfg.StartType = mgr.StartAutomatic
	if e = s.UpdateConfig(cfg); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.Start()
}

func setServiceSecurity(h windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return managed.ErrAuthority
	}
	return windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
}
