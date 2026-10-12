//go:build windows

package windowsupdateipc

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"localrmm/internal/windowsservice"
	"os"
)

func checkUpdateServiceSCM(pid uint32, path string) error {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return ErrPeer
	}
	defer windows.CloseServiceHandle(scm)
	handle, e := windows.OpenService(scm, windows.StringToUTF16Ptr(ServiceName), windows.READ_CONTROL|windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return ErrPeer
	}
	s := &mgr.Service{Name: ServiceName, Handle: handle}
	defer s.Close()
	if CheckServiceDescriptor(handle) != nil {
		return ErrPeer
	}
	c, e := s.Config()
	if e != nil || c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || c.ServiceStartName != "LocalSystem" || c.BinaryPathName != `"`+path+`" --run-service` {
		return ErrPeer
	}
	status, e := s.Query()
	if e != nil || status.ProcessId != pid || (status.State != svc.Running && (pid != uint32(os.Getpid()) || status.State != svc.StartPending)) {
		return ErrPeer
	}
	return nil
}
func CheckServiceDescriptor(h windows.Handle) error {
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrPeer
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return ErrPeer
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return ErrPeer
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrPeer
	}
	seen := map[string]bool{}
	e = eachACE(sd, func(s string, mask uint32, kind, flags byte) error {
		if kind != windows.ACCESS_ALLOWED_ACE_TYPE || flags != 0 || seen[s] {
			return ErrPeer
		}
		seen[s] = true
		if s == sid {
			if mask != 0x20005 {
				return ErrPeer
			}
		} else if s == "S-1-5-18" || s == "S-1-5-32-544" {
			if mask != 0x1f01ff && mask != windows.SERVICE_ALL_ACCESS {
				return ErrPeer
			}
		} else {
			return ErrPeer
		}
		return nil
	})
	if e != nil || !seen[sid] || !seen["S-1-5-18"] || !seen["S-1-5-32-544"] {
		return ErrPeer
	}
	return nil
}
