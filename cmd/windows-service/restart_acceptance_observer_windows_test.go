//go:build windows && tracebolt_restart_acceptance && !tracebolt_fresh_native && !tracebolt_setup_native

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
)

type restartObserver struct {
	handle  windows.Handle
	receipt windowsservice.Receipt
}
type restartProcess struct {
	handle  windows.Handle
	pid     uint32
	created uint64
	image   string
}

func (p *restartProcess) close() error { return windows.CloseHandle(p.handle) }
func (p *restartProcess) generation() string {
	return restartHash([]byte(strconv.FormatUint(uint64(p.pid), 10) + ":" + strconv.FormatUint(p.created, 10)))
}
func (o *restartObserver) close() error { return windows.CloseServiceHandle(o.handle) }
func restartOpenObserver(r windowsservice.Receipt) (*restartObserver, error) {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, restartAcceptanceRejected
	}
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(windowsservice.Name), restartObserverRights)
	closed := windows.CloseServiceHandle(scm)
	if e != nil || closed != nil {
		if h != 0 {
			windows.CloseServiceHandle(h)
		}
		return nil, restartAcceptanceRejected
	}
	o := &restartObserver{handle: h, receipt: r}
	if _, e = o.snapshot(); e != nil {
		o.close()
		return nil, restartAcceptanceRejected
	}
	return o, nil
}
func (o *restartObserver) snapshot() (uint32, error) {
	c, e := restartQueryConfiguration(o.handle)
	if e != nil {
		return 0, restartAcceptanceRejected
	}
	raw, e := json.Marshal(c)
	if e != nil || restartHash(raw) != o.receipt.ConfigurationSHA256 {
		return 0, restartAcceptanceRejected
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil || sid != o.receipt.ServiceSID {
		return 0, restartAcceptanceRejected
	}
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if windows.QueryServiceStatusEx(o.handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) != nil || status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 || status.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
		return 0, restartAcceptanceRejected
	}
	return status.ProcessId, nil
}
func (o *restartObserver) process() (*restartProcess, error) {
	pid, e := o.snapshot()
	if e != nil {
		return nil, restartAcceptanceRejected
	}
	h, e := windows.OpenProcess(restartProcessRights, false, pid)
	if e != nil {
		return nil, restartAcceptanceRejected
	}
	p := &restartProcess{handle: h, pid: pid}
	good := false
	defer func() {
		if !good {
			p.close()
		}
	}()
	var create, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &create, &exit, &kernel, &user) != nil {
		return nil, restartAcceptanceRejected
	}
	p.created = uint64(create.HighDateTime)<<32 | uint64(create.LowDateTime)
	var image [512]uint16
	n := uint32(len(image))
	if windows.QueryFullProcessImageName(h, 0, &image[0], &n) != nil || n == 0 || n >= uint32(len(image)) {
		return nil, restartAcceptanceRejected
	}
	p.image = windows.UTF16ToString(image[:n])
	if p.image != o.receipt.Layout.Executable || p.created == 0 || !restartValidateHeldToken(h, o.receipt.ServiceSID) || !o.same(p) {
		return nil, restartAcceptanceRejected
	}
	good = true
	return p, nil
}
func (o *restartObserver) same(p *restartProcess) bool {
	// A running SCM PID is bracketed by the still-held process object. A reused
	// integer PID cannot replace this object's creation time or nonsignaled state.
	before, e := windows.WaitForSingleObject(p.handle, 0)
	if e != nil || before != uint32(windows.WAIT_TIMEOUT) {
		return false
	}
	pid, e := o.snapshot()
	if e != nil || pid != p.pid {
		return false
	}
	var create, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(p.handle, &create, &exit, &kernel, &user) != nil || !restartSameGeneration(restartGeneration{p.pid, p.created}, restartGeneration{pid, uint64(create.HighDateTime)<<32 | uint64(create.LowDateTime)}) {
		return false
	}
	var image [512]uint16
	n := uint32(len(image))
	if windows.QueryFullProcessImageName(p.handle, 0, &image[0], &n) != nil || n == 0 || n >= uint32(len(image)) || windows.UTF16ToString(image[:n]) != p.image || !restartValidateHeldToken(p.handle, o.receipt.ServiceSID) {
		return false
	}
	again, e := o.snapshot()
	if e != nil || again != p.pid {
		return false
	}
	after, e := windows.WaitForSingleObject(p.handle, 0)
	return e == nil && after == uint32(windows.WAIT_TIMEOUT)
}

// SCM pointers are accepted only inside the same bounded native query buffer.
// No production control handle or configuration mutation API is reachable here.
func restartWide(b []byte, p *uint16, multi bool) ([]string, error) {
	if p == nil {
		if multi {
			return []string{}, nil
		}
		return []string{""}, nil
	}
	base, ptr := uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(p))
	if ptr < base || ptr-base >= uintptr(len(b)) || (ptr-base)%2 != 0 {
		return nil, restartAcceptanceRejected
	}
	tail := b[ptr-base:]
	out := []string{}
	start := 0
	for i := 0; i+1 < len(tail); i += 2 {
		if tail[i] != 0 || tail[i+1] != 0 {
			continue
		}
		units := make([]uint16, (i-start)/2)
		for j := range units {
			units[j] = binary.LittleEndian.Uint16(tail[start+j*2:])
		}
		s := windows.UTF16ToString(units)
		if !multi {
			return []string{s}, nil
		}
		if s == "" {
			return out, nil
		}
		out = append(out, s)
		if len(out) > 32 {
			return nil, restartAcceptanceRejected
		}
		start = i + 2
	}
	runtime.KeepAlive(b)
	return nil, restartAcceptanceRejected
}
func restartConfig2(h windows.Handle, kind uint32) ([]byte, error) {
	var n uint32
	e := windows.QueryServiceConfig2(h, kind, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < 4 || n > 64<<10 {
		return nil, restartAcceptanceRejected
	}
	b := make([]byte, n)
	if windows.QueryServiceConfig2(h, kind, &b[0], uint32(len(b)), &n) != nil || n > uint32(len(b)) {
		return nil, restartAcceptanceRejected
	}
	return b, nil
}
func restartQueryConfiguration(h windows.Handle) (windowsservice.Configuration, error) {
	fail := func() (windowsservice.Configuration, error) {
		return windowsservice.Configuration{}, restartAcceptanceRejected
	}
	var n uint32
	e := windows.QueryServiceConfig(h, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || n > 64<<10 {
		return fail()
	}
	b := make([]byte, n)
	q := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
	if windows.QueryServiceConfig(h, q, uint32(len(b)), &n) != nil || n > uint32(len(b)) {
		return fail()
	}
	binaryPath, e := restartWide(b, q.BinaryPathName, false)
	if e != nil {
		return fail()
	}
	account, e := restartWide(b, q.ServiceStartName, false)
	if e != nil {
		return fail()
	}
	display, e := restartWide(b, q.DisplayName, false)
	if e != nil {
		return fail()
	}
	group, e := restartWide(b, q.LoadOrderGroup, false)
	if e != nil {
		return fail()
	}
	dependencies, e := restartWide(b, q.Dependencies, true)
	if e != nil {
		return fail()
	}
	c := windowsservice.Configuration{Name: windowsservice.Name, DisplayName: display[0], BinaryPath: binaryPath[0], Account: account[0], ServiceType: q.ServiceType, StartType: q.StartType, ErrorControl: q.ErrorControl, Dependencies: dependencies, LoadOrderGroup: group[0]}
	description, e := restartConfig2(h, windows.SERVICE_CONFIG_DESCRIPTION)
	if e != nil || len(description) < int(unsafe.Sizeof(windows.SERVICE_DESCRIPTION{})) {
		return fail()
	}
	desc, e := restartWide(description, (*windows.SERVICE_DESCRIPTION)(unsafe.Pointer(&description[0])).Description, false)
	if e != nil {
		return fail()
	}
	c.Description = desc[0]
	sid, e := restartConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
	if e != nil || len(sid) < 4 {
		return fail()
	}
	c.SIDType = binary.LittleEndian.Uint32(sid)
	delay, e := restartConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
	if e != nil || len(delay) < 4 {
		return fail()
	}
	c.DelayedAutoStart = binary.LittleEndian.Uint32(delay) != 0
	required, e := restartConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if e != nil || len(required) < int(unsafe.Sizeof(uintptr(0))) {
		return fail()
	}
	c.RequiredPrivileges, e = restartWide(required, *(**uint16)(unsafe.Pointer(&required[0])), true)
	if e != nil {
		return fail()
	}
	failure, e := restartConfig2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS)
	if e != nil || len(failure) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
		return fail()
	}
	f := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&failure[0]))
	reboot, e := restartWide(failure, f.RebootMsg, false)
	if e != nil {
		return fail()
	}
	command, e := restartWide(failure, f.Command, false)
	if e != nil {
		return fail()
	}
	c.FailureActions = f.ActionsCount != 0 || reboot[0] != "" || command[0] != ""
	triggers, e := restartConfig2(h, windows.SERVICE_CONFIG_TRIGGER_INFO)
	if e != nil || len(triggers) < 4 {
		return fail()
	}
	c.Triggers = binary.LittleEndian.Uint32(triggers) != 0
	runtime.KeepAlive(b)
	runtime.KeepAlive(description)
	runtime.KeepAlive(required)
	runtime.KeepAlive(failure)
	return c, nil
}
