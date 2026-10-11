//go:build windows

package windowsaction

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A held process handle, current own-process SCM PID and exact token identity
// distinguish the broker virtual account from the observation service SID and
// same-token collection children. Query access denial always fails closed.
type peer struct {
	process, service windows.Handle
	pid              uint32
	name, sid        string
	own              bool
}

func (p *peer) close() { windows.CloseHandle(p.process); windows.CloseServiceHandle(p.service) }
func (p *peer) check() error {
	signaled, e := windows.WaitForSingleObject(p.process, 0)
	if e != nil || signaled != uint32(windows.WAIT_TIMEOUT) {
		return ErrBinding
	}
	st, e := serviceStatus(p.service)
	if e != nil || st.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || (st.CurrentState == windows.SERVICE_RUNNING && st.ProcessId != p.pid) || st.CurrentState != windows.SERVICE_RUNNING && !(p.own && st.CurrentState == windows.SERVICE_START_PENDING) {
		return ErrBinding
	}
	return nil
}
func openPeer(pid uint32, name, sid string, own bool) (*peer, error) {
	if pid == 0 || name != BrokerName && name != AgentName || !validSID(sid) || own && (name != BrokerName || pid != uint32(os.Getpid())) {
		return nil, ErrBinding
	}
	processAccess := uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE)
	tokenAccess := uint32(windows.TOKEN_QUERY)
	if own {
		processAccess |= windows.READ_CONTROL
		tokenAccess |= windows.READ_CONTROL
	}
	process, e := windows.OpenProcess(processAccess, false, pid)
	if e != nil {
		return nil, ErrBinding
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrBinding
	}
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL)
	windows.CloseServiceHandle(scm)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrBinding
	}
	p := &peer{process, h, pid, name, sid, own}
	fail := func() (*peer, error) { p.close(); return nil, ErrBinding }
	var token windows.Token
	if windows.OpenProcessToken(process, tokenAccess, &token) != nil {
		return fail()
	}
	defer token.Close()
	expectedUser := "S-1-5-19"
	if name == BrokerName {
		expectedUser = sid
	}
	user, e := token.GetTokenUser()
	if e != nil || user.User.Sid == nil || user.User.Sid.String() != expectedUser {
		return fail()
	}
	groups, e := token.GetTokenGroups()
	if e != nil || len(groups.AllGroups()) > 128 {
		return fail()
	}
	tokenGroups := make([]tokenGroup, 0, len(groups.AllGroups()))
	found := false
	for _, g := range groups.AllGroups() {
		if g.Sid == nil || !g.Sid.IsValid() {
			return fail()
		}
		s := g.Sid.String()
		tokenGroups = append(tokenGroups, tokenGroup{s, g.Attributes})
		if strings.HasPrefix(s, "S-1-5-80-") && s != sid && s != "S-1-5-80-0" {
			return fail()
		}
		if s == sid {
			if found || g.Attributes&windows.SE_GROUP_ENABLED == 0 || g.Attributes&windows.SE_GROUP_OWNER == 0 || g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
				return fail()
			}
			found = true
		}
	}
	if !found && name != BrokerName {
		return fail()
	}
	var needed uint32
	e = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || needed < 4 || needed > 65536 {
		return fail()
	}
	raw := make([]byte, needed)
	if windows.GetTokenInformation(token, windows.TokenPrivileges, &raw[0], uint32(len(raw)), &needed) != nil || needed > uint32(len(raw)) {
		return fail()
	}
	priv := (*windows.Tokenprivileges)(unsafe.Pointer(&raw[0]))
	if unsafe.Offsetof(priv.Privileges)+uintptr(priv.PrivilegeCount)*unsafe.Sizeof(windows.LUIDAndAttributes{}) > uintptr(len(raw)) {
		return fail()
	}
	var changeNotify windows.LUID
	if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &changeNotify) != nil {
		return fail()
	}
	for _, x := range priv.AllPrivileges() {
		if x.Luid != changeNotify {
			return fail()
		}
	}
	if name == BrokerName {
		logon, e := brokerLogonSID(user.User.Sid.String(), sid, tokenGroups)
		if e != nil {
			return fail()
		}
		// Full independent-object admission is the broker's own pre-authority
		// guard. The client proves fixed SCM PID/token identity, without opening
		// broker threads or widening generic future-object DACL permissions.
		if own && validateBrokerKernelObjects(process, token, pid, sid, logon) != nil {
			return fail()
		}
		agentSID, e := serviceSID(AgentName)
		if e != nil || brokerServiceACL(h, sid, agentSID) != nil {
			return fail()
		}
		// Restricted token membership is independently checked; a SID present only
		// in the ordinary enabled groups is not sufficient for the broker.
		restricted, e := token.IsRestricted()
		if e != nil || !restricted {
			return fail()
		}
		needed = 0
		e = windows.GetTokenInformation(token, windows.TokenRestrictedSids, nil, 0, &needed)
		if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || needed < 8 || needed > 65536 {
			return fail()
		}
		raw = make([]byte, needed)
		if windows.GetTokenInformation(token, windows.TokenRestrictedSids, &raw[0], uint32(len(raw)), &needed) != nil || needed > uint32(len(raw)) {
			return fail()
		}
		r := (*windows.Tokengroups)(unsafe.Pointer(&raw[0]))
		if unsafe.Offsetof(r.Groups)+uintptr(r.GroupCount)*unsafe.Sizeof(windows.SIDAndAttributes{}) > uintptr(len(raw)) {
			return fail()
		}
		found = false
		for _, g := range r.AllGroups() {
			addr := uintptr(unsafe.Pointer(g.Sid))
			base := uintptr(unsafe.Pointer(&raw[0]))
			if addr < base || addr+8 > base+uintptr(len(raw)) {
				return fail()
			}
			header := unsafe.Slice((*byte)(unsafe.Pointer(g.Sid)), 8)
			if addr+8+4*uintptr(header[1]) > base+uintptr(len(raw)) || !g.Sid.IsValid() {
				return fail()
			}
			if g.Sid.String() == sid {
				found = true
			}
		}
		if !found {
			return fail()
		}
		exe, e := brokerExecutable()
		if e != nil {
			return fail()
		}
		if _, e = configurationDigest(h, exe, BrokerAccount); e != nil {
			return fail()
		}
		info, e := config2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
		if e != nil || *(*uint32)(unsafe.Pointer(&info[0])) != windows.SERVICE_SID_TYPE_RESTRICTED {
			return fail()
		}
		var image [512]uint16
		n := uint32(len(image))
		if windows.QueryFullProcessImageName(process, 0, &image[0], &n) != nil || n == 0 || n >= uint32(len(image)) || windows.UTF16ToString(image[:n]) != exe {
			return fail()
		}
	}
	if e = p.check(); e != nil {
		return fail()
	}
	return p, nil
}
func verifyBrokerProcess(policy Policy) error {
	sid, e := serviceSID(BrokerName)
	if e != nil || sid != policy.BrokerSID {
		return ErrBinding
	}
	agent, e := serviceSID(AgentName)
	if e != nil || agent != policy.AgentSID {
		return ErrBinding
	}
	p, e := openPeer(uint32(os.Getpid()), BrokerName, sid, true)
	if e != nil {
		return e
	}
	defer p.close()
	return p.check()
}
