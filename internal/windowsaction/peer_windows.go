//go:build windows

package windowsaction

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
)

// Own-process authority checks and cross-account peer proof are deliberately
// separate. Only this self helper opens a primary token, always through the
// current-process pseudo handle. No foreign token or private peer file is opened.
type ownBrokerPeer struct {
	process, service windows.Handle
	pid              uint32
}

func (p *ownBrokerPeer) close() {
	windows.CloseHandle(p.process)
	windows.CloseServiceHandle(p.service)
}
func (p *ownBrokerPeer) check() error {
	signaled, e := windows.WaitForSingleObject(p.process, 0)
	if e != nil || signaled != uint32(windows.WAIT_TIMEOUT) {
		return ErrBinding
	}
	st, e := serviceStatus(p.service)
	if e != nil || st.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || (st.CurrentState == windows.SERVICE_RUNNING && st.ProcessId != p.pid) || st.CurrentState != windows.SERVICE_RUNNING && st.CurrentState != windows.SERVICE_START_PENDING {
		return ErrBinding
	}
	return nil
}
func openOwnBrokerPeer(sid string) (*ownBrokerPeer, error) {
	pid := uint32(os.Getpid())
	if pid == 0 || !validSID(sid) {
		return nil, ErrBinding
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|windows.READ_CONTROL, false, pid)
	if e != nil {
		return nil, ErrBinding
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrBinding
	}
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(BrokerName), windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL)
	windows.CloseServiceHandle(scm)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrBinding
	}
	p := &ownBrokerPeer{process: process, service: h, pid: pid}
	fail := func() (*ownBrokerPeer, error) { p.close(); return nil, ErrBinding }
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.READ_CONTROL, &token) != nil {
		return fail()
	}
	defer token.Close()
	expectedUser := sid
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
	logon, e := brokerLogonSID(user.User.Sid.String(), sid, tokenGroups)
	if e != nil {
		return fail()
	}
	// Full independent-object admission remains the broker's own pre-authority
	// guard, independent of the public cross-account peer proof.
	if validateBrokerKernelObjects(process, token, pid, sid, logon) != nil {
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
	// The protected public marker is checked against our own executable bytes,
	// without requiring the observer to read a private image or foreign token.
	held, file, e := holdExecutable(exe)
	for _, handle := range held {
		defer windows.CloseHandle(handle)
	}
	if e != nil {
		return fail()
	}
	hash, e := hashHandle(file)
	if e != nil {
		return fail()
	}
	marker, e := brokerMarker(h)
	if e != nil || !strings.HasSuffix(marker, "; executable-sha256="+strings.TrimPrefix(hash, "sha256:")) {
		return fail()
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
	p, e := openOwnBrokerPeer(sid)
	if e != nil {
		return e
	}
	defer p.close()
	if policy.Binding.InstallationID != "" {
		marker, e := brokerMarker(p.service)
		if e != nil || !strings.HasPrefix(marker, brokerPublicMarkerPrefix+policy.Binding.InstallationID+"; executable-sha256=") {
			return ErrBinding
		}
	}
	return p.check()
}

// brokerPeer is a public proof of the fixed broker service. The observer cannot
// query its foreign primary token or private installation files. The protected
// SCM object attests the account, restricted service SID configuration, fixed
// command and installation marker; the broker separately verifies its own token
// and protected executable before opening authority. The marker is not a
// client-measured executable hash.
type brokerPeer struct {
	process, service                                 windows.Handle
	pipe                                             windows.Handle
	pid                                              uint32
	sid, agentSID, executable, configuration, marker string
}

func (p *brokerPeer) close() { windows.CloseHandle(p.process); windows.CloseServiceHandle(p.service) }
func openBrokerPeer(pipe windows.Handle, pid uint32, sid string) (*brokerPeer, error) {
	if pid == 0 || !validSID(sid) {
		return nil, ErrBinding
	}
	fixedSID, e := serviceSID(BrokerName)
	if e != nil || fixedSID != sid {
		return nil, ErrBinding
	}
	agentSID, e := serviceSID(AgentName)
	if e != nil {
		return nil, ErrBinding
	}
	exe, e := brokerExecutable()
	if e != nil {
		return nil, ErrBinding
	}
	// Only this object needs the exact observer-SID query-only process ACE.
	// SYNCHRONIZE proves liveness without trusting exit code 259; no
	// READ_CONTROL, memory, token or handle-duplication rights are requested.
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return nil, ErrBinding
	}
	p := &brokerPeer{process: process, pipe: pipe, pid: pid, sid: sid, agentSID: agentSID, executable: exe}
	fail := func() (*brokerPeer, error) { p.close(); return nil, ErrBinding }
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return fail()
	}
	p.service, e = windows.OpenService(scm, windows.StringToUTF16Ptr(BrokerName), windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG|windows.READ_CONTROL)
	windows.CloseServiceHandle(scm)
	if e != nil {
		return fail()
	}
	p.configuration, p.marker, e = brokerPublicConfiguration(p.service, exe)
	if e != nil || p.check() != nil {
		return fail()
	}
	return p, nil
}
func (p *brokerPeer) check() error {
	var pid uint32
	if windows.GetNamedPipeServerProcessId(p.pipe, &pid) != nil || pid != p.pid || !livePeerProcess(p.process) {
		return ErrBinding
	}
	st, e := serviceStatus(p.service)
	if e != nil || st.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId != p.pid || brokerServiceACL(p.service, p.sid, p.agentSID) != nil {
		return ErrBinding
	}
	configuration, marker, e := brokerPublicConfiguration(p.service, p.executable)
	if e != nil || configuration != p.configuration || marker != p.marker {
		return ErrBinding
	}
	var image [512]uint16
	n := uint32(len(image))
	if windows.QueryFullProcessImageName(p.process, 0, &image[0], &n) != nil || n == 0 || n >= uint32(len(image)) || windows.UTF16ToString(image[:n]) != p.executable {
		return ErrBinding
	}
	return nil
}
func brokerPublicConfiguration(service windows.Handle, exe string) (string, string, error) {
	digest, e := configurationDigest(service, exe, BrokerAccount)
	if e != nil {
		return "", "", ErrBinding
	}
	sid, e := config2(service, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
	if e != nil || len(sid) < 4 || binary.LittleEndian.Uint32(sid[:4]) != windows.SERVICE_SID_TYPE_RESTRICTED {
		return "", "", ErrBinding
	}
	description, e := config2(service, windows.SERVICE_CONFIG_DESCRIPTION)
	if e != nil || len(description) < int(unsafe.Sizeof(uintptr(0))) {
		return "", "", ErrBinding
	}
	marker, e := boundedString(description, *(**uint16)(unsafe.Pointer(&description[0])), unsafe.Sizeof(uintptr(0)))
	if e != nil || validBrokerPublicMarker(marker) != nil {
		return "", "", ErrBinding
	}
	runtime.KeepAlive(description)
	return digest, marker, nil
}

// observationPeer combines the pipe's exact identification token with the held
// running observer SCM process, public image/configuration and installation
// marker proof. A LocalService sibling or same-token worker is insufficient.
type observationPeer struct {
	process      windows.Handle
	proof        *windowsservice.ObservationPeer
	ctx          context.Context
	pipe         windows.Handle
	pid          uint32
	sid          string
	identity     [32]byte
	failedRevert bool
}

func (p *observationPeer) close() { p.proof.Close(); windows.CloseHandle(p.process) }
func openObservationPeer(ctx context.Context, pipe windows.Handle, sid string) (*observationPeer, error) {
	if ctx == nil || ctx.Err() != nil || !validSID(sid) {
		return nil, ErrBinding
	}
	fixedSID, e := windowsservice.LookupServiceSID()
	if e != nil || sid != fixedSID {
		return nil, ErrBinding
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(pipe, &pid) != nil || pid == 0 {
		return nil, ErrBinding
	}
	// The shared public proof deliberately needs query-only access. This
	// additional held handle requires only query-limited plus synchronize,
	// rejecting a terminated process even if its exit code was STILL_ACTIVE.
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return nil, ErrBinding
	}
	proof, e := windowsservice.OpenObservationPeer(ctx, pid)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrBinding
	}
	p := &observationPeer{process: process, proof: proof, ctx: ctx, pipe: pipe, pid: pid, sid: sid}
	p.identity, e = observerPipeIdentity(pipe, sid)
	if e != nil {
		p.close()
		return nil, e
	}
	if e = p.check(); e != nil {
		p.close()
		return nil, e
	}
	return p, nil
}
func (p *observationPeer) check() error {
	if p.failedRevert {
		return errPeerRevert
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(p.pipe, &pid) != nil || pid != p.pid || !livePeerProcess(p.process) || p.proof.Check(p.ctx) != nil {
		return ErrBinding
	}
	identity, e := observerPipeIdentity(p.pipe, p.sid)
	if e != nil {
		p.failedRevert = errors.Is(e, errPeerRevert)
		return e
	}
	if identity != p.identity {
		return ErrBinding
	}
	if !livePeerProcess(p.process) {
		return ErrBinding
	}
	return p.proof.Check(p.ctx)
}
func livePeerProcess(process windows.Handle) bool {
	status, e := windows.WaitForSingleObject(process, 0)
	return e == nil && status == uint32(windows.WAIT_TIMEOUT)
}

var errPeerRevert = errors.New("windows_action_identity_revert_failed")
var impersonateActionPipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// Called only after a bounded request-frame read, because the API identifies
// the security context of the last read. This isolated, pinned thread does only
// TOKEN_QUERY acquisition and immediate verified RevertToSelf. No handler, SCM,
// file, authority, state or native service control runs in the client context.
// A failed revert strands the OS thread and stops Serve; it never rejoins Go's
// thread pool. The returned token has identification level and query access only.
// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
func actionPipeIdentificationToken(pipe windows.Handle) (windows.Token, error) {
	type result struct {
		token windows.Token
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		clean := false
		defer func() {
			if clean {
				runtime.UnlockOSThread()
			}
		}()
		if !noActionThreadImpersonation() {
			done <- result{err: errPeerRevert}
			return
		}
		clean = true
		if impersonateActionPipe.Find() != nil {
			done <- result{err: ErrBinding}
			return
		}
		ok, _, _ := impersonateActionPipe.Call(uintptr(pipe))
		if ok == 0 {
			done <- result{err: ErrBinding}
			return
		}
		clean = false
		var token windows.Token
		openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		revertErr := windows.RevertToSelf()
		if revertErr != nil || !noActionThreadImpersonation() {
			if token != 0 {
				token.Close()
			}
			done <- result{err: errPeerRevert}
			return
		}
		clean = true
		if openErr != nil {
			done <- result{err: ErrBinding}
			return
		}
		typ, e := peerTokenNumber(token, windows.TokenType)
		level, le := peerTokenNumber(token, windows.TokenImpersonationLevel)
		if e != nil || le != nil || typ != windows.TokenImpersonation || level != windows.SecurityIdentification {
			token.Close()
			done <- result{err: ErrBinding}
			return
		}
		done <- result{token: token}
	}()
	r := <-done
	return r.token, r.err
}
func noActionThreadImpersonation() bool {
	var token windows.Token
	e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if e == nil {
		token.Close()
		return false
	}
	return errors.Is(e, windows.ERROR_NO_TOKEN)
}
func peerTokenInformation(t windows.Token, kind uint32, capacity int) ([]byte, error) {
	b := make([]byte, capacity)
	var n uint32
	if windows.GetTokenInformation(t, kind, &b[0], uint32(len(b)), &n) != nil || n == 0 || n > uint32(len(b)) {
		return nil, ErrBinding
	}
	return b[:n], nil
}
func peerTokenNumber(t windows.Token, kind uint32) (uint32, error) {
	b, e := peerTokenInformation(t, kind, 4)
	if e != nil || len(b) != 4 {
		return 0, ErrBinding
	}
	return binary.LittleEndian.Uint32(b), nil
}
func boundedPeerSID(b []byte, sid *windows.SID) bool {
	if sid == nil || len(b) < 8 {
		return false
	}
	base, ptr := uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(sid))
	end := base + uintptr(len(b))
	if ptr < base || ptr > end-8 {
		return false
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
	return ptr+8+uintptr(header[1])*4 <= end && sid.IsValid()
}
func observerPipeIdentity(pipe windows.Handle, sid string) ([32]byte, error) {
	token, e := actionPipeIdentificationToken(pipe)
	if e != nil {
		return [32]byte{}, e
	}
	defer token.Close()
	fail := func() ([32]byte, error) { return [32]byte{}, ErrBinding }
	user, e := peerTokenInformation(token, windows.TokenUser, 1024)
	if e != nil || len(user) < int(unsafe.Sizeof(windows.Tokenuser{})) {
		return fail()
	}
	u := (*windows.Tokenuser)(unsafe.Pointer(&user[0]))
	if !boundedPeerSID(user, u.User.Sid) {
		return fail()
	}
	userSID := u.User.Sid.String()
	session, e := peerTokenNumber(token, windows.TokenSessionId)
	if e != nil {
		return fail()
	}
	groups, e := peerTokenInformation(token, windows.TokenGroups, 65536)
	if e != nil || len(groups) < int(unsafe.Sizeof(windows.Tokengroups{})) {
		return fail()
	}
	g := (*windows.Tokengroups)(unsafe.Pointer(&groups[0]))
	if g.GroupCount > 128 || unsafe.Offsetof(g.Groups)+uintptr(g.GroupCount)*unsafe.Sizeof(windows.SIDAndAttributes{}) > uintptr(len(groups)) {
		return fail()
	}
	tokenGroups := make([]tokenGroup, 0, g.GroupCount)
	fingerprint := []byte(userSID)
	fingerprint = binary.LittleEndian.AppendUint32(fingerprint, session)
	for _, group := range g.AllGroups() {
		if !boundedPeerSID(groups, group.Sid) {
			return fail()
		}
		s := group.Sid.String()
		tokenGroups = append(tokenGroups, tokenGroup{s, group.Attributes})
		fingerprint = binary.LittleEndian.AppendUint32(fingerprint, uint32(len(s)))
		fingerprint = append(fingerprint, s...)
		fingerprint = binary.LittleEndian.AppendUint32(fingerprint, group.Attributes)
	}
	if observationTokenPolicy(userSID, sid, session, tokenGroups) != nil {
		return fail()
	}
	privileges, e := peerTokenInformation(token, windows.TokenPrivileges, 65536)
	if e != nil || len(privileges) < 4 {
		return fail()
	}
	priv := (*windows.Tokenprivileges)(unsafe.Pointer(&privileges[0]))
	if priv.PrivilegeCount > 128 || unsafe.Offsetof(priv.Privileges)+uintptr(priv.PrivilegeCount)*unsafe.Sizeof(windows.LUIDAndAttributes{}) > uintptr(len(privileges)) {
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
	fingerprint = append(fingerprint, privileges...)
	stats, e := peerTokenInformation(token, windows.TokenStatistics, 128)
	if e != nil || len(stats) != 56 {
		return fail()
	}
	// AuthenticationId is stable across identification-token acquisitions;
	// TokenId is not. Identity/group/privilege/session fields are bound above.
	fingerprint = append(fingerprint, stats[8:16]...)
	runtime.KeepAlive(user)
	runtime.KeepAlive(groups)
	return sha256.Sum256(fingerprint), nil
}
