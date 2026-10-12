//go:build windows

package windowsusersoftwarelocal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

// TOKEN_INFORMATION_CLASS 29 is not named in this x/sys revision.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
const tokenIsAppContainer = 29

var ErrRevert = errors.New("selected_user_software_identity_revert_failed")

type heldPeer struct {
	token          windows.Token
	service        windows.Handle
	serverProof    *windowsservice.ObservationPeer
	proofContext   context.Context
	pid            uint32
	pipe           windows.Handle
	serviceSID     string
	identification bool
	identity       [32]byte
	peer           Peer
}

func (p *heldPeer) close() {
	if p.token != 0 {
		p.token.Close()
	}
	if p.service != 0 {
		windows.CloseServiceHandle(p.service)
	}
	if p.serverProof != nil {
		p.serverProof.Close()
	}
}
func fixedServiceSID() (string, error) { return windowsservice.LookupServiceSID() }

// Foreign primary tokens are never opened. Own-process primary identity remains
// independently checked before any native read or observation-service authority.
func openOwnPeer(service bool) (*heldPeer, error) {
	p := &heldPeer{pid: uint32(os.Getpid())}
	var e error
	if service {
		if windowsservice.ValidateRuntimeIdentity() != nil {
			return nil, ErrBinding
		}
		p.serviceSID, e = fixedServiceSID()
		if e != nil {
			return nil, ErrBinding
		}
		scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
		if e != nil {
			return nil, ErrBinding
		}
		p.service, e = windows.OpenService(scm, windows.StringToUTF16Ptr(ServiceName), windows.SERVICE_QUERY_STATUS)
		windows.CloseServiceHandle(scm)
		if e != nil {
			return nil, ErrBinding
		}
	}
	p.token, e = windows.OpenCurrentProcessToken()
	if e != nil {
		p.close()
		return nil, ErrBinding
	}
	p.peer, p.identity, e = tokenIdentity(p.token, p.pid, p.serviceSID, false)
	if e != nil {
		p.close()
		return nil, e
	}
	if e = p.checkIdentity(); e != nil {
		p.close()
		return nil, e
	}
	return p, nil
}
func ownNormalPeer() (*heldPeer, error) { return openOwnPeer(false) }
func openServerPeer(ctx context.Context, pid uint32) (*heldPeer, error) {
	proof, e := windowsservice.OpenObservationPeer(ctx, pid)
	if e != nil {
		return nil, ErrBinding
	}
	return &heldPeer{pid: pid, serverProof: proof, proofContext: ctx}, nil
}
func openClientPeer(pipe windows.Handle) (*heldPeer, error) {
	var pid uint32
	if windows.GetNamedPipeClientProcessId(pipe, &pid) != nil || pid == 0 {
		return nil, ErrBinding
	}
	token, e := pipeIdentificationToken(pipe)
	if e != nil {
		return nil, e
	}
	p := &heldPeer{token: token, pid: pid, pipe: pipe, identification: true}
	p.peer, p.identity, e = tokenIdentity(token, pid, "", true)
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
func (p *heldPeer) checkIdentity() error {
	if p.serverProof != nil {
		return p.serverProof.Check(p.proofContext)
	}
	var token windows.Token
	var e error
	if p.identification {
		var pid uint32
		if windows.GetNamedPipeClientProcessId(p.pipe, &pid) != nil || pid != p.pid {
			return ErrBinding
		}
		token, e = pipeIdentificationToken(p.pipe)
	} else {
		token, e = windows.OpenCurrentProcessToken()
	}
	if e != nil {
		return e
	}
	defer token.Close()
	identity, digest, e := tokenIdentity(token, p.pid, p.serviceSID, p.identification)
	if e != nil || digest != p.identity || identity != p.peer {
		return ErrBinding
	}
	if p.identification {
		session, e := pipeClientSession(p.pipe)
		if e != nil || session != identity.SessionID {
			return ErrBinding
		}
	}
	return nil
}
func (p *heldPeer) check() error {
	if e := p.checkIdentity(); e != nil {
		return e
	}
	if p.service != 0 {
		status, e := p.ownStatus()
		if e != nil || !status.OwnProcess || status.State != serviceRunning || status.PID != p.pid {
			return ErrBinding
		}
	}
	return nil
}
func (p *heldPeer) ownStatus() (ownServiceStatus, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var n uint32
	e := windows.QueryServiceStatusEx(p.service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &n)
	if e != nil {
		return ownServiceStatus{}, ErrBinding
	}
	return ownServiceStatus{OwnProcess: status.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS, State: status.CurrentState, PID: status.ProcessId}, nil
}

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// Only this tiny identity acquisition block enters the pipe security context.
// The dedicated OS thread is never returned to Go if verified revert fails.
// TOKEN_QUERY is held only after reverting; no handler, state, source, file or
// registry read occurs with a client security context on the thread.
func pipeIdentificationToken(pipe windows.Handle) (windows.Token, error) {
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
		if !noThreadImpersonation() {
			done <- result{err: ErrRevert}
			return
		}
		clean = true
		if impersonatePipe.Find() != nil {
			done <- result{err: ErrBinding}
			return
		}
		ok, _, _ := impersonatePipe.Call(uintptr(pipe))
		if ok == 0 {
			done <- result{err: ErrBinding}
			return
		}
		clean = false
		var token windows.Token
		openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		revertErr := windows.RevertToSelf()
		if revertErr != nil || !noThreadImpersonation() {
			if token != 0 {
				token.Close()
			}
			done <- result{err: ErrRevert}
			return
		}
		clean = true
		if openErr != nil {
			done <- result{err: ErrBinding}
			return
		}
		typ, e := tokenNumber(token, windows.TokenType)
		level, le := tokenNumber(token, windows.TokenImpersonationLevel)
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
func tokenInfo(t windows.Token, kind uint32, cap int) ([]byte, error) {
	b := make([]byte, cap)
	var n uint32
	e := windows.GetTokenInformation(t, kind, &b[0], uint32(len(b)), &n)
	if e != nil || n == 0 || n > uint32(len(b)) {
		return nil, ErrBinding
	}
	return b[:n], nil
}
func tokenNumber(t windows.Token, kind uint32) (uint32, error) {
	b, e := tokenInfo(t, kind, 4)
	if e != nil || len(b) != 4 {
		return 0, ErrBinding
	}
	return binary.LittleEndian.Uint32(b), nil
}
func boundedSID(b []byte, s *windows.SID) bool {
	if s == nil || len(b) < 8 {
		return false
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	ptr := uintptr(unsafe.Pointer(s))
	end := base + uintptr(len(b))
	if ptr < base || ptr > end-8 {
		return false
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(s)), 8)
	return ptr+8+uintptr(header[1])*4 <= end && s.IsValid()
}
func tokenIdentity(t windows.Token, pid uint32, serviceSID string, identification bool) (Peer, [32]byte, error) {
	fail := func() (Peer, [32]byte, error) { return Peer{}, [32]byte{}, ErrBinding }
	user, e := tokenInfo(t, windows.TokenUser, 1024)
	if e != nil || len(user) < int(unsafe.Sizeof(windows.Tokenuser{})) {
		return fail()
	}
	u := (*windows.Tokenuser)(unsafe.Pointer(&user[0]))
	if !boundedSID(user, u.User.Sid) {
		return fail()
	}
	sid := u.User.Sid.String()
	session, e := tokenNumber(t, windows.TokenSessionId)
	if e != nil {
		return fail()
	}
	var processSession uint32
	if !identification && (windows.ProcessIdToSessionId(pid, &processSession) != nil || processSession != session) {
		return fail()
	}
	typ, e := tokenNumber(t, windows.TokenType)
	if e != nil || (!identification && typ != windows.TokenPrimary) || (identification && typ != windows.TokenImpersonation) {
		return fail()
	}
	if identification {
		level, e := tokenNumber(t, windows.TokenImpersonationLevel)
		if e != nil || level != windows.SecurityIdentification {
			return fail()
		}
	}
	groups, e := tokenInfo(t, windows.TokenGroups, 65536)
	if e != nil || len(groups) < int(unsafe.Sizeof(windows.Tokengroups{})) {
		return fail()
	}
	g := (*windows.Tokengroups)(unsafe.Pointer(&groups[0]))
	if g.GroupCount > 128 || unsafe.Offsetof(g.Groups)+uintptr(g.GroupCount)*unsafe.Sizeof(windows.SIDAndAttributes{}) > uintptr(len(groups)) {
		return fail()
	}
	fingerprint := bytes.NewBufferString(sid)
	interactive, serviceGroup, expectedService := false, false, false
	for _, group := range g.AllGroups() {
		if !boundedSID(groups, group.Sid) {
			return fail()
		}
		text := group.Sid.String()
		fingerprint.WriteString(text)
		binary.Write(fingerprint, binary.LittleEndian, group.Attributes)
		enabled := group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0
		if enabled && (text == "S-1-5-4" || text == "S-1-5-14") {
			interactive = true
		}
		if enabled && (text == "S-1-5-6" || text == "S-1-5-3") {
			serviceGroup = true
		}
		if identification && enabled && strings.HasPrefix(text, "S-1-15-2-") {
			return fail()
		}
		if serviceSID != "" && strings.HasPrefix(text, "S-1-5-80-") && text != serviceSID && text != "S-1-5-80-0" {
			return fail()
		}
		if text == serviceSID && enabled && group.Attributes&windows.SE_GROUP_OWNER != 0 {
			expectedService = true
		}
	}
	if serviceSID != "" {
		if sid != "S-1-5-19" || session != 0 || !expectedService {
			return fail()
		}
	} else {
		if session == 0 || !interactive || serviceGroup || sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || strings.HasPrefix(sid, "S-1-5-80-") {
			return fail()
		}
		elevated, e := tokenNumber(t, windows.TokenElevation)
		if e != nil || elevated != 0 {
			return fail()
		}
		if !identification {
			appContainer, e := tokenNumber(t, tokenIsAppContainer)
			if e != nil || appContainer != 0 {
				return fail()
			}
		}
		integrity, e := tokenInfo(t, windows.TokenIntegrityLevel, 1024)
		if e != nil || len(integrity) < int(unsafe.Sizeof(windows.Tokenmandatorylabel{})) {
			return fail()
		}
		label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&integrity[0]))
		if !boundedSID(integrity, label.Label.Sid) || label.Label.Sid.SubAuthorityCount() == 0 {
			return fail()
		}
		level := label.Label.Sid.SubAuthority(uint32(label.Label.Sid.SubAuthorityCount() - 1))
		if level < 8192 || level >= 12288 {
			return fail()
		}

	}
	stats, e := tokenInfo(t, windows.TokenStatistics, 128)
	if e != nil || len(stats) != 56 {
		return fail()
	}
	if identification {
		fingerprint.Write(stats[8:16])
	} else {
		fingerprint.Write(stats)
	}
	binary.Write(fingerprint, binary.LittleEndian, session)
	return Peer{SID: sid, ProcessID: pid, SessionID: session}, sha256.Sum256(fingerprint.Bytes()), nil
}

func noThreadImpersonation() bool {
	var token windows.Token
	e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if e == nil {
		token.Close()
		return false
	}
	return errors.Is(e, windows.ERROR_NO_TOKEN)
}

var getPipeClientSession = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientSessionId")

// Unlike ProcessIdToSessionId on a foreign process, this uses the connected
// pipe handle and requires no foreign-process query or token ACL access.
func pipeClientSession(pipe windows.Handle) (uint32, error) {
	if getPipeClientSession.Find() != nil {
		return 0, ErrBinding
	}
	var session uint32
	ok, _, _ := getPipeClientSession.Call(uintptr(pipe), uintptr(unsafe.Pointer(&session)))
	if ok == 0 || session == 0 {
		return 0, ErrBinding
	}
	return session, nil
}
