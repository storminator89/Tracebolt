//go:build windows

package windowssoftwareipc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowsservice"
	"runtime"
	"unsafe"
)

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
		return nil, ErrPeer
	}
	fixedSID, e := windowsservice.LookupServiceSID()
	if e != nil || sid != fixedSID {
		return nil, ErrPeer
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(pipe, &pid) != nil || pid == 0 {
		return nil, ErrPeer
	}
	// The shared public proof deliberately needs query-only access. This
	// additional held handle requires only query-limited plus synchronize,
	// rejecting a terminated process even if its exit code was STILL_ACTIVE.
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return nil, ErrPeer
	}
	proof, e := windowsservice.OpenObservationPeer(ctx, pid)
	if e != nil {
		windows.CloseHandle(process)
		return nil, ErrPeer
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
		return ErrPeer
	}
	identity, e := observerPipeIdentity(p.pipe, p.sid)
	if e != nil {
		p.failedRevert = errors.Is(e, errPeerRevert)
		return e
	}
	if identity != p.identity {
		return ErrPeer
	}
	if !livePeerProcess(p.process) {
		return ErrPeer
	}
	return p.proof.Check(p.ctx)
}
func livePeerProcess(process windows.Handle) bool {
	status, e := windows.WaitForSingleObject(process, 0)
	return e == nil && status == uint32(windows.WAIT_TIMEOUT)
}

var errPeerRevert = errors.New("windows_software_identity_revert_failed")
var impersonateUpdatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// Called only after a bounded request-frame read, because the API identifies
// the security context of the last read. This isolated, pinned thread does only
// TOKEN_QUERY acquisition and immediate verified RevertToSelf. No handler, SCM,
// file, authority, state or native service control runs in the client context.
// A failed revert strands the OS thread and stops Serve; it never rejoins Go's
// thread pool. The returned token has identification level and query access only.
// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
func updatePipeIdentificationToken(pipe windows.Handle) (windows.Token, error) {
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
		if !noUpdateThreadImpersonation() {
			done <- result{err: errPeerRevert}
			return
		}
		clean = true
		if impersonateUpdatePipe.Find() != nil {
			done <- result{err: ErrPeer}
			return
		}
		ok, _, _ := impersonateUpdatePipe.Call(uintptr(pipe))
		if ok == 0 {
			done <- result{err: ErrPeer}
			return
		}
		clean = false
		var token windows.Token
		openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		revertErr := windows.RevertToSelf()
		if revertErr != nil || !noUpdateThreadImpersonation() {
			if token != 0 {
				token.Close()
			}
			done <- result{err: errPeerRevert}
			return
		}
		clean = true
		if openErr != nil {
			done <- result{err: ErrPeer}
			return
		}
		typ, e := peerTokenNumber(token, windows.TokenType)
		level, le := peerTokenNumber(token, windows.TokenImpersonationLevel)
		if e != nil || le != nil || typ != windows.TokenImpersonation || level != windows.SecurityIdentification {
			token.Close()
			done <- result{err: ErrPeer}
			return
		}
		done <- result{token: token}
	}()
	r := <-done
	return r.token, r.err
}
func noUpdateThreadImpersonation() bool {
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
		return nil, ErrPeer
	}
	return b[:n], nil
}
func peerTokenNumber(t windows.Token, kind uint32) (uint32, error) {
	b, e := peerTokenInformation(t, kind, 4)
	if e != nil || len(b) != 4 {
		return 0, ErrPeer
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
	token, e := updatePipeIdentificationToken(pipe)
	if e != nil {
		return [32]byte{}, e
	}
	defer token.Close()
	fail := func() ([32]byte, error) { return [32]byte{}, ErrPeer }
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
