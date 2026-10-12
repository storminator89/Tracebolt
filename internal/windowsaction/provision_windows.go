//go:build windows

package windowsaction

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

type nativeProvision struct {
	held           []windows.Handle
	imageParents   []windows.Handle
	imageDirectory windows.Handle
	target         windows.Handle
	observer       windows.Handle
	broker         windows.Handle
	targetFile     windows.Handle
	plan           ProvisionPlan
}

func ProvisionPath() (string, error) {
	p, e := AuthorityPath()
	if e != nil {
		return "", e
	}
	return p + "-setup", nil
}
func nativeProvisionSession(ctx context.Context) (provisionSession, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	t, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return nil, ErrBinding
	}
	elevated := t.IsElevated()
	ce := t.Close()
	if !elevated || ce != nil {
		return nil, ErrBinding
	}
	return &nativeProvision{}, nil
}
func (s *nativeProvision) Close() error {
	var e error
	for _, h := range []windows.Handle{s.broker, s.target, s.observer} {
		if h != 0 {
			e = errors.Join(e, windows.CloseServiceHandle(h))
		}
	}
	s.broker = 0
	s.target = 0
	s.observer = 0
	for i := len(s.held) - 1; i >= 0; i-- {
		e = errors.Join(e, windows.CloseHandle(s.held[i]))
	}
	s.held = nil
	return e
}
func openReadService(name string) (windows.Handle, error) {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return 0, ErrUnavailable
	}
	defer windows.CloseServiceHandle(scm)
	rights := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.READ_CONTROL)
	if name != BrokerName && name != AgentName {
		rights |= windows.SERVICE_ENUMERATE_DEPENDENTS
	}
	return windows.OpenService(scm, windows.StringToUTF16Ptr(name), rights)
}
func missingProvisionChild(parent windows.Handle, name string) error {
	h, e := windowspath.OpenChild(parent, name, false, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ)
	if e == nil {
		windows.CloseHandle(h)
		return ErrProvisionExisting
	}
	if !errors.Is(e, windows.STATUS_OBJECT_NAME_NOT_FOUND) && !errors.Is(e, windows.STATUS_NO_SUCH_FILE) {
		return ErrBinding
	}
	return nil
}
func absentProvisionStore(path string, o windowsstate.Options) error {
	s, e := windowsstate.Open(path, o)
	if e == nil {
		s.Close()
		return ErrProvisionExisting
	}
	if !errors.Is(e, fs.ErrNotExist) {
		return ErrBinding
	}
	return nil
}
func (s *nativeProvision) Plan(ctx context.Context, p Policy, m windowspackage.Manifest, observerDigest string, http bool) (ProvisionPlan, error) {
	if ctx == nil || ctx.Err() != nil || ValidatePolicy(p) != nil || !p.Enabled || len(s.held) != 0 {
		return ProvisionPlan{}, ErrInvalid
	}
	b, a := FixedServiceSIDs()
	if p.BrokerSID != b || p.AgentSID != a {
		return ProvisionPlan{}, ErrBinding
	}
	actual, e := serviceSID(AgentName)
	if e != nil || actual != a {
		return ProvisionPlan{}, ErrBinding
	}
	h, e := openReadService(BrokerName)
	if e == nil {
		windows.CloseServiceHandle(h)
		return ProvisionPlan{}, ErrProvisionExisting
	}
	if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return ProvisionPlan{}, ErrBinding
	}
	root, e := AuthorityPath()
	if e != nil {
		return ProvisionPlan{}, e
	}
	if e = absentProvisionStore(root, AuthorityOptions(b, false)); e != nil {
		return ProvisionPlan{}, e
	}
	setup, e := ProvisionPath()
	if e != nil {
		return ProvisionPlan{}, e
	}
	if e = absentProvisionStore(setup, ProvisionOptions(b, false)); e != nil {
		return ProvisionPlan{}, e
	}
	l, e := windowsservice.ResolveLayout()
	if e != nil {
		return ProvisionPlan{}, e
	}
	held, _, e := holdExecutable(l.Executable)
	s.held = append(s.held, held...)
	if e != nil || len(held) < 3 {
		return ProvisionPlan{}, ErrBinding
	}
	s.imageParents = held[:len(held)-1]
	s.imageDirectory = held[len(held)-2]
	if e = missingProvisionChild(s.imageDirectory, BrokerImageName); e != nil {
		return ProvisionPlan{}, e
	}
	s.observer, e = openReadService(AgentName)
	if e != nil {
		return ProvisionPlan{}, ErrBinding
	}
	st, e := serviceStatus(s.observer)
	if e != nil || st.CurrentState != windows.SERVICE_STOPPED {
		return ProvisionPlan{}, ErrBinding
	}
	s.target, e = openReadService(p.Target.Name)
	if e != nil {
		return ProvisionPlan{}, ErrBinding
	}
	held, s.targetFile, e = holdExecutable(p.Target.Executable)
	s.held = append(s.held, held...)
	if e != nil {
		return ProvisionPlan{}, e
	}
	if e = s.checkTarget(p); e != nil {
		return ProvisionPlan{}, e
	}
	directory, e := provisionACLDelta(s.imageDirectory, windows.SE_FILE_OBJECT, b, 0x1200a9, "directory")
	if e != nil {
		return ProvisionPlan{}, e
	}
	target, e := provisionACLDelta(s.target, windows.SE_SERVICE, b, 0x2003d, "target")
	if e != nil {
		return ProvisionPlan{}, e
	}
	observer, e := provisionACLDelta(s.observer, windows.SE_SERVICE, b, 0x20005, "observer")
	if e != nil {
		return ProvisionPlan{}, e
	}
	exe, e := brokerExecutable()
	if e != nil {
		return ProvisionPlan{}, e
	}
	s.plan = ProvisionPlan{Version: ProvisionVersion, Consent: ProvisionConsent, Policy: p, Artifact: m, ObserverReceiptDigest: observerDigest, Executable: exe, Account: BrokerAccount, Description: provisionDescription(p, m), BrokerServiceSDDL: brokerServiceSDDL(b, a), ImageDirectory: directory, TargetService: target, ObserverService: observer, PeerProcessQueryRights: PeerProcessQueryRights, HTTPAcknowledged: http}
	if ctx.Err() != nil {
		return ProvisionPlan{}, ctx.Err()
	}
	return s.plan, nil
}
func (s *nativeProvision) checkTarget(p Policy) error {
	for _, h := range s.held {
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrBinding
		}
		directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if (!directory && info.NumberOfLinks != 1) || pathACL(h, directory) != nil {
			return ErrBinding
		}
	}
	digest, e := configurationDigest(s.target, p.Target.Executable, `NT AUTHORITY\LocalService`)
	if e != nil || digest != p.Target.ConfigurationDigest {
		return ErrProvisionTargetConfig
	}
	digest, e = hashHandle(s.targetFile)
	if e != nil || digest != p.Target.ExecutableDigest {
		return ErrProvisionTargetImage
	}
	var need, count uint32
	if windows.EnumDependentServices(s.target, windows.SERVICE_ACTIVE, nil, 0, &need, &count) != nil || need != 0 || count != 0 {
		return ErrProvisionTargetDependents
	}
	st, e := serviceStatus(s.target)
	if e != nil || st.CurrentState != windows.SERVICE_STOPPED && st.CurrentState != windows.SERVICE_RUNNING {
		return ErrProvisionTargetState
	}
	return nil
}
func descriptorText(h windows.Handle, kind windows.SE_OBJECT_TYPE) (string, error) {
	sd, e := windows.GetSecurityInfo(h, kind, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() || sd.Length() > 8192 {
		return "", ErrBinding
	}
	return sd.String(), nil
}
func provisionACLDelta(h windows.Handle, kind windows.SE_OBJECT_TYPE, sid string, rights uint32, role string) (ACLDelta, error) {
	before, e := descriptorText(h, kind)
	if e != nil {
		return ACLDelta{}, e
	}
	sd, e := windows.SecurityDescriptorFromString(before)
	if e != nil {
		return ACLDelta{}, ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedWriter(owner.String()) {
		return ACLDelta{}, ErrBinding
	}
	control, _, e := sd.Control()
	if e != nil || role != "observer" && control&windows.SE_DACL_PROTECTED == 0 {
		return ACLDelta{}, ErrBinding
	}
	e = eachACE(sd, func(principal string, mask uint32, k, f byte) error {
		if principal == sid || k != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrBinding
		}
		if role == "target" {
			if f != 0 {
				return ErrBinding
			}
			if !trustedWriter(principal) && mask & ^uint32(0x2008d) != 0 {
				return ErrBinding
			}
		} else if role == "observer" {
			if f != 0 || !trustedWriter(principal) && mask&(0x10000000|0x40000000|0x2|0x10000|0x40000|0x80000) != 0 {
				return ErrBinding
			}
		} else if role == "directory" {
			if f&windows.INHERIT_ONLY_ACE == 0 && !trustedWriter(principal) && mask&untrustedPathWriteMask(true) != 0 {
				return ErrBinding
			}
		} else {
			return ErrInvalid
		}
		return nil
	})
	if e != nil {
		return ACLDelta{}, e
	}
	after, e := windows.SecurityDescriptorFromString(before + fmt.Sprintf("(A;;0x%x;;;%s)", rights, sid))
	if e != nil {
		return ACLDelta{}, ErrBinding
	}
	return ACLDelta{before, after.String(), sid, rights}, nil
}
func setExactDACL(h windows.Handle, kind windows.SE_OBJECT_TYPE, before, after string) error {
	current, e := descriptorText(h, kind)
	if e != nil || current != before {
		return ErrBinding
	}
	sd, e := windows.SecurityDescriptorFromString(after)
	if e != nil {
		return ErrBinding
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrBinding
	}
	control, _, e := sd.Control()
	if e != nil {
		return ErrBinding
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if e = windows.SetSecurityInfo(h, kind, info, nil, nil, acl, nil); e != nil {
		return ErrBinding
	}
	current, e = descriptorText(h, kind)
	if e != nil || current != after {
		return ErrBinding
	}
	return nil
}
func (s *nativeProvision) CreateJournal(ctx context.Context, p ProvisionPlan) (provisionJournal, error) {
	if ctx.Err() != nil || p.Digest() != s.plan.Digest() {
		return nil, ErrBinding
	}
	path, e := ProvisionPath()
	if e != nil {
		return nil, e
	}
	return windowsstate.Open(path, ProvisionOptions(p.Policy.BrokerSID, true))
}
func (s *nativeProvision) ApplyStage(ctx context.Context, stage string, p ProvisionPlan, payload []byte) error {
	if ctx.Err() != nil || p.Digest() != s.plan.Digest() {
		return ErrBinding
	}
	if e := s.checkTarget(p.Policy); e != nil {
		return e
	}
	switch stage {
	case "image-directory-query":
		if len(s.imageParents) < 2 {
			return ErrBinding
		}
		h, e := windowspath.OpenChild(s.imageParents[len(s.imageParents)-2], "Tracebolt", true, windowspath.DirectoryAccess|windows.WRITE_DAC, windowspath.DirectoryShare)
		if e != nil {
			return ErrBinding
		}
		defer windows.CloseHandle(h)
		var a, b windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &a) != nil || windows.GetFileInformationByHandle(s.imageDirectory, &b) != nil || a.VolumeSerialNumber != b.VolumeSerialNumber || a.FileIndexHigh != b.FileIndexHigh || a.FileIndexLow != b.FileIndexLow {
			return ErrBinding
		}
		return setExactDACL(h, windows.SE_FILE_OBJECT, p.ImageDirectory.Before, p.ImageDirectory.After)
	case "broker-image":
		return s.createImage(ctx, p, payload)
	case "disabled-broker-service":
		return s.createBroker(p)
	case "broker-service-security":
		return s.configureBroker(p)
	case "target-service-rights":
		return applyServiceDelta(p.Policy.Target.Name, p.TargetService)
	case "observer-service-query":
		return applyServiceDelta(AgentName, p.ObserverService)
	case "broker-authority":
		if e := s.Verify(ctx, p); e != nil {
			return e
		}
		root, e := AuthorityPath()
		if e != nil {
			return e
		}
		return initializeCreateOnly(root, p.Policy, time.Now().UTC(), func(policy Policy) error { return reviewSetup(policy, true) })
	}
	return ErrInvalid
}
func applyServiceDelta(name string, delta ACLDelta) error {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(scm)
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(name), windows.READ_CONTROL|windows.WRITE_DAC)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(h)
	return setExactDACL(h, windows.SE_SERVICE, delta.Before, delta.After)
}
func (s *nativeProvision) createImage(ctx context.Context, p ProvisionPlan, payload []byte) error {
	current, e := descriptorText(s.imageDirectory, windows.SE_FILE_OBJECT)
	if e != nil || current != p.ImageDirectory.After {
		return ErrBinding
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + p.Policy.BrokerSID + ")")
	if e != nil {
		return ErrBinding
	}
	h, e := windowspath.CreateChild(s.imageDirectory, BrokerImageName, false, sd)
	if e != nil {
		return ErrBinding
	}
	f := os.NewFile(uintptr(h), "<new action broker>")
	if f == nil {
		windows.CloseHandle(h)
		return ErrBinding
	}
	// The create handle is exclusive; close only after flush/readback, then reopen
	// through the same pinned parent without write/delete sharing.
	err := func() error {
		for offset := 0; offset < len(payload); {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			end := min(offset+(1<<20), len(payload))
			n, e := f.Write(payload[offset:end])
			if e != nil || n != end-offset {
				return ErrBinding
			}
			offset = end
		}
		if f.Sync() != nil {
			return ErrBinding
		}
		hash, e := hashHandle(h)
		if e != nil || hash != "sha256:"+p.Artifact.SHA256 {
			return ErrBinding
		}
		return nil
	}()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrBinding
	}
	held, _, e := holdExecutable(p.Executable)
	s.held = append(s.held, held...)
	return e
}
func (s *nativeProvision) createBroker(p ProvisionPlan) error {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(scm)
	s.broker, e = windows.CreateService(scm, windows.StringToUTF16Ptr(BrokerName), windows.StringToUTF16Ptr("Tracebolt Windows Action Broker"), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_CHANGE_CONFIG|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_DISABLED, windows.SERVICE_ERROR_NORMAL, windows.StringToUTF16Ptr(`"`+p.Executable+`"`), nil, nil, nil, windows.StringToUTF16Ptr(BrokerAccount), nil)
	if e != nil {
		return ErrBinding
	}
	sid, e := serviceSID(BrokerName)
	if e != nil || sid != p.Policy.BrokerSID {
		return ErrBinding
	}
	return nil
}
func (s *nativeProvision) configureBroker(p ProvisionPlan) error {
	if s.broker == 0 {
		return ErrBinding
	}
	sidType := uint32(windows.SERVICE_SID_TYPE_RESTRICTED)
	if windows.ChangeServiceConfig2(s.broker, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType))) != nil {
		return ErrBinding
	}
	privileges := append(windows.StringToUTF16("SeChangeNotifyPrivilege"), 0)
	required := struct{ Privileges *uint16 }{&privileges[0]}
	e := windows.ChangeServiceConfig2(s.broker, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&required)))
	runtime.KeepAlive(privileges)
	if e != nil {
		return ErrBinding
	}
	description := windows.SERVICE_DESCRIPTION{Description: windows.StringToUTF16Ptr(p.Description)}
	if windows.ChangeServiceConfig2(s.broker, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&description))) != nil {
		return ErrBinding
	}
	sd, e := windows.SecurityDescriptorFromString(p.BrokerServiceSDDL)
	if e != nil {
		return ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return ErrBinding
	}
	group, _, e := sd.Group()
	if e != nil {
		return ErrBinding
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return ErrBinding
	}
	if windows.SetSecurityInfo(s.broker, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, group, acl, nil) != nil {
		return ErrBinding
	}
	return brokerServiceACL(s.broker, p.Policy.BrokerSID, p.Policy.AgentSID)
}
func (s *nativeProvision) Verify(ctx context.Context, p ProvisionPlan) error {
	if ctx.Err() != nil || s.checkTarget(p.Policy) != nil {
		return ErrBinding
	}
	for _, item := range []struct {
		h     windows.Handle
		kind  windows.SE_OBJECT_TYPE
		after string
	}{{s.imageDirectory, windows.SE_FILE_OBJECT, p.ImageDirectory.After}, {s.target, windows.SE_SERVICE, p.TargetService.After}, {s.observer, windows.SE_SERVICE, p.ObserverService.After}} {
		got, e := descriptorText(item.h, item.kind)
		if e != nil || got != item.after {
			return ErrBinding
		}
	}
	if e := reviewSetup(p.Policy, true); e != nil {
		return e
	}
	description, e := config2(s.broker, windows.SERVICE_CONFIG_DESCRIPTION)
	if e != nil || len(description) < int(unsafe.Sizeof(uintptr(0))) {
		return ErrBinding
	}
	text, e := boundedString(description, *(**uint16)(unsafe.Pointer(&description[0])), unsafe.Sizeof(uintptr(0)))
	if e != nil || text != p.Description {
		return ErrBinding
	}
	held, file, e := holdExecutable(p.Executable)
	for _, h := range held {
		defer windows.CloseHandle(h)
	}
	if e != nil {
		return e
	}
	hash, e := hashHandle(file)
	if e != nil || hash != "sha256:"+p.Artifact.SHA256 {
		return ErrBinding
	}
	return nil
}

// readProvisionReceipt is runtime read-only. Missing/partial/changed setup never
// becomes consent, and a completed installation remains permanently fenced.
func readProvisionReceipt(policy Policy) (ProvisionPlan, error) {
	path, e := ProvisionPath()
	if e != nil {
		return ProvisionPlan{}, e
	}
	s, e := windowsstate.Open(path, ProvisionOptions(policy.BrokerSID, false))
	if e != nil {
		return ProvisionPlan{}, e
	}
	defer s.Close()
	p, e := readProvisionRecords(s, policy)
	if e != nil {
		return ProvisionPlan{}, e
	}
	if s.Close() != nil {
		return ProvisionPlan{}, ErrIntegrity
	}
	return p, nil
}

// enableBrokerPeerQueries runs only after all own-token/kernel admission and
// opening an exact completed provisioning receipt. Legacy absent setup state
// performs no grant. This changes only the current process object, never its
// token, threads, default DACL, account, or service configuration.
func enableBrokerPeerQueries(policy Policy) error {
	if policy.ProvisioningVersion == "" {
		return nil
	}
	if policy.ProvisioningVersion != ProvisionVersion {
		return ErrBinding
	}
	p, e := readProvisionReceipt(policy)
	if e != nil {
		return e
	}
	if p.PeerProcessQueryRights != PeerProcessQueryRights || p.Account != BrokerAccount || p.Description != provisionDescription(policy, p.Artifact) || verifyBrokerProcess(policy) != nil {
		return ErrBinding
	}
	exe, e := brokerExecutable()
	if e != nil || exe != p.Executable {
		return ErrBinding
	}
	held, file, e := holdExecutable(exe)
	for _, h := range held {
		defer windows.CloseHandle(h)
	}
	if e != nil {
		return e
	}
	hash, e := hashHandle(file)
	if e != nil || hash != "sha256:"+p.Artifact.SHA256 {
		return ErrBinding
	}
	h, e := openReadService(BrokerName)
	if e != nil {
		return e
	}
	defer windows.CloseServiceHandle(h)
	marker, e := brokerMarker(h)
	if e != nil || marker != p.Description {
		return ErrBinding
	}
	if e = grantOwnProcessQuery(policy.AgentSID); e != nil {
		return e
	}
	return verifyBrokerProcess(policy)
}

// EnableObserverPeerQueries is reachable only from a fresh relay-v2 grant. It
// validates our own limited observation identity and exact SCM PID, then binds
// the other fixed SID to the protected public broker installation marker. It
// never opens a foreign token, private broker file, or action-capable handle.
func EnableObserverPeerQueries(ctx context.Context, binding Binding, imageDigest string) error {
	if ctx == nil || ctx.Err() != nil || !ValidBinding(binding) || !ValidDigest(imageDigest) || windowsservice.ValidateRuntimeIdentity() != nil {
		return ErrBinding
	}
	own, e := windowsservice.OpenObservationPeer(ctx, uint32(os.Getpid()))
	if e != nil {
		return ErrBinding
	}
	defer own.Close()
	b, a := FixedServiceSIDs()
	actual, e := serviceSID(AgentName)
	if e != nil || actual != a {
		return ErrBinding
	}
	h, e := openReadService(BrokerName)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(h)
	if brokerServiceACL(h, b, a) != nil {
		return ErrBinding
	}
	exe, e := brokerExecutable()
	if e != nil {
		return e
	}
	if _, _, e = brokerPublicConfiguration(h, exe); e != nil {
		return e
	}
	marker, e := brokerMarker(h)
	if e != nil || marker != "Tracebolt Windows action broker; installation="+binding.InstallationID+"; executable-sha256="+strings.TrimPrefix(imageDigest, "sha256:") {
		return ErrBinding
	}
	if own.Check(ctx) != nil || ctx.Err() != nil {
		return ErrBinding
	}
	if e = grantOwnProcessQuery(b); e != nil {
		return e
	}
	return own.Check(ctx)
}
func brokerMarker(h windows.Handle) (string, error) {
	raw, e := config2(h, windows.SERVICE_CONFIG_DESCRIPTION)
	if e != nil || len(raw) < int(unsafe.Sizeof(uintptr(0))) {
		return "", ErrBinding
	}
	marker, e := boundedString(raw, *(**uint16)(unsafe.Pointer(&raw[0])), unsafe.Sizeof(uintptr(0)))
	if e != nil || validBrokerPublicMarker(marker) != nil {
		return "", ErrBinding
	}
	return marker, nil
}
func grantOwnProcessQuery(sid string) error {
	b, a := FixedServiceSIDs()
	if sid != a && sid != b {
		return ErrBinding
	}
	h, e := windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC, false, uint32(os.Getpid()))
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseHandle(h)
	before, e := descriptorText(h, windows.SE_KERNEL_OBJECT)
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(before)
	if e != nil {
		return ErrBinding
	}
	found := false
	e = eachACE(sd, func(principal string, mask uint32, k, f byte) error {
		if principal == sid {
			if found || k != windows.ACCESS_ALLOWED_ACE_TYPE || f != 0 || mask != PeerProcessQueryRights {
				return ErrBinding
			}
			found = true
		}
		return nil
	})
	if e != nil {
		return e
	}
	if found {
		return nil
	}
	after, e := windows.SecurityDescriptorFromString(before + fmt.Sprintf("(A;;0x%x;;;%s)", PeerProcessQueryRights, sid))
	if e != nil {
		return ErrBinding
	}
	return setExactDACL(h, windows.SE_KERNEL_OBJECT, before, after.String())
}
