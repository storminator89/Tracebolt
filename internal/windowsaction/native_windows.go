//go:build windows

package windowsaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
)

const targetRights = windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.SERVICE_START | windows.SERVICE_STOP | windows.SERVICE_ENUMERATE_DEPENDENTS | windows.READ_CONTROL

func AuthorityPath() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	if e != nil || !windowspath.Canonical(p) {
		return "", ErrUnavailable
	}
	return p + `\Tracebolt-action-broker`, nil
}
func brokerExecutable() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	if e != nil || !windowspath.Canonical(p) {
		return "", ErrUnavailable
	}
	return p + `\Tracebolt\tracebolt-windows-action-broker.exe`, nil
}
func serviceSID(name string) (string, error) {
	if name != BrokerName && name != AgentName {
		return "", ErrInvalid
	}
	s, _, _, e := windows.LookupSID("", `NT SERVICE\`+name)
	if e != nil || s == nil || !s.IsValid() || !validSID(s.String()) {
		return "", ErrUnavailable
	}
	return s.String(), nil
}

type windowsBackend struct{}

func nativeBackend() Backend { return windowsBackend{} }

type nativeService struct {
	handle              windows.Handle
	target              Target
	brokerSID, agentSID string
	held                []windows.Handle
	file                windows.Handle
}

func (windowsBackend) Open(t Target, brokerSID, agentSID string) (Service, error) {
	if !ValidTarget(t.Name) || !validSID(brokerSID) || !validSID(agentSID) || brokerSID == agentSID {
		return nil, ErrInvalid
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer windows.CloseServiceHandle(scm)
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(t.Name), targetRights)
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &nativeService{handle: h, target: t, brokerSID: brokerSID, agentSID: agentSID}
	s.held, s.file, e = holdExecutable(t.Executable)
	if e != nil {
		return s, e
	}
	return s, nil
}
func (s *nativeService) Close() error {
	var result error
	for i := len(s.held) - 1; i >= 0; i-- {
		result = errors.Join(result, windows.CloseHandle(s.held[i]))
	}
	s.held = nil
	result = errors.Join(result, windows.CloseServiceHandle(s.handle))
	return result
}
func (s *nativeService) Start() error { return windows.StartService(s.handle, 0, nil) }
func (s *nativeService) Stop() error {
	var st windows.SERVICE_STATUS
	return windows.ControlService(s.handle, windows.SERVICE_CONTROL_STOP, &st)
}
func (s *nativeService) Inspect() (Snapshot, error) {
	if e := checkBrokerServiceACL(s.brokerSID, s.agentSID); e != nil {
		return Snapshot{}, e
	}
	digest, e := configurationDigest(s.handle, s.target.Executable, `NT AUTHORITY\LocalService`)
	if e != nil || digest != s.target.ConfigurationDigest {
		return Snapshot{}, ErrBinding
	}
	if e = serviceACL(s.handle, s.brokerSID); e != nil {
		return Snapshot{}, e
	}
	// No active dependent is stopped implicitly. ERROR_MORE_DATA proves there is
	// at least one and is rejected without allocating an unbounded service list.
	var need, count uint32
	e = windows.EnumDependentServices(s.handle, windows.SERVICE_ACTIVE, nil, 0, &need, &count)
	if e != nil || need != 0 || count != 0 {
		return Snapshot{}, ErrUnavailable
	}
	for i, h := range s.held {
		if e = pathACL(h, i < len(s.held)-1); e != nil {
			return Snapshot{}, e
		}
	}
	digest, e = hashHandle(s.file)
	if e != nil || digest != s.target.ExecutableDigest {
		return Snapshot{}, ErrBinding
	}
	st, e := serviceStatus(s.handle)
	if e != nil {
		return Snapshot{}, e
	}
	return Snapshot{st.CurrentState, st.ControlsAccepted&windows.SERVICE_ACCEPT_STOP != 0, st.ProcessId}, nil
}
func serviceStatus(h windows.Handle) (windows.SERVICE_STATUS_PROCESS, error) {
	var st windows.SERVICE_STATUS_PROCESS
	var n uint32
	e := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n)
	if e != nil || n > uint32(unsafe.Sizeof(st)) {
		return st, ErrUnavailable
	}
	return st, nil
}
func config2(h windows.Handle, kind uint32) ([]byte, error) {
	var n uint32
	e := windows.QueryServiceConfig2(h, kind, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < 4 || n > 8192 {
		return nil, ErrUnavailable
	}
	b := make([]byte, n)
	e = windows.QueryServiceConfig2(h, kind, &b[0], uint32(len(b)), &n)
	if e != nil || n > uint32(len(b)) {
		return nil, ErrUnavailable
	}
	return b, nil
}
func boundedString(b []byte, p *uint16, minimum uintptr) (string, error) {
	if p == nil {
		return "", nil
	}
	base := uintptr(unsafe.Pointer(&b[0]))
	addr := uintptr(unsafe.Pointer(p))
	if addr < base+minimum || addr >= base+uintptr(len(b)) || (addr-base)%2 != 0 {
		return "", ErrInvalid
	}
	data := b[addr-base:]
	u := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		n := uint16(data[i]) | uint16(data[i+1])<<8
		if n == 0 {
			return windows.UTF16ToString(u), nil
		}
		if n >= 0xd800 && n <= 0xdfff {
			return "", ErrInvalid
		}
		u = append(u, n)
	}
	return "", ErrInvalid
}

// Every admitted native configuration input is bounded and pinned. The first
// slice supports no dependencies, triggers, recovery, scripts or command args.
func configurationDigest(h windows.Handle, exe, expectedAccount string) (string, error) {
	return configurationDigestMode(h, exe, expectedAccount, false)
}

// Only explicit create-only provisioning may inspect disabled staging.
func configurationDigestMode(h windows.Handle, exe, expectedAccount string, disabled bool) (string, error) {
	var n uint32
	e := windows.QueryServiceConfig(h, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < uint32(unsafe.Sizeof(windows.QUERY_SERVICE_CONFIG{})) || n > 8192 {
		return "", ErrUnavailable
	}
	b := make([]byte, n)
	c := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
	if windows.QueryServiceConfig(h, c, n, &n) != nil || n > uint32(len(b)) {
		return "", ErrUnavailable
	}
	min := unsafe.Sizeof(*c)
	binary, e := boundedString(b, c.BinaryPathName, min)
	if e != nil || binary != `"`+exe+`"` {
		return "", ErrBinding
	}
	account, e := boundedString(b, c.ServiceStartName, min)
	if e != nil || account != expectedAccount {
		return "", ErrBinding
	}
	deps, e := boundedString(b, c.Dependencies, min)
	if e != nil || deps != "" {
		return "", ErrBinding
	}
	group, e := boundedString(b, c.LoadOrderGroup, min)
	if e != nil || group != "" || c.TagId != 0 {
		return "", ErrBinding
	}
	display, e := boundedString(b, c.DisplayName, min)
	if e != nil {
		return "", e
	}
	if c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || (disabled && c.StartType != windows.SERVICE_DISABLED || !disabled && c.StartType != windows.SERVICE_DEMAND_START && c.StartType != windows.SERVICE_AUTO_START) || c.ErrorControl > 1 {
		return "", ErrBinding
	}
	failure, e := config2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS)
	if e != nil || len(failure) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
		return "", ErrBinding
	}
	f := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&failure[0]))
	if f.ActionsCount != 0 {
		return "", ErrBinding
	}
	reboot, e := boundedString(failure, f.RebootMsg, unsafe.Sizeof(*f))
	if e != nil || reboot != "" {
		return "", ErrBinding
	}
	cmd, e := boundedString(failure, f.Command, unsafe.Sizeof(*f))
	if e != nil || cmd != "" {
		return "", ErrBinding
	}
	triggers, e := config2(h, windows.SERVICE_CONFIG_TRIGGER_INFO)
	if e != nil || *(*uint32)(unsafe.Pointer(&triggers[0])) != 0 {
		return "", ErrBinding
	}
	sid, e := config2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
	if e != nil {
		return "", e
	}
	sidType := *(*uint32)(unsafe.Pointer(&sid[0]))
	if sidType != windows.SERVICE_SID_TYPE_UNRESTRICTED && sidType != windows.SERVICE_SID_TYPE_RESTRICTED {
		return "", ErrBinding
	}
	delayed, e := config2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
	if e != nil {
		return "", e
	}
	delay := *(*uint32)(unsafe.Pointer(&delayed[0]))
	if delay > 1 {
		return "", ErrBinding
	}
	failflag, e := config2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
	if e != nil || *(*uint32)(unsafe.Pointer(&failflag[0])) != 0 {
		return "", ErrBinding
	}
	required, e := config2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if e != nil || len(required) < int(unsafe.Sizeof(uintptr(0))) {
		return "", ErrBinding
	}
	priv, e := boundedString(required, *(**uint16)(unsafe.Pointer(&required[0])), unsafe.Sizeof(uintptr(0)))
	if e != nil || priv != "SeChangeNotifyPrivilege" {
		return "", ErrBinding
	}
	p := *(**uint16)(unsafe.Pointer(&required[0]))
	off := uintptr(unsafe.Pointer(p)) - uintptr(unsafe.Pointer(&required[0])) + uintptr(2*(len(priv)+1))
	if off+2 > uintptr(len(required)) || required[off] != 0 || required[off+1] != 0 {
		return "", ErrBinding
	}
	raw, _ := json.Marshal(struct {
		Type, Start, Error, SID, Delay      uint32
		Binary, Account, Display, Privilege string
	}{c.ServiceType, c.StartType, c.ErrorControl, sidType, delay, binary, account, display, priv})
	runtime.KeepAlive(b)
	runtime.KeepAlive(required)
	return Digest(raw), nil
}
func eachACE(sd *windows.SECURITY_DESCRIPTOR, visit func(string, uint32, byte, byte) error) error {
	if sd == nil || !sd.IsValid() {
		return ErrBinding
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount > 64 {
		return ErrBinding
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return ErrBinding
		}
		offset := unsafe.Offsetof(ace.SidStart)
		if uintptr(ace.Header.AceSize) < offset+8 {
			return ErrBinding
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		header := unsafe.Slice((*byte)(unsafe.Pointer(sid)), 8)
		if offset+8+4*uintptr(header[1]) > uintptr(ace.Header.AceSize) || !sid.IsValid() {
			return ErrBinding
		}
		if e = visit(sid.String(), uint32(ace.Mask), ace.Header.AceType, ace.Header.AceFlags); e != nil {
			return e
		}
	}
	return nil
}
func trustedWriter(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func serviceACL(h windows.Handle, broker string) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedWriter(owner.String()) {
		return ErrBinding
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrBinding
	}
	seen := false
	e = eachACE(sd, func(s string, mask uint32, kind, flags byte) error {
		if flags != 0 || kind != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrBinding
		}
		if trustedWriter(s) {
			return nil
		}
		if s == broker {
			if seen || mask != targetRights {
				return ErrBinding
			}
			seen = true
			return nil
		}
		if mask & ^uint32(windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_ENUMERATE_DEPENDENTS|windows.SERVICE_INTERROGATE|windows.READ_CONTROL) != 0 {
			return ErrBinding
		}
		return nil
	})
	if e != nil || !seen {
		return ErrBinding
	}
	return nil
}
func pathACL(h windows.Handle, directory bool) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedWriter(owner.String()) {
		return ErrBinding
	}
	writes := untrustedPathWriteMask(directory)
	return eachACE(sd, func(s string, mask uint32, kind, flags byte) error {
		if flags&windows.INHERIT_ONLY_ACE != 0 {
			return nil
		}
		if kind == windows.ACCESS_ALLOWED_ACE_TYPE && !trustedWriter(s) && mask&writes != 0 {
			return ErrBinding
		}
		return nil
	})
}
func holdExecutable(path string) (held []windows.Handle, file windows.Handle, err error) {
	if !windowspath.Canonical(path) || !strings.HasSuffix(strings.ToLower(path), ".exe") || windows.GetDriveType(windows.StringToUTF16Ptr(path[:3])) != windows.DRIVE_FIXED {
		return nil, 0, ErrBinding
	}
	parts := strings.Split(path[3:], `\`)
	current := path[:3]
	for i := 0; i <= len(parts); i++ {
		directory := i < len(parts)
		var h windows.Handle
		if i == 0 {
			h, err = windowspath.OpenRoot(current)
		} else {
			current = strings.TrimSuffix(current, `\`) + `\` + parts[i-1]
			access, share := uint32(windowspath.DirectoryAccess), uint32(windowspath.DirectoryShare)
			if !directory {
				access = windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.GENERIC_READ
				share = windows.FILE_SHARE_READ
			}
			h, err = windowspath.OpenChild(held[len(held)-1], parts[i-1], directory, access, share)
		}
		if err != nil {
			return held, 0, ErrBinding
		}
		held = append(held, h)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
			return held, 0, ErrBinding
		}
		var final [512]uint16
		n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
		if e != nil || n == 0 || n >= uint32(len(final)) || windows.UTF16ToString(final[:n]) != `\\?\`+current {
			return held, 0, ErrBinding
		}
		if directory {
			var flags uint32
			var ios windows.IO_STATUS_BLOCK
			if windows.NtQueryInformationFile(h, &ios, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileCaseSensitiveInformation) != nil || flags != 0 {
				return held, 0, ErrBinding
			}
		}
		if e = pathACL(h, directory); e != nil {
			return held, 0, e
		}
		file = h
	}
	return held, file, nil
}
func hashHandle(h windows.Handle) (string, error) {
	var duplicate windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return "", ErrBinding
	}
	f := os.NewFile(uintptr(duplicate), "protected executable")
	if f == nil {
		windows.CloseHandle(duplicate)
		return "", ErrBinding
	}
	defer f.Close()
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return "", ErrBinding
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(f, 256<<20+1))
	if e != nil || n == 0 || n > 256<<20 {
		return "", ErrBinding
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
func ReviewExistingSetup(p Policy) error {
	if p.ProvisioningVersion != "" {
		return ErrInvalid
	}
	return reviewSetup(p, false)
}
func reviewSetup(p Policy, disabled bool) error {
	if ValidatePolicy(p) != nil {
		return ErrInvalid
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseServiceHandle(scm)
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(BrokerName), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.READ_CONTROL)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseServiceHandle(h)
	st, e := serviceStatus(h)
	if e != nil || st.CurrentState != windows.SERVICE_STOPPED {
		return ErrBinding
	}
	exe, e := brokerExecutable()
	if e != nil {
		return e
	}
	if _, e = configurationDigestMode(h, exe, BrokerAccount, disabled); e != nil {
		return e
	}
	info, e := config2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
	if e != nil || *(*uint32)(unsafe.Pointer(&info[0])) != windows.SERVICE_SID_TYPE_RESTRICTED {
		return ErrBinding
	}
	held, file, e := holdExecutable(exe)
	for _, handle := range held {
		defer windows.CloseHandle(handle)
	}
	if e != nil {
		return e
	}
	hash, e := hashHandle(file)
	if e != nil {
		return e
	}
	marker, e := brokerMarker(h)
	if e != nil || marker != brokerPublicMarkerPrefix+p.Binding.InstallationID+"; executable-sha256="+strings.TrimPrefix(hash, "sha256:") {
		return ErrBinding
	}
	b, e := serviceSID(BrokerName)
	if e != nil || b != p.BrokerSID {
		return ErrBinding
	}
	a, e := serviceSID(AgentName)
	if e != nil || a != p.AgentSID {
		return ErrBinding
	}
	s, e := nativeBackend().Open(p.Target, p.BrokerSID, p.AgentSID)
	if s != nil {
		defer s.Close()
	}
	if e != nil {
		return e
	}
	_, e = s.Inspect()
	return e
}

func brokerServiceACL(h windows.Handle, broker, agent string) error {
	sd, e := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return ErrBinding
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return ErrBinding
	}
	control, _, e := sd.Control()
	if e != nil {
		return ErrBinding
	}
	entries := []serviceACE{}
	e = eachACE(sd, func(s string, m uint32, k, f byte) error {
		entries = append(entries, serviceACE{s, m, k, f})
		return nil
	})
	if e != nil {
		return e
	}
	return validateBrokerServiceACL(owner.String(), control&windows.SE_DACL_PROTECTED != 0, entries, broker, agent)
}
func checkBrokerServiceACL(broker, agent string) error {
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(scm)
	h, e := windows.OpenService(scm, windows.StringToUTF16Ptr(BrokerName), windows.READ_CONTROL)
	if e != nil {
		return ErrBinding
	}
	defer windows.CloseServiceHandle(h)
	return brokerServiceACL(h, broker, agent)
}

func (windowsBackend) ValidateRuntime(p Policy) error { return verifyBrokerProcess(p) }
