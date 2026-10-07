//go:build windows

package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"localrmm/internal/windowsservice"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	probeServiceName    = "TraceboltWindowsAcceptanceProbe"
	probeExecutableName = "tracebolt-windows-acceptance.exe"
	probeArgument       = "--internal-denial-probe"

	// ProbeDeniedExitCode is reported with ERROR_SERVICE_SPECIFIC_ERROR after
	// both real private-file read opens returned ERROR_ACCESS_DENIED. The
	// controller must also establish that the exact target objects exist.
	ProbeDeniedExitCode   uint32 = 0x545001
	probeContextExitCode  uint32 = 0x545002
	probeIdentityExitCode uint32 = 0x545003
	probeReadExitCode     uint32 = 0x545004
	probeCanceledExitCode uint32 = 0x545005
)

// ProbeContextValid is read-only. A flag alone never authorizes this mode: the
// SCM parent, exact image/arguments/configuration and actual limited service
// token must all match. No endpoint file is opened by this pre-dispatch check.
func ProbeContextValid() bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	_, ok := probeRuntimeContext()
	return ok
}

func runProbeRuntime(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !ProbeContextValid() {
		return ErrAcceptance
	}
	h := &denialProbeHandler{ctx: ctx, result: make(chan uint32, 1)}
	if svc.Run(probeServiceName, h) != nil {
		return ErrAcceptance
	}
	select {
	case code := <-h.result:
		if code == ProbeDeniedExitCode {
			return nil
		}
	default:
	}
	return ErrAcceptance
}

type denialProbeHandler struct {
	ctx    context.Context
	result chan uint32
}

func (h *denialProbeHandler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	finish := func(code uint32) (bool, uint32) {
		h.result <- code
		return true, code
	}
	if len(args) != 1 || args[0] != probeServiceName {
		return finish(probeContextExitCode)
	}
	current := svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
	changes <- current
	if h.ctx == nil || h.ctx.Err() != nil {
		return finish(probeCanceledExitCode)
	}
	layout, ok := probeRuntimeContext()
	if !ok {
		return finish(probeContextExitCode)
	}
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- current
	done := make(chan uint32, 1)
	go func() { done <- probePrivateReadDenial(ctx, layout) }()
	canceled := h.ctx.Done()
	stopping := false
	stop := func() {
		if stopping {
			return
		}
		stopping = true
		canceled = nil
		cancel()
		current = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
		changes <- current
	}
	for {
		select {
		case <-canceled:
			stop()
		case request, open := <-requests:
			if !open {
				requests = nil
				stop()
				continue
			}
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				stop()
			case svc.Interrogate:
				changes <- current
			}
		case code := <-done:
			// Never publish successful denial after a concurrent cancellation,
			// and never report Stopped until the read-only worker has returned.
			if stopping || h.ctx.Err() != nil {
				code = probeCanceledExitCode
			}
			return finish(code)
		}
	}
}

func probeRuntimeContext() (windowsservice.Layout, bool) {
	layout, err := windowsservice.ResolveLayout()
	if err != nil || len(os.Args) != 2 || os.Args[1] != probeArgument {
		return windowsservice.Layout{}, false
	}
	expectedImage := layout.ProgramFiles + `\Tracebolt\` + probeExecutableName
	image, err := os.Executable()
	if err != nil || !strings.EqualFold(image, expectedImage) {
		return windowsservice.Layout{}, false
	}
	probeSID, mainSID, ok := probeSIDs()
	if !ok || !validateProcessToken(windows.GetCurrentProcessId(), probeSID, mainSID) {
		return windowsservice.Layout{}, false
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return windowsservice.Layout{}, false
	}
	defer windows.CloseServiceHandle(scm)
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(probeServiceName), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return windowsservice.Layout{}, false
	}
	defer windows.CloseServiceHandle(h)
	cfg, err := (&mgr.Service{Name: probeServiceName, Handle: h}).Config()
	if err != nil || !probeFixedConfiguration(cfg, expectedImage) {
		return windowsservice.Layout{}, false
	}
	_, digest, ok := probeDescriptionBinding(cfg.Description)
	if !ok || !probeHashImage(expectedImage, digest) {
		return windowsservice.Layout{}, false
	}
	privileges, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if !ok || !probeOnlyChangeNotify(privileges) {
		return windowsservice.Layout{}, false
	}
	actions, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS)
	if !ok || len(actions) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
		return windowsservice.Layout{}, false
	}
	a := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&actions[0]))
	if a.ActionsCount != 0 || !probeEmptyUTF16(actions, a.RebootMsg) || !probeEmptyUTF16(actions, a.Command) {
		return windowsservice.Layout{}, false
	}
	triggers, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_TRIGGER_INFO)
	if !ok || binary.LittleEndian.Uint32(triggers) != 0 {
		return windowsservice.Layout{}, false
	}
	failureFlag, ok := probeQueryConfig2(h, windows.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
	if !ok || binary.LittleEndian.Uint32(failureFlag) != 0 {
		return windowsservice.Layout{}, false
	}
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err = windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	// Windows documents the service PID as undefined during START_PENDING.
	// After Running, it must bind to this exact process.
	if err != nil || !probeOwnStatus(status, windows.GetCurrentProcessId()) {
		return windowsservice.Layout{}, false
	}
	runtime.KeepAlive(actions)
	return layout, true
}

func probeFixedConfiguration(c mgr.Config, executable string) bool {
	return c.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS && c.StartType == windows.SERVICE_DEMAND_START && c.ErrorControl == windows.SERVICE_ERROR_NORMAL &&
		c.BinaryPathName == `"`+executable+`" "`+probeArgument+`"` && strings.EqualFold(c.ServiceStartName, windowsservice.Account) &&
		c.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED && len(c.Dependencies) == 0 && c.LoadOrderGroup == "" && c.TagId == 0 && !c.DelayedAutoStart
}

func probeOwnStatus(s windows.SERVICE_STATUS_PROCESS, pid uint32) bool {
	return pid != 0 && s.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS && (s.CurrentState == windows.SERVICE_START_PENDING || (s.CurrentState == windows.SERVICE_RUNNING && s.ProcessId == pid))
}

func probeSIDs() (string, string, bool) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+probeServiceName)
	if err != nil || sid == nil || !sid.IsValid() {
		return "", "", false
	}
	main, err := windowsservice.LookupServiceSID()
	probe := sid.String()
	return probe, main, err == nil && nativeServiceSID(probe) && nativeServiceSID(main) && probe != main
}

func probePrivateReadDenial(ctx context.Context, layout windowsservice.Layout) uint32 {
	// A fixed OS thread lets the read-only no-impersonation check describe the
	// exact effective identity used by both CreateFile calls.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	if err == nil {
		_ = threadToken.Close()
		return probeIdentityExitCode
	}
	if err != windows.ERROR_NO_TOKEN {
		return probeIdentityExitCode
	}
	probe, main, ok := probeSIDs()
	if !ok || !validateProcessToken(windows.GetCurrentProcessId(), probe, main) {
		return probeIdentityExitCode
	}
	return probeReadTargets(ctx, []string{layout.EnrollmentRoot + `\agent-key.pem`, layout.SenderRoot + `\state.json`}, probeReadOpenDenied)
}

// probeReadTargets is injectable only inside the package for in-memory tests.
// Production supplies exactly the two fixed actual private paths above.
func probeReadTargets(ctx context.Context, paths []string, readDenied func(string) bool) uint32 {
	if ctx == nil || ctx.Err() != nil {
		return probeCanceledExitCode
	}
	if len(paths) != 2 || paths[0] == "" || paths[1] == "" || readDenied == nil {
		return probeReadExitCode
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			return probeCanceledExitCode
		}
		if !readDenied(path) {
			return probeReadExitCode
		}
	}
	if ctx.Err() != nil {
		return probeCanceledExitCode
	}
	return ProbeDeniedExitCode
}

func probeReadOpenDenied(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	// OPEN_EXISTING plus FILE_READ_DATA never creates/truncates or reads bytes.
	// All sharing modes avoid mistaking a sharing violation for a permission
	// denial. A successful handle is closed immediately and is a failed gate.
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	h, err := windows.CreateFile(name, windows.FILE_READ_DATA, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		_ = windows.CloseHandle(h)
		return false
	}
	return probeAccessDenied(err)
}

// Only the actual Win32 result counts. Policy errors, not-found, sharing
// violations, wrappers and synthetic sentinel errors never count as denial.
func probeAccessDenied(err error) bool { return err == windows.ERROR_ACCESS_DENIED }

func probeQueryConfig2(h windows.Handle, kind uint32) ([]byte, bool) {
	var needed uint32
	err := windows.QueryServiceConfig2(h, kind, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < 4 || needed > 65536 {
		return nil, false
	}
	b := make([]byte, needed)
	if windows.QueryServiceConfig2(h, kind, &b[0], uint32(len(b)), &needed) != nil || needed > uint32(len(b)) {
		return nil, false
	}
	return b, true
}

func probeOnlyChangeNotify(b []byte) bool {
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	if len(b) < ptrSize {
		return false
	}
	p := *(*uintptr)(unsafe.Pointer(&b[0]))
	base := uintptr(unsafe.Pointer(&b[0]))
	if p < base+uintptr(ptrSize) || p >= base+uintptr(len(b)) || (p-base)%2 != 0 {
		return false
	}
	data := b[int(p-base):]
	want := "SeChangeNotifyPrivilege"
	if len(data) < (len(want)+2)*2 {
		return false
	}
	for i := 0; i < len(want); i++ {
		if binary.LittleEndian.Uint16(data[i*2:]) != uint16(want[i]) {
			return false
		}
	}
	return binary.LittleEndian.Uint16(data[len(want)*2:]) == 0 && binary.LittleEndian.Uint16(data[(len(want)+1)*2:]) == 0
}

func probeEmptyUTF16(b []byte, value *uint16) bool {
	if value == nil {
		return true
	}
	if len(b) < 2 {
		return false
	}
	base, p := uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(value))
	if p < base || p-base > uintptr(len(b)-2) || (p-base)%2 != 0 {
		return false
	}
	return binary.LittleEndian.Uint16(b[int(p-base):]) == 0
}

func probeDescriptionBinding(description string) (string, string, bool) {
	const prefix = "Tracebolt native acceptance probe; installation="
	if !strings.HasPrefix(description, prefix) {
		return "", "", false
	}
	id, digest, ok := strings.Cut(strings.TrimPrefix(description, prefix), "; executable-sha256=")
	if !ok || len(id) != 32 || id != strings.ToLower(id) || !validDigest(digest) {
		return "", "", false
	}
	decoded, err := hex.DecodeString(id)
	return id, digest, err == nil && len(decoded) == 16
}

// This is the public acceptance executable, not endpoint private state. The
// handle denies write/delete sharing throughout its bounded streaming hash.
func probeHashImage(path, digest string) bool {
	h, _, err := openChecked(path, false, windows.GENERIC_READ, windows.FILE_SHARE_READ)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(h), "<acceptance executable>")
	if f == nil {
		_ = windows.CloseHandle(h)
		return false
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxArtifactBytes+1))
	return err == nil && n > 0 && n <= maxArtifactBytes && hex.EncodeToString(hash.Sum(nil)) == digest
}
