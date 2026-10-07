//go:build windows

package windowsservice

import (
	"context"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ValidateRuntimeIdentity is read-only and must precede any private-state read.
// It requires LocalService and this service's enabled SID; no privilege beyond
// SeChangeNotifyPrivilege may be present, even if currently disabled.
func ValidateRuntimeIdentity() (err error) {
	defer func() { err = Mark(PhaseRuntimeIdentity, ReasonIdentityRejected, err) }()
	expected, err := LookupServiceSID()
	if err != nil {
		return ErrUnsafeIdentity
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return ErrUnsafeIdentity
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return ErrUnsafeIdentity
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return ErrUnsafeIdentity
	}
	identity := runtimeIdentity{UserSID: user.User.Sid.String()}
	for _, g := range groups.AllGroups() {
		identity.Groups = append(identity.Groups, identityGroup{SID: g.Sid.String(), Enabled: g.Attributes&windows.SE_GROUP_ENABLED != 0, Owner: g.Attributes&windows.SE_GROUP_OWNER != 0, DenyOnly: g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0})
	}
	var required windows.LUID
	if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(RequiredPrivilege), &required) != nil {
		return ErrUnsafeIdentity
	}
	var needed uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || needed < 4 || needed > 65536 {
		return ErrUnsafeIdentity
	}
	b := make([]byte, needed)
	if windows.GetTokenInformation(token, windows.TokenPrivileges, &b[0], uint32(len(b)), &needed) != nil {
		return ErrUnsafeIdentity
	}
	p := (*windows.Tokenprivileges)(unsafe.Pointer(&b[0]))
	offset := unsafe.Offsetof(p.Privileges)
	size := unsafe.Sizeof(windows.LUIDAndAttributes{})
	if uint64(offset)+uint64(p.PrivilegeCount)*uint64(size) > uint64(len(b)) {
		return ErrUnsafeIdentity
	}
	for _, privilege := range p.AllPrivileges() {
		if privilege.Luid != required {
			identity.UnexpectedPrivilege = true
		}
	}
	return validateIdentity(identity, expected)
}

// Run connects only to the SCM dispatcher. It neither installs nor changes the
// service and cannot be used as an elevated foreground enrollment shortcut.
func Run(ctx context.Context, worker Worker) error {
	if ctx == nil || worker == nil {
		return Mark(PhaseRuntimeDispatch, ReasonInvalidConfiguration, errors.New("missing Windows service context or worker"))
	}
	if err := ctx.Err(); err != nil {
		return Mark(PhaseRuntimeDispatch, ReasonInterrupted, err)
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return Mark(PhaseRuntimeDispatch, ReasonDispatcherUnavailable, err)
	}
	if !isService {
		return Mark(PhaseRuntimeDispatch, ReasonInvalidConfiguration, errors.New("SCM service context required"))
	}
	h := &runtimeHandler{ctx: ctx, worker: worker, result: make(chan error, 1)}
	if err = svc.Run(Name, h); err != nil {
		return Mark(PhaseRuntimeDispatch, ReasonDispatcherUnavailable, err)
	}
	select {
	case err = <-h.result:
		return err
	default:
		return Mark(PhaseRuntimeDispatch, ReasonUnexpectedExit, errors.New("SCM dispatcher ended before worker execution"))
	}
}

func validateNativeRuntimeInstallation() (err error) {
	defer func() {
		if err == nil {
			return
		}
		reason := ReasonOperationFailed
		if d := Describe(err); d.Phase == PhaseRuntimeInstallation {
			reason = d.Reason
		} else if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			reason = ReasonRuntimeReadDenied
		}
		err = Mark(PhaseRuntimeInstallation, reason, err)
	}()
	l, err := ResolveLayout()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	snapshot, err := Inspect(context.Background())
	if err != nil {
		return err
	}
	digest, err := verifyExecutable(l)
	if err != nil {
		return err
	}
	return validateRuntimeInstallation(l, snapshot, executable, digest, windows.GetCurrentProcessId())
}

type runtimeHandler struct {
	ctx    context.Context
	worker Worker
	result chan error
}

func (h *runtimeHandler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	if len(args) != 1 || args[0] != Name {
		err := Mark(PhaseRuntimeDispatch, ReasonInvalidArguments, ErrMismatch)
		h.result <- err
		return true, ServiceExitCode(err)
	}
	// Pending is sent immediately, before native identity checks. No worker starts
	// unless every token restriction is verified.
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
	if err := ValidateRuntimeIdentity(); err != nil {
		h.result <- err
		return true, ServiceExitCode(err)
	}
	if err := validateNativeRuntimeInstallation(); err != nil {
		h.result <- err
		return true, ServiceExitCode(err)
	}
	controls := make(chan control)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		for {
			select {
			case <-finished:
				return
			case request, ok := <-requests:
				if !ok {
					close(controls)
					return
				}
				var c control
				switch request.Cmd {
				case svc.Stop:
					c = controlStop
				case svc.Shutdown:
					c = controlShutdown
				case svc.Interrogate:
					c = controlInterrogate
				default:
					continue
				}
				select {
				case controls <- c:
				case <-finished:
					return
				}
			}
		}
	}()
	err := runLifecycle(h.ctx, h.worker, controls, func(s status) {
		// svc.Run reports final SERVICE_STOPPED with our exit code once Execute
		// returns. Do not report it twice: the status handle is invalidated then.
		if s.State == Stopped {
			return
		}
		var accepts svc.Accepted
		if s.AcceptStop {
			accepts |= svc.AcceptStop
		}
		if s.AcceptShutdown {
			accepts |= svc.AcceptShutdown
		}
		changes <- svc.Status{State: svc.State(s.State), Accepts: accepts, CheckPoint: s.CheckPoint, WaitHint: s.WaitHint}
	})
	if err != nil {
		if d := Describe(err); d.Phase == PhaseUnknown {
			err = Mark(PhaseLifecycle, ReasonOperationFailed, err)
		} else {
			err = Mark(d.Phase, d.Reason, err)
		}
		h.result <- err
		return true, ServiceExitCode(err)
	}
	h.result <- nil
	return false, 0
}
