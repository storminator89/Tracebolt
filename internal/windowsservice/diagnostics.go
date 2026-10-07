package windowsservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Phase and Reason are finite diagnostic labels, never free-form error text.
// Their spelling and numeric IDs are an operator-facing compatibility contract.
type Phase string
type Reason string

const (
	PhaseUnknown             Phase = "unknown"
	PhaseSetup               Phase = "setup"
	PhaseReceipt             Phase = "receipt"
	PhaseRuntimeDispatch     Phase = "runtime_dispatch"
	PhaseRuntimeIdentity     Phase = "runtime_identity"
	PhaseRuntimeInstallation Phase = "runtime_installation"
	PhaseBootstrap           Phase = "bootstrap"
	PhaseRetainedState       Phase = "retained_state"
	PhasePendingApproval     Phase = "pending_approval"
	PhaseEnrollment          Phase = "enrollment"
	PhaseHandoff             Phase = "handoff"
	PhaseSender              Phase = "sender"
	PhaseLifecycle           Phase = "lifecycle"
)

const (
	ReasonUnknown               Reason = "unknown"
	ReasonInvalidConfiguration  Reason = "invalid_configuration"
	ReasonIdentityRejected      Reason = "identity_rejected"
	ReasonRuntimeReadDenied     Reason = "runtime_read_denied"
	ReasonStateRejected         Reason = "state_rejected"
	ReasonApprovalExpired       Reason = "approval_expired"
	ReasonEnrollmentTerminal    Reason = "enrollment_terminal"
	ReasonEnrollmentFailed      Reason = "enrollment_failed"
	ReasonHandoffInvalid        Reason = "handoff_invalid"
	ReasonSenderFailed          Reason = "sender_failed"
	ReasonInputFailed           Reason = "input_failed"
	ReasonOperationFailed       Reason = "operation_failed"
	ReasonUnsupportedPlatform   Reason = "unsupported_platform"
	ReasonInvalidArguments      Reason = "invalid_arguments"
	ReasonDispatcherUnavailable Reason = "dispatcher_unavailable"
	ReasonUnsafePath            Reason = "unsafe_path"
	ReasonStateUnavailable      Reason = "state_unavailable"
	ReasonInterrupted           Reason = "interrupted"
	ReasonResultEncoding        Reason = "result_encoding"
	ReasonResultWrite           Reason = "result_write"
	ReasonUnexpectedExit        Reason = "unexpected_exit"
	ReasonInputRejected         Reason = "input_rejected"
)

// Explicit IDs prevent new entries or reordered declarations from renumbering
// an existing status. Do not reuse an ID or derive it from a declaration index.
func phaseID(phase Phase) (uint32, bool) {
	switch phase {
	case PhaseUnknown:
		return 0, true
	case PhaseSetup:
		return 1, true
	case PhaseReceipt:
		return 2, true
	case PhaseRuntimeDispatch:
		return 3, true
	case PhaseRuntimeIdentity:
		return 4, true
	case PhaseRuntimeInstallation:
		return 5, true
	case PhaseBootstrap:
		return 6, true
	case PhaseRetainedState:
		return 7, true
	case PhasePendingApproval:
		return 8, true
	case PhaseEnrollment:
		return 9, true
	case PhaseHandoff:
		return 10, true
	case PhaseSender:
		return 11, true
	case PhaseLifecycle:
		return 12, true
	default:
		return 0, false
	}
}

func reasonID(reason Reason) (uint32, bool) {
	switch reason {
	case ReasonUnknown:
		return 0, true
	case ReasonInvalidConfiguration:
		return 1, true
	case ReasonIdentityRejected:
		return 2, true
	case ReasonRuntimeReadDenied:
		return 3, true
	case ReasonStateRejected:
		return 4, true
	case ReasonApprovalExpired:
		return 5, true
	case ReasonEnrollmentTerminal:
		return 6, true
	case ReasonEnrollmentFailed:
		return 7, true
	case ReasonHandoffInvalid:
		return 8, true
	case ReasonSenderFailed:
		return 9, true
	case ReasonInputFailed:
		return 10, true
	case ReasonOperationFailed:
		return 11, true
	case ReasonUnsupportedPlatform:
		return 12, true
	case ReasonInvalidArguments:
		return 13, true
	case ReasonDispatcherUnavailable:
		return 14, true
	case ReasonUnsafePath:
		return 15, true
	case ReasonStateUnavailable:
		return 16, true
	case ReasonInterrupted:
		return 17, true
	case ReasonResultEncoding:
		return 18, true
	case ReasonResultWrite:
		return 19, true
	case ReasonUnexpectedExit:
		return 20, true
	case ReasonInputRejected:
		return 21, true
	default:
		return 0, false
	}
}

// DiagnosticStatus carries no cause, path, identity, network destination,
// fingerprint, invitation or host metadata. ServiceCode is the SCM
// ServiceSpecificExitCode, not a Win32 error or a process exit status.
type DiagnosticStatus struct {
	Phase       Phase  `json:"phase"`
	Reason      Reason `json:"reason"`
	ServiceCode uint32 `json:"serviceSpecificExitCode"`
}

func diagnosticStatus(phase Phase, reason Reason) DiagnosticStatus {
	p, phaseOK := phaseID(phase)
	r, reasonOK := reasonID(reason)
	if !phaseOK || !reasonOK {
		return DiagnosticStatus{PhaseUnknown, ReasonUnknown, 1000}
	}
	// The range reserves 100 reason IDs per phase. Every error is nonzero;
	// unknown/unknown is 1000. A successful stop is represented only by nil.
	return DiagnosticStatus{phase, reason, 1000 + 100*p + r}
}

func (d DiagnosticStatus) sanitized() DiagnosticStatus {
	if d == (DiagnosticStatus{}) {
		return d
	}
	return diagnosticStatus(d.Phase, d.Reason)
}

func (d DiagnosticStatus) String() string {
	d = d.sanitized()
	return "windows_service phase=" + string(d.Phase) + " reason=" + string(d.Reason) + " service_code=" + strconv.FormatUint(uint64(d.ServiceCode), 10)
}

// Format also protects %#v and %+v: reflection must never reveal an error's
// private cause. Width and precision are deliberately ignored to bound output.
func (d DiagnosticStatus) Format(s fmt.State, verb rune) { formatDiagnostic(s, verb, d.String()) }
func (d DiagnosticStatus) GoString() string              { return d.String() }
func (d DiagnosticStatus) MarshalJSON() ([]byte, error) {
	type plain DiagnosticStatus
	return json.Marshal(plain(d.sanitized()))
}

type diagnosticError struct {
	status DiagnosticStatus
	cause  error
}

// Mark labels an error without formatting its cause. The cause is retained only
// for errors.Is/errors.As and cancellation; callers must not log the unwrapped
// error. A nil cause remains nil. Invalid labels become unknown/unknown.
func Mark(phase Phase, reason Reason, cause error) error {
	if cause == nil {
		return nil
	}
	return &diagnosticError{diagnosticStatus(phase, reason), cause}
}

func (e *diagnosticError) safeStatus() DiagnosticStatus {
	if e == nil {
		return diagnosticStatus(PhaseUnknown, ReasonUnknown)
	}
	return e.status.sanitized()
}

func (e *diagnosticError) Error() string    { return e.safeStatus().String() }
func (e *diagnosticError) GoString() string { return e.Error() }
func (e *diagnosticError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
func (e *diagnosticError) Format(s fmt.State, verb rune) { formatDiagnostic(s, verb, e.Error()) }
func (e *diagnosticError) MarshalJSON() ([]byte, error)  { return e.safeStatus().MarshalJSON() }

func formatDiagnostic(s fmt.State, verb rune, text string) {
	if verb == 'q' {
		text = strconv.Quote(text)
	}
	_, _ = io.WriteString(s, text)
}

// Describe extracts only a trusted finite label. It never calls Error, Format,
// or a third-party As method. Wrapped and joined errors are searched with a
// fixed budget so a cyclic or oversized error chain cannot block diagnostics.
// Raw, unknown errors fail closed; they never become an operator-facing string.
func Describe(err error) (result DiagnosticStatus) {
	if err == nil {
		return DiagnosticStatus{}
	}
	result = diagnosticStatus(PhaseUnknown, ReasonUnknown)
	defer func() {
		if recover() != nil {
			result = diagnosticStatus(PhaseUnknown, ReasonUnknown)
		}
	}()
	const maxErrors = 64
	pending := []error{err}
	for budget := maxErrors; len(pending) > 0 && budget > 0; budget-- {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		if marked, ok := current.(*diagnosticError); ok {
			return marked.safeStatus()
		}
		if result.Phase == PhaseUnknown && result.Reason == ReasonUnknown {
			switch current {
			case ErrUnsupported:
				result = diagnosticStatus(PhaseLifecycle, ReasonUnsupportedPlatform)
			case ErrUnsafeIdentity:
				result = diagnosticStatus(PhaseRuntimeIdentity, ReasonIdentityRejected)
			case ErrRuntimeReadAccess:
				result = diagnosticStatus(PhaseRuntimeInstallation, ReasonRuntimeReadDenied)
			case ErrUnsafePath:
				result = diagnosticStatus(PhaseRuntimeInstallation, ReasonUnsafePath)
			case ErrMismatch, ErrNotInstalled:
				result = diagnosticStatus(PhaseRuntimeInstallation, ReasonInvalidConfiguration)
			case ErrExisting:
				result = diagnosticStatus(PhaseSetup, ReasonInvalidConfiguration)
			case ErrNotStopped:
				result = diagnosticStatus(PhaseLifecycle, ReasonInvalidConfiguration)
			case context.Canceled, context.DeadlineExceeded:
				result = diagnosticStatus(PhaseLifecycle, ReasonInterrupted)
			}
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			capacity := budget - 1 - len(pending)
			if capacity > len(children) {
				capacity = len(children)
			}
			if capacity > 0 {
				pending = append(pending, children[:capacity]...)
			}
		}
	}
	return result
}

// Diagnostic is the concise CLI counterpart to Describe.
func Diagnostic(err error) DiagnosticStatus { return Describe(err) }

// ServiceExitCode returns zero only for nil, which includes an orderly worker
// cancellation already normalized by runLifecycle. Other cancellations remain
// failures; this function cannot infer whether a service stop was requested.
func ServiceExitCode(err error) uint32 { return Describe(err).ServiceCode }
