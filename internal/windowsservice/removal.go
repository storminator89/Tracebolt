package windowsservice

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// InspectRemoval observes removal after a successful ApplyUninstall. It requires
// the original completed receipt and reads SCM configuration, status and trusted
// executable bytes without mutation.
// A still-present service must retain the exact receipt-bound configuration and
// be stopped. Its ServiceSID is empty: name-to-SID lookup can cease to work while
// SCM deletion is still pending. This is not an identity check or authorization
// to mutate a service and must not replace InspectOwned or pre-delete checks.
// Only an absent service at Open is successful absence; all observation handles
// are closed before returning, and errors never establish removal completion.
func InspectRemoval(ctx context.Context, r Receipt) (Snapshot, error) {
	return inspectRemoval(ctx, nativeBackend(), r)
}

// removalInspector is deliberately separate from ordinary service inspection.
// It reads every supported configuration field and status without SID lookup.
type removalInspector interface {
	inspectRemoval() (Snapshot, error)
}

// CanWaitRemovalObservation reports whether this error came only from opening
// or querying SCM during InspectRemoval, with clean handle closure and no final
// context cancellation. A caller must also independently establish a single
// native marked-for-deletion cause before waiting. This predicate never makes
// other failures retryable, and caller-wrapped errors fail closed.
func CanWaitRemovalObservation(err error) bool {
	observation, ok := err.(*removalObservationError)
	return ok && observation != nil && observation.canWait
}

type removalObservationError struct {
	cause   error
	canWait bool
}

func (e *removalObservationError) Error() string { return e.cause.Error() }
func (e *removalObservationError) Format(s fmt.State, verb rune) {
	formatDiagnostic(s, verb, e.Error())
}
func (e *removalObservationError) GoString() string { return e.Error() }
func (e *removalObservationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func inspectRemoval(ctx context.Context, b backend, r Receipt) (result Snapshot, err error) {
	canWait := false
	// Registered first, so eligibility is sealed after every handle-close defer.
	defer func() {
		if contextErr := ctx.Err(); contextErr != nil {
			result = Snapshot{}
			canWait = false
			err = errors.Join(err, setupStageError("service_removal_context", "interrupted", contextErr))
		}
		if err != nil {
			err = &removalObservationError{cause: err, canWait: canWait}
		}
	}()
	if err = ctx.Err(); err != nil {
		return Snapshot{}, setupStageError("service_removal_context", "interrupted", err)
	}
	l, err := b.Layout()
	if err != nil {
		return Snapshot{}, setupStageError("service_removal_layout", "failed", err)
	}
	expected := configuration(l, r.InstallationID, r.ExecutableSHA256)
	if r.Version != 1 || !r.Complete || r.Layout != l || !validHex(r.InstallationID, 16) || !validHex(r.ExecutableSHA256, 32) || !validServiceSID(r.ServiceSID) || r.ConfigurationSHA256 != digestConfig(expected) {
		return Snapshot{}, setupStageError("service_removal_receipt", "mismatch", ErrMismatch)
	}
	// MS-SCMR RDeleteService sets Start to SERVICE_DISABLED before marking
	// Deleted. The receipt above still authenticates the original active
	// configuration; only post-delete observation expects this one transition.
	expected.StartType = 4
	if err = ctx.Err(); err != nil {
		return Snapshot{}, setupStageError("service_removal_context", "interrupted", err)
	}
	s, err := b.Open(readAccess)
	if s != nil {
		defer func() {
			if closeErr := s.Close(); closeErr != nil {
				result = Snapshot{}
				canWait = false
				err = errors.Join(err, setupStageError("service_removal_close", "failed", closeErr))
			}
		}()
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return Snapshot{}, setupStageError("service_removal_context", "interrupted", contextErr)
	}
	if removalOpenAbsent(err) && s == nil {
		return Snapshot{}, nil
	}
	if err != nil {
		canWait = true
		return Snapshot{}, setupStageError("service_removal_open", "failed", err)
	}
	reader, ok := s.(removalInspector)
	if !ok {
		return Snapshot{}, setupStageError("service_removal_reader", "missing", ErrMismatch)
	}
	snapshot, err := reader.inspectRemoval()
	if err != nil {
		canWait = true
		return Snapshot{}, setupStageError("service_removal_snapshot", "failed", err)
	}
	if !snapshot.Exists || !reflect.DeepEqual(snapshot.Configuration, expected) {
		return Snapshot{}, setupStageError("service_removal_binding", "mismatch", ErrMismatch)
	}
	if snapshot.State != Stopped {
		return Snapshot{}, setupStageError("service_removal_state", "not_stopped", ErrNotStopped)
	}
	if err = ctx.Err(); err != nil {
		return Snapshot{}, setupStageError("service_removal_context", "interrupted", err)
	}
	hash, err := b.VerifyExecutable(l)
	if err != nil {
		return Snapshot{}, setupStageError("service_removal_executable", "failed", err)
	}
	if hash != r.ExecutableSHA256 {
		return Snapshot{}, setupStageError("service_removal_hash", "changed", ErrMismatch)
	}
	return snapshot, nil
}

// Absence must be the sole cause returned by Open. An errors.Is match from a
// multi-error or custom matcher can hide another failure and is not proof that
// SCM reported the service missing. Bound malformed/cyclic unwrap chains.
func removalOpenAbsent(err error) (absent bool) {
	defer func() {
		if recover() != nil {
			absent = false
		}
	}()
	for depth := 0; err != nil && depth < 64; depth++ {
		if err == ErrNotInstalled {
			return true
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			return false
		case interface{ Unwrap() error }:
			err = wrapped.Unwrap()
		default:
			return false
		}
	}
	return false
}
