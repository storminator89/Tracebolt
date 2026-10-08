package main

import (
	"context"
	"fmt"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"syscall"
)

// setupFailure adds memory-only location metadata. It deliberately preserves the
// underlying public error text, identity and diagnostic chain. No caller-supplied
// text is used as metadata; the acceptance-only decoder independently allowlists
// every stage/category pair before retaining it.
type setupFailure struct {
	stage, category string
	cause           error
	first           bool
}

func (e *setupFailure) Error() string    { return e.cause.Error() }
func (e *setupFailure) Unwrap() error    { return e.cause }
func (e *setupFailure) GoString() string { return e.Error() }
func (e *setupFailure) Format(s fmt.State, verb rune) {
	if verb == 'q' {
		fmt.Fprintf(s, "%q", e.Error())
		return
	}
	fmt.Fprint(s, e.Error())
}
func setupFailed(stage string, err error) error {
	return setupFailedCategory(stage, setupCauseCategory(err), err)
}
func setupFailedCategory(stage, category string, err error) error {
	if err == nil {
		err = errLifecycle
	}
	if stage, _ := setupFailureDiagnostic(err); stage != "unknown" {
		return err
	}
	return &setupFailure{stage: stage, category: category, cause: err}
}

// A bounded, panic-contained walk never calls arbitrary Error/Is/As methods.
func setupErrorChain(err error) (chain []error, valid bool) {
	defer func() {
		if recover() != nil {
			chain, valid = nil, false
		}
	}()
	pending := []error{err}
	for len(pending) > 0 {
		if len(chain) >= 32 {
			return nil, false
		}
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == nil {
			continue
		}
		chain = append(chain, current)
		switch e := current.(type) {
		case interface{ Unwrap() []error }:
			children := e.Unwrap()
			if len(children) > 32-len(chain)-len(pending) {
				return nil, false
			}
			pending = append(pending, children...)
		case interface{ Unwrap() error }:
			pending = append(pending, e.Unwrap())
		}
	}
	return chain, true
}
func setupFailureDiagnostic(err error) (string, string) {
	chain, valid := setupErrorChain(err)
	if valid {
		for _, current := range chain {
			if failure, ok := current.(*setupFailure); ok {
				return failure.stage, failure.category
			}
		}
	}
	return "unknown", "unknown"
}

// Only identity-based sentinels are inspected. Error text and native numbers are
// never used; an unrecognized cause is the finite failed category.
func setupCauseCategory(err error) string {
	chain, valid := setupErrorChain(err)
	if !valid {
		return "failed"
	}
	for _, current := range chain {
		is := func(target error) bool { return current == target }
		if errno, ok := current.(syscall.Errno); ok && errno.Is(os.ErrPermission) {
			return "access_denied"
		}
		switch {
		case is(context.Canceled), is(context.DeadlineExceeded):
			return "interrupted"
		case is(os.ErrPermission):
			return "access_denied"
		case is(os.ErrNotExist):
			return "not_found"
		case is(windowsstate.ErrUnsupported):
			return "unsupported"
		case is(windowsstate.ErrPolicy):
			return "state_policy"
		case is(windowsstate.ErrIntegrity):
			return "state_integrity"
		case is(windowsstate.ErrStorage):
			return "state_storage"
		case is(windowsstate.ErrPoisoned):
			return "state_poisoned"
		case is(windowsstate.ErrClosed):
			return "state_closed"
		case is(enrollmentclient.ErrBootstrap):
			return "enrollment_bootstrap"
		case is(enrollmentclient.ErrState):
			return "enrollment_state"
		case is(enrollmentclient.ErrLocked):
			return "enrollment_locked"
		case is(enrollmentclient.ErrResponse):
			return "enrollment_response"
		case is(enrollmentclient.ErrTransport):
			return "enrollment_transport"
		case is(enrollmentclient.ErrInvitation):
			return "enrollment_invitation"
		case is(enrollmentclient.ErrTerminal):
			return "enrollment_terminal"
		case is(enrollmentclient.ErrInput):
			return "enrollment_input"
		case is(enrollmentclient.ErrServiceDeadline):
			return "enrollment_deadline"
		}
	}
	return "failed"
}

// A mandatory receipt encode/write can fail after apply already failed. Keep
// that first failure's finite location, but retain only the historical receipt
// error as the cause; the first error's text/native data never becomes output.
func setupFirstInstallFailure(first, returned error) error {
	if first == nil {
		return returned
	}
	stage, category := windowsservice.SetupDiagnostic(first)
	if stage == "unknown" {
		stage, category = setupFailureDiagnostic(first)
	}
	if stage == "unknown" {
		stage, category = "service_install", setupCauseCategory(first)
	}
	return &setupFailure{stage: stage, category: category, cause: returned, first: true}
}

func setupFirstFailureDiagnostic(err error) (string, string) {
	chain, valid := setupErrorChain(err)
	if valid {
		for _, current := range chain {
			if failure, ok := current.(*setupFailure); ok && failure.first {
				return failure.stage, failure.category
			}
		}
	}
	return "unknown", "unknown"
}
