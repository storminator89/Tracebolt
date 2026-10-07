package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
)

// Worker marks ready only after local runtime initialization has succeeded.
// Ready means the loop can receive controls, not that enrollment is approved or
// a report arrived. A worker MUST return after ctx cancellation, without spawning
// uncancelled background work. There is no interactive input in an SCM worker.
type Worker func(ctx context.Context, ready func()) error

type control uint8

const (
	controlInterrogate control = iota
	controlStop
	controlShutdown
)

type status struct {
	State                      State
	AcceptStop, AcceptShutdown bool
	CheckPoint, WaitHint       uint32
}

// runLifecycle is shared with platform-neutral, completely injected fixtures.
// It reports stopped only after the worker exits. Checkpoints are not fabricated
// by a timer: a blocked shutdown stays pending rather than pretending progress.
func runLifecycle(parent context.Context, worker Worker, controls <-chan control, report func(status)) error {
	current := status{State: StartPending, CheckPoint: 1, WaitHint: 30000}
	report(current)
	if worker == nil {
		report(status{State: Stopped})
		return errors.New("missing Windows service worker")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	readySignal := make(chan struct{})
	var ready <-chan struct{} = readySignal
	done := make(chan error, 1)
	var once sync.Once
	go func() { done <- worker(ctx, func() { once.Do(func() { close(readySignal) }) }) }()
	stopping := false
	canceled := parent.Done()
	stop := func() {
		if !stopping {
			stopping = true
			ready = nil
			canceled = nil
			current = status{State: StopPending, CheckPoint: 1, WaitHint: 30000}
			report(current)
			cancel()
		}
	}
	for {
		select {
		case <-canceled:
			stop()
		case <-ready:
			ready = nil
			if ctx.Err() != nil {
				stop()
				continue
			}
			current = status{State: Running, AcceptStop: true, AcceptShutdown: true}
			report(current)
		case command, ok := <-controls:
			if !ok {
				controls = nil
				stop()
				continue
			}
			switch command {
			case controlStop, controlShutdown:
				stop()
			case controlInterrogate:
				report(current)
			}
		case err := <-done:
			// Cancellation and worker completion may become ready together.
			if !stopping && parent.Err() != nil {
				stop()
			}
			// A success return without a stop is still an unexpected service exit.
			if !stopping {
				if err == nil {
					err = errors.New("Windows service worker exited unexpectedly")
				}
				current = status{State: StopPending, CheckPoint: 1, WaitHint: 30000}
				report(current)
			}
			report(status{State: Stopped})
			if stopping && onlyOrderlyCancellation(err) {
				return nil
			}
			return err
		}
	}
}

type identityGroup struct {
	SID      string
	Enabled  bool
	Owner    bool
	DenyOnly bool
}
type runtimeIdentity struct {
	UserSID             string
	Groups              []identityGroup
	UnexpectedPrivilege bool
}

func validateIdentity(i runtimeIdentity, expectedSID string) error {
	if i.UserSID != LocalServiceSID || !validServiceSID(expectedSID) || i.UnexpectedPrivilege {
		return ErrUnsafeIdentity
	}
	found := false
	for _, g := range i.Groups {
		if g.SID == "S-1-5-32-544" && g.Enabled && !g.DenyOnly {
			return ErrUnsafeIdentity
		}
		if g.SID == expectedSID && g.Enabled && g.Owner && !g.DenyOnly {
			found = true
		}
	}
	if !found {
		return ErrUnsafeIdentity
	}
	return nil
}

// Runtime cannot read the administrator-only ownership receipt. It instead
// checks the fixed installed configuration and public hash marker, its actual
// image path, and SCM's process identity when that status is valid. This is not permission to adopt/manage
// a service: control APIs still require the protected receipt.
func validateRuntimeInstallation(l Layout, snapshot Snapshot, executable, digest string, processID uint32) error {
	// QueryServiceStatusEx documents an invalid/unspecified PID during startup:
	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
	// The SCM dispatcher and service-SID token establish the starting identity.
	if !snapshot.Exists || processID == 0 || (snapshot.State == Running && snapshot.ProcessID != processID) || (snapshot.State != StartPending && snapshot.State != Running) || !strings.EqualFold(executable, l.Executable) || !validServiceSID(snapshot.ServiceSID) {
		return ErrMismatch
	}
	description := strings.TrimPrefix(snapshot.Configuration.Description, descriptionPrefix)
	if description == snapshot.Configuration.Description {
		return ErrMismatch
	}
	id, registeredDigest, found := strings.Cut(description, "; executable-sha256=")
	if !found || !validHex(id, 16) || !validHex(registeredDigest, 32) || digest != registeredDigest || !reflect.DeepEqual(snapshot.Configuration, configuration(l, id, registeredDigest)) {
		return ErrMismatch
	}
	return nil
}

// Stop must not turn a diagnosed failure, or a failure joined with cancellation,
// into success. Only an exclusively canceled error chain is an orderly exit.
func onlyOrderlyCancellation(err error) (ok bool) {
	if err == nil {
		return false
	}
	d := Describe(err)
	if d.Phase != PhaseUnknown && d.Reason != ReasonInterrupted {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	queue := []error{err}
	for budget := 64; len(queue) > 0 && budget > 0; budget-- {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			return false
		}
		if current == context.Canceled {
			continue
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() error }:
			next := wrapped.Unwrap()
			if next == nil {
				return false
			}
			queue = append(queue, next)
		case interface{ Unwrap() []error }:
			next := wrapped.Unwrap()
			if len(next) == 0 || len(next) > budget-len(queue) {
				return false
			}
			queue = append(queue, next...)
		default:
			return false
		}
	}
	return len(queue) == 0
}
