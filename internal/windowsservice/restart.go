package windowsservice

import (
	"context"
	"errors"
	"reflect"
	"time"
)

var ErrRestartState = errors.New("restart requires the owned service to be running with no transition pending")

// LifecycleLease is the coordinator's already-open protected installer store.
// It must stay exclusively held from receipt decoding through completion and
// handle closure. Verify must recheck the same store, never reopen or repair it.
// The receipt is ownership evidence, not permission to acquire new privileges.
type LifecycleLease interface{ Verify() error }

// RestartResult describes observations and individual requests, not health,
// telemetry delivery, a new process identity, or operating-system boot proof.
// Attempted remains true on an ambiguous native error; Requested means only
// that the native control returned success. LastObservedState is historical.
type RestartResult struct {
	Outcome           string `json:"outcome"`
	Phase             string `json:"phase"`
	StopAttempted     bool   `json:"stopAttempted"`
	StopRequested     bool   `json:"stopRequested"`
	StoppedObserved   bool   `json:"stoppedObserved"`
	StartAttempted    bool   `json:"startAttempted"`
	StartRequested    bool   `json:"startRequested"`
	RunningObserved   bool   `json:"runningObserved"`
	LastObservedState State  `json:"lastObservedState,omitempty"`
	Observations      int    `json:"observations"`
	StateRetained     bool   `json:"stateRetained"`
}

// RestartTimeout is the fixed cooperative public command budget, including
// receipt acquisition and final lease release. It is not a native-call timeout.
const RestartTimeout = restartBudget

const (
	restartBudget          = 45 * time.Second
	restartPoll            = 250 * time.Millisecond
	restartMaxObservations = 184
)

type restartClock struct {
	now  func() time.Time
	wait func(context.Context, time.Duration) error
}

// ApplyRestart is an explicit local own-agent operation. It never starts an
// initially stopped/pending service or accepts a target/name/path argument.
// Polling and subsequent effects have a fixed cooperative budget. Windows SCM
// calls are synchronous and cannot be interrupted here: a late return fails
// closed after the call returns, without abandoning a goroutine or releasing
// the lease while an effect might still be executing. No control is retried.
func ApplyRestart(ctx context.Context, r Receipt, lease LifecycleLease) (RestartResult, error) {
	return restart(ctx, nativeBackend(), r, lease, restartClock{time.Now, func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}})
}

func restart(ctx context.Context, b backend, r Receipt, lease LifecycleLease, clock restartClock) (result RestartResult, err error) {
	result = RestartResult{Outcome: "not-requested", Phase: "validate", StateRetained: true}
	if ctx == nil || b == nil || lease == nil || clock.now == nil || clock.wait == nil {
		return result, ErrMismatch
	}
	started := clock.now()
	deadline := started.Add(restartBudget)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		now := clock.now()
		if now.Before(started) || !now.Before(deadline) {
			return context.DeadlineExceeded
		}
		return nil
	}
	// Includes final native close and prevents late results being called complete.
	defer func() {
		checkErr := check()
		if checkErr != nil && err == nil {
			result.Phase = "final-context"
		}
		err = errors.Join(err, checkErr)
		if err != nil && (result.StopAttempted || result.StartAttempted) {
			result.Outcome = "intervention-required"
		}
	}()
	if err = check(); err != nil {
		return result, err
	}
	result.Phase = "receipt"
	if err = lease.Verify(); err != nil {
		return result, err
	}
	if err = check(); err != nil {
		return result, err
	}
	l, err := b.Layout()
	if err != nil {
		return result, err
	}
	if err = check(); err != nil {
		return result, err
	}
	expected := configuration(l, r.InstallationID, r.ExecutableSHA256)
	if r.Version != 1 || !r.Complete || r.Layout != l || !validHex(r.InstallationID, 16) || !validHex(r.ExecutableSHA256, 32) || !validServiceSID(r.ServiceSID) || r.ConfigurationSHA256 != digestConfig(expected) {
		return result, ErrMismatch
	}
	result.Phase = "open"
	s, err := b.Open(restartAccess)
	if s != nil {
		defer func() {
			if e := s.Close(); e != nil {
				if err == nil {
					result.Phase = "close"
				}
				err = errors.Join(err, e)
			}
		}()
	}
	if err != nil {
		return result, err
	}
	if s == nil {
		return result, ErrMismatch
	}
	observe := func() (State, error) {
		if e := check(); e != nil {
			return 0, e
		}
		if result.Observations >= restartMaxObservations {
			return 0, context.DeadlineExceeded
		}
		result.Observations++
		snapshot, e := s.Inspect()
		if e != nil {
			return 0, e
		}
		if e = check(); e != nil {
			return 0, e
		}
		if !snapshot.Exists || snapshot.ServiceSID != r.ServiceSID || !reflect.DeepEqual(snapshot.Configuration, expected) {
			return 0, ErrMismatch
		}
		// QueryServiceStatusEx only supplies a meaningful PID for Running here.
		// Do not compare PIDs across restart (reuse is possible), and do not
		// infer process identity from a stopped or pending snapshot.
		if snapshot.State == Running && snapshot.ProcessID == 0 {
			return 0, ErrMismatch
		}
		result.LastObservedState = snapshot.State
		return snapshot.State, nil
	}
	verify := func() error {
		if e := check(); e != nil {
			return e
		}
		if e := lease.Verify(); e != nil {
			return e
		}
		if e := check(); e != nil {
			return e
		}
		hash, e := b.VerifyExecutable(l)
		if e != nil {
			return e
		}
		if hash != r.ExecutableSHA256 {
			return ErrMismatch
		}
		return check()
	}
	result.Phase = "initial-observe"
	state, err := observe()
	if err != nil {
		return result, err
	}
	if state != Running {
		return result, ErrRestartState
	}
	result.Phase = "pre-stop"
	if err = verify(); err != nil {
		return result, err
	}
	// Observe again after potentially slow executable validation, using the same
	// handle, before attempting a control. Foreign privileged actors remain out of
	// the lease's threat model; SCM provides no conditional compare-and-control.
	state, err = observe()
	if err != nil {
		return result, err
	}
	if state != Running {
		return result, ErrRestartState
	}
	result.Phase = "stop"
	if err = check(); err != nil {
		return result, err
	}
	result.StopAttempted = true
	if err = s.Stop(); err != nil {
		return result, err
	}
	result.StopRequested = true
	waitFor := func(target, pending, previous State) error {
		for {
			state, e := observe()
			if e != nil {
				return e
			}
			if state == target {
				return nil
			}
			if state != pending && state != previous {
				return ErrRestartState
			}
			if e = check(); e != nil {
				return e
			}
			delay := deadline.Sub(clock.now())
			if delay > restartPoll {
				delay = restartPoll
			}
			if delay <= 0 {
				return context.DeadlineExceeded
			}
			if e = clock.wait(ctx, delay); e != nil {
				return e
			}
		}
	}
	result.Phase = "stop-observe"
	if err = waitFor(Stopped, StopPending, Running); err != nil {
		return result, err
	}
	result.StoppedObserved = true
	result.Phase = "pre-start"
	if err = verify(); err != nil {
		return result, err
	}
	state, err = observe()
	if err != nil {
		return result, err
	}
	if state != Stopped {
		return result, ErrRestartState
	}
	result.Phase = "start"
	if err = check(); err != nil {
		return result, err
	}
	result.StartAttempted = true
	if err = s.Start(); err != nil {
		return result, err
	}
	result.StartRequested = true
	result.Phase = "start-observe"
	if err = waitFor(Running, StartPending, Stopped); err != nil {
		return result, err
	}
	result.RunningObserved = true
	result.Phase = "final-verify"
	if err = verify(); err != nil {
		return result, err
	}
	// A final same-handle observation follows hashing, so an already stopped or
	// drifted service cannot be reported as running solely from the earlier read.
	state, err = observe()
	if err != nil {
		return result, err
	}
	if state != Running {
		return result, ErrRestartState
	}
	result.Outcome = "running-observed"
	result.Phase = "complete"
	return result, nil
}
