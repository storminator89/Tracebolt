package setupgate

import (
	"context"
	"time"
)

// InitialChooserFailureStages are finite test-controller diagnostics. No HWND,
// PID, timing value or callback error is included in acceptance evidence.
var InitialChooserFailureStages = []string{
	"chooser-ready-discovery", "chooser-ready-process", "chooser-ready-owned",
	"chooser-ready-enabled", "chooser-ready-deadline",
}

// InitialChooserBinding verifies the exact process/root/control pinned by the
// initial launch. Owned must reject missing, replaced or foreign windows; it
// must never reacquire them. The ordinary reopened wizard does not use this.
type InitialChooserBinding struct {
	Now          func() time.Time
	Alive, Owned func() bool
}

type InitialChooserSteps struct {
	InitialChooserBinding
	Discover func() (bool, error)
	Pin      func() bool
	Enabled  func() (bool, error)
	Wait     func(context.Context, time.Duration) error
}

func initialChooserBudget(ctx context.Context, deadline time.Time, stage func(string), now func() time.Time) error {
	if ctx.Err() != nil || !now().Before(deadline) {
		stage("chooser-ready-deadline")
		return ErrGuard
	}
	return nil
}

func checkInitialChooserBinding(ctx context.Context, deadline time.Time, stage func(string), s InitialChooserBinding) error {
	if initialChooserBudget(ctx, deadline, stage, s.Now) != nil {
		return ErrGuard
	}
	stage("chooser-ready-process")
	if !s.Alive() {
		return ErrGuard
	}
	stage("chooser-ready-owned")
	if !s.Owned() {
		return ErrGuard
	}
	return initialChooserBudget(ctx, deadline, stage, s.Now)
}

// AwaitInitialChooser shares one caller-supplied absolute deadline with window
// discovery. Only absence before the first discovery and a still-owned disabled
// chooser may wait. Pinning, process/API/ownership failures never retry, and this
// helper has no click callback. A successful return does not authorize a click.
func AwaitInitialChooser(ctx context.Context, deadline time.Time, stage func(string), s InitialChooserSteps) error {
	if ctx == nil || deadline.IsZero() || stage == nil || s.Now == nil || s.Alive == nil || s.Owned == nil || s.Discover == nil || s.Pin == nil || s.Enabled == nil || s.Wait == nil {
		return ErrGuard
	}
	wait := func() error {
		if initialChooserBudget(ctx, deadline, stage, s.Now) != nil {
			return ErrGuard
		}
		delay := deadline.Sub(s.Now())
		if delay > 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		if delay <= 0 {
			stage("chooser-ready-deadline")
			return ErrGuard
		}
		if s.Wait(ctx, delay) != nil {
			stage("chooser-ready-deadline")
			return ErrGuard
		}
		return nil
	}
	for {
		if initialChooserBudget(ctx, deadline, stage, s.Now) != nil {
			return ErrGuard
		}
		stage("chooser-ready-process")
		if !s.Alive() {
			return ErrGuard
		}
		stage("chooser-ready-discovery")
		found, err := s.Discover()
		if err != nil {
			return ErrGuard
		}
		if initialChooserBudget(ctx, deadline, stage, s.Now) != nil {
			return ErrGuard
		}
		if found {
			break
		}
		if wait() != nil {
			return ErrGuard
		}
	}
	stage("chooser-ready-owned")
	if !s.Pin() {
		return ErrGuard
	}
	for {
		if checkInitialChooserBinding(ctx, deadline, stage, s.InitialChooserBinding) != nil {
			return ErrGuard
		}
		stage("chooser-ready-enabled")
		enabled, err := s.Enabled()
		if err != nil {
			return ErrGuard
		}
		// IsWindowEnabled can report false for an invalid HWND. Revalidate before
		// treating that observation as a retryable disabled state (or as ready).
		if checkInitialChooserBinding(ctx, deadline, stage, s.InitialChooserBinding) != nil {
			return ErrGuard
		}
		if enabled {
			return nil
		}
		if wait() != nil {
			return ErrGuard
		}
	}
}

// InitialChooserAttempt spends its one initial click even when a guard fails.
// A caller may return to ordinary chooser behavior only after Click succeeds.
type InitialChooserAttempt struct{ spent bool }

// Click retains CheckClick's visibility/geometry/DPI guards
// and single post. Revalidate the pin and original launch deadline at entry and
// immediately before posting. Nothing here retries a click or waits again.
func (a *InitialChooserAttempt) Click(ctx context.Context, deadline time.Time, stage func(string), binding InitialChooserBinding, s ClickSteps) error {
	if a == nil || a.spent {
		return ErrGuard
	}
	a.spent = true
	if ctx == nil || deadline.IsZero() || stage == nil || binding.Now == nil || binding.Alive == nil || binding.Owned == nil || s.Control == nil || s.Enabled == nil || s.Visibility == nil || s.Post == nil {
		return ErrGuard
	}
	if checkInitialChooserBinding(ctx, deadline, stage, binding) != nil {
		return ErrGuard
	}
	post := s.Post
	s.Post = func() bool {
		if checkInitialChooserBinding(ctx, deadline, stage, binding) != nil {
			return false
		}
		stage("chooser-click-enabled")
		if !s.Enabled() {
			return false
		}
		if initialChooserBudget(ctx, deadline, stage, binding.Now) != nil {
			return false
		}
		stage("chooser-click-post")
		return post()
	}
	return CheckClick(stage, "chooser-click", s)
}

// InitialChooserWindows contains the handles and process ID captured once by
// the controller. The values stay internal and are never written to a report.
type InitialChooserWindows struct {
	Root, Control                  uintptr
	PID, RootThread, ControlThread uint32
}

type InitialChooserWindowSteps struct {
	Valid                 func(uintptr) bool
	Owner                 func(uintptr) (uint32, uint32, error)
	Root, Parent, Control func(uintptr) uintptr
}

// OwnsInitialChooser verifies the original pair only. A new root/control, even
// within the same process, is not an acceptable replacement for either pin.
func OwnsInitialChooser(w InitialChooserWindows, s InitialChooserWindowSteps) bool {
	if w.Root == 0 || w.Control == 0 || w.Root == w.Control || w.PID == 0 || w.RootThread == 0 || w.ControlThread == 0 || s.Valid == nil || s.Owner == nil || s.Root == nil || s.Parent == nil || s.Control == nil {
		return false
	}
	if !s.Valid(w.Root) || !s.Valid(w.Control) {
		return false
	}
	for _, pin := range []struct {
		h      uintptr
		thread uint32
	}{{w.Root, w.RootThread}, {w.Control, w.ControlThread}} {
		pid, thread, err := s.Owner(pin.h)
		if err != nil || pid != w.PID || thread != pin.thread {
			return false
		}
	}
	return s.Root(w.Root) == w.Root && s.Root(w.Control) == w.Root &&
		s.Parent(w.Control) == w.Root && s.Control(w.Root) == w.Control
}
