package setupgate

import "time"

// InitialChooserFailureStages are failure-only diagnostics for current-profile
// initial discovery/readiness. They contain no handles, geometry or API errors.
var InitialChooserFailureStages = []string{
	"initial-chooser-attempt", "initial-chooser-context", "initial-chooser-process",
	"initial-chooser-deadline", "initial-chooser-discovery", "initial-chooser-identity",
	"initial-chooser-ready", "initial-chooser-post",
}

// InitialChooserIdentity pins the owned process, root, chooser and actual GUI
// thread. Native observers must also reject invalid handles and broken ancestry.
type InitialChooserIdentity struct {
	Process, Thread uint32
	Root, Control   uintptr
}

func (i InitialChooserIdentity) valid(pid uint32) bool {
	return pid != 0 && i.Process == pid && i.Thread != 0 && i.Root != 0 && i.Control != 0 && i.Root != i.Control
}

type InitialChooserSteps struct {
	Now               func() time.Time
	Canceled, Process func() bool
	Wait              func(time.Duration) error
	// Only an all-zero identity with no error denotes pre-discovery absence.
	Discover   func() (InitialChooserIdentity, error)
	Observe    func() (InitialChooserIdentity, bool, error)
	Visibility func(func(string)) error
	Post       func() bool
}

// InitialChooser shares one absolute launch deadline across discovery, readiness
// and the first click. Neither failed discovery nor a failed click can be retried.
// It is owned by the serial native controller, not a concurrent API.
type InitialChooser struct {
	deadline                              time.Time
	pid                                   uint32
	steps                                 InitialChooserSteps
	identity                              InitialChooserIdentity
	discoveryAttempted, discovered, spent bool
}

func NewInitialChooser(deadline time.Time, pid uint32, steps InitialChooserSteps) *InitialChooser {
	return &InitialChooser{deadline: deadline, pid: pid, steps: steps}
}

func (c *InitialChooser) configured(stage func(string)) bool {
	return c != nil && stage != nil && !c.deadline.IsZero() && c.pid != 0 &&
		c.steps.Now != nil && c.steps.Canceled != nil && c.steps.Process != nil && c.steps.Wait != nil &&
		c.steps.Discover != nil && c.steps.Observe != nil && c.steps.Visibility != nil && c.steps.Post != nil
}

func (c *InitialChooser) guard(stage func(string)) error {
	stage("initial-chooser-context")
	if c.steps.Canceled() {
		return ErrGuard
	}
	stage("initial-chooser-process")
	if !c.steps.Process() {
		return ErrGuard
	}
	stage("initial-chooser-deadline")
	if !c.steps.Now().Before(c.deadline) {
		return ErrGuard
	}
	return nil
}

func (c *InitialChooser) pause(stage func(string)) error {
	if c.guard(stage) != nil {
		return ErrGuard
	}
	remaining := c.deadline.Sub(c.steps.Now())
	if remaining <= 0 {
		return ErrGuard
	}
	if remaining > 100*time.Millisecond {
		remaining = 100 * time.Millisecond
	}
	stage("initial-chooser-context")
	if c.steps.Wait(remaining) != nil {
		return ErrGuard
	}
	return nil
}

func (c *InitialChooser) Discover(stage func(string)) (err error) {
	if c == nil {
		return ErrGuard
	}
	defer func() {
		if err != nil {
			c.spent = true
		}
	}()
	attempted := c.discoveryAttempted
	c.discoveryAttempted = true
	if !c.configured(stage) {
		return ErrGuard
	}
	stage("initial-chooser-attempt")
	if attempted || c.spent {
		return ErrGuard
	}
	for {
		if c.guard(stage) != nil {
			return ErrGuard
		}
		stage("initial-chooser-discovery")
		identity, err := c.steps.Discover()
		if err != nil {
			return ErrGuard
		}
		if identity != (InitialChooserIdentity{}) {
			stage("initial-chooser-identity")
			if !identity.valid(c.pid) {
				return ErrGuard
			}
			if c.guard(stage) != nil {
				return ErrGuard
			}
			c.identity, c.discovered = identity, true
			return nil
		}
		if c.pause(stage) != nil {
			return ErrGuard
		}
	}
}

func (c *InitialChooser) observe(stage func(string)) (bool, error) {
	stage("initial-chooser-identity")
	identity, enabled, err := c.steps.Observe()
	if err != nil || identity != c.identity || !identity.valid(c.pid) {
		return false, ErrGuard
	}
	return enabled, nil
}

func (c *InitialChooser) Click(stage func(string)) error {
	if c == nil {
		return ErrGuard
	}
	spent := c.spent
	c.spent = true // A failed attempt is spent too, including malformed inputs.
	if !c.configured(stage) {
		return ErrGuard
	}
	stage("initial-chooser-attempt")
	if spent || !c.discovered {
		return ErrGuard
	}
	for {
		if c.guard(stage) != nil {
			return ErrGuard
		}
		enabled, err := c.observe(stage)
		if err != nil {
			return ErrGuard
		}
		if c.guard(stage) != nil {
			return ErrGuard
		}
		if enabled {
			break
		}
		stage("initial-chooser-ready")
		if c.pause(stage) != nil {
			return ErrGuard
		}
	}
	// Preserve every existing visibility/geometry/DPI check. Polling never posts.
	if c.steps.Visibility(stage) != nil {
		return ErrGuard
	}
	if c.guard(stage) != nil {
		return ErrGuard
	}
	enabled, err := c.observe(stage)
	if err != nil {
		return ErrGuard
	}
	stage("initial-chooser-ready")
	if !enabled {
		return ErrGuard
	}
	// Observation and DPI cleanup can consume the remaining budget or observe
	// cancellation/exit. Recheck at the native post edge; there is no new timeout.
	if c.guard(stage) != nil {
		return ErrGuard
	}
	stage("initial-chooser-post")
	if !c.steps.Post() {
		return ErrGuard
	}
	return nil
}
