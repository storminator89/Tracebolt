package setupgate

// ChooserClickFailureStages contains only finite branch labels for the two
// observed chooser clicks. No native handles, geometry or callback errors leave
// this sequence.
var ChooserClickFailureStages = []string{
	"chooser-click-control", "chooser-click-enabled", "chooser-click-dpi-set",
	"chooser-click-visible", "chooser-click-root", "chooser-click-not-iconic",
	"chooser-click-control-rect", "chooser-click-client-rect",
	"chooser-click-client-top-left", "chooser-click-client-bottom-right",
	"chooser-click-monitor", "chooser-click-monitor-info",
	"chooser-click-client-contained", "chooser-click-work-contained",
	"chooser-click-dpi-restore", "chooser-click-post",
	"chooser-open-control", "chooser-open-enabled", "chooser-open-dpi-set",
	"chooser-open-visible", "chooser-open-root", "chooser-open-not-iconic",
	"chooser-open-control-rect", "chooser-open-client-rect",
	"chooser-open-client-top-left", "chooser-open-client-bottom-right",
	"chooser-open-monitor", "chooser-open-monitor-info",
	"chooser-open-client-contained", "chooser-open-work-contained",
	"chooser-open-dpi-restore", "chooser-open-post",
}

func clickPrefix(prefix string) bool {
	return prefix == "chooser-click" || prefix == "chooser-open"
}

type ClickSteps struct {
	Control, Enabled, Post func() bool
	Visibility             func() error
}

// CheckClick preserves the native driver's short circuit: look up the control,
// check enabled state, finish all visibility checks and DPI cleanup, then post
// one BM_CLICK. It never retries, waits, or exposes a callback error.
func CheckClick(stage func(string), prefix string, s ClickSteps) error {
	if stage == nil || !clickPrefix(prefix) || s.Control == nil || s.Enabled == nil || s.Visibility == nil || s.Post == nil {
		return ErrGuard
	}
	stage(prefix + "-control")
	if !s.Control() {
		return ErrGuard
	}
	stage(prefix + "-enabled")
	if !s.Enabled() {
		return ErrGuard
	}
	if s.Visibility() != nil {
		return ErrGuard
	}
	stage(prefix + "-post")
	if !s.Post() {
		return ErrGuard
	}
	return nil
}

type ClickVisibilitySteps struct {
	LockThread, UnlockThread                                  func()
	SetDPI, RestoreDPI, Visible, Root, NotIconic              func() bool
	ControlRect, ClientRect, ClientTopLeft, ClientBottomRight func() bool
	Monitor, MonitorInfo, ClientContained, WorkContained      func() bool
}

// CheckClickVisibility runs the original geometry guards in order on one locked
// OS thread. DPI restoration still fails the operation, but cannot replace an
// earlier failed guard's label. Cleanup finishes before CheckClick may post.
func CheckClickVisibility(stage func(string), prefix string, s ClickVisibilitySteps) (err error) {
	if stage == nil || !clickPrefix(prefix) || s.LockThread == nil || s.UnlockThread == nil || s.SetDPI == nil || s.RestoreDPI == nil {
		return ErrGuard
	}
	checks := []struct {
		suffix string
		run    func() bool
	}{
		{"visible", s.Visible}, {"root", s.Root}, {"not-iconic", s.NotIconic},
		{"control-rect", s.ControlRect}, {"client-rect", s.ClientRect},
		{"client-top-left", s.ClientTopLeft}, {"client-bottom-right", s.ClientBottomRight},
		{"monitor", s.Monitor}, {"monitor-info", s.MonitorInfo},
		{"client-contained", s.ClientContained}, {"work-contained", s.WorkContained},
	}
	for _, check := range checks {
		if check.run == nil {
			return ErrGuard
		}
	}
	s.LockThread()
	defer s.UnlockThread()
	stage(prefix + "-dpi-set")
	if !s.SetDPI() {
		return ErrGuard
	}
	defer func() {
		if !s.RestoreDPI() && err == nil {
			stage(prefix + "-dpi-restore")
			err = ErrGuard
		}
	}()
	for _, check := range checks {
		stage(prefix + "-" + check.suffix)
		if !check.run() {
			return ErrGuard
		}
	}
	return nil
}
