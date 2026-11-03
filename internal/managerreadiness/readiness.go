// Package managerreadiness describes bounded, read-only runtime evidence. It
// neither starts workers nor grants authority or native/release acceptance.
package managerreadiness

import (
	"sync"
	"time"
)

const SchemaVersion = "tracebolt.manager-readiness.v1"

type Component struct {
	Component string     `json:"component"`
	State     string     `json:"state"`
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
}

type View struct {
	SchemaVersion string      `json:"schemaVersion"`
	Scope         string      `json:"scope"`
	Status        string      `json:"status"`
	ServerNow     time.Time   `json:"serverNow"`
	Components    []Component `json:"components"`
	Unassessed    []string    `json:"unassessed"`
}

// NewView does not equate a running process, disabled component, or unavailable
// evidence with readiness. Ready covers only the named components in this view.
func NewView(now time.Time, components []Component) View {
	v := View{SchemaVersion: SchemaVersion, Scope: "core_reads_and_last_worker_steps", Status: "ready", ServerNow: now.UTC(), Components: components, Unassessed: []string{"full_store_integrity", "write_capacity_and_durability", "complete_maintenance_sweep", "optional_provider_workers", "native_and_release_acceptance"}}
	if len(components) == 0 {
		v.Status = "unavailable"
	}
	for _, c := range components {
		if c.State != "ready" && c.State != "succeeded" && c.State != "not_configured" {
			v.Status = "unavailable"
		}
	}
	return v
}

// Worker records completion of the existing loop's own evaluation. A Start,
// absence of warnings, or reading Snapshot never creates successful evidence.
// Errors are retained only as a boolean, not potentially private source text.
type Worker struct {
	mu       sync.Mutex
	maxAge   time.Duration
	running  bool
	finished time.Time
	failed   bool
}

func NewWorker(maxAge time.Duration) *Worker { return &Worker{maxAge: maxAge} }
func (w *Worker) Start() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running, w.failed, w.finished = true, false, time.Time{}
}
func (w *Worker) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running = false
}
func (w *Worker) Complete(at time.Time, err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	if !w.finished.IsZero() && at.Before(w.finished) {
		w.failed = true
		return
	}
	w.finished, w.failed = at.UTC(), err != nil
}
func (w *Worker) Snapshot(name string, now time.Time) Component {
	c := Component{Component: name, State: "not_configured"}
	if w == nil {
		return c
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	c.State = "stopped"
	if !w.finished.IsZero() {
		at := w.finished
		c.CheckedAt = &at
	}
	if !w.running {
		return c
	}
	c.State = "starting"
	if w.finished.IsZero() {
		return c
	}
	switch {
	case w.finished.After(now), w.maxAge <= 0, now.Sub(w.finished) > w.maxAge:
		c.State = "stale"
	case w.failed:
		c.State = "failed"
	default:
		c.State = "ready"
	}
	return c
}
