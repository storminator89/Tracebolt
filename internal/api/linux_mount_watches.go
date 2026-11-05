package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/linuxmountwatch"
	"localrmm/internal/store"
	"net/http"
	"strings"
	"time"
)

type linuxMountWatchSource interface {
	WithLinuxMountWatch(context.Context, string, *linuxmountwatch.Target, string, func(linuxmountwatch.Input, func(time.Time) error) error) error
}

func (h *operatorHandler) linuxMountWatchAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[4] != "mount-watch" || !enrollmentcrypto.ValidID(parts[3], "agent_") {
		fail(w, 404, "not_found", "Mount watch is unavailable.")
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method == "GET" && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		fail(w, 400, "invalid_request", "Mount watch does not accept queries or a read body.")
		return
	}
	owner, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authenticated operator is required.")
		return
	}
	can := !owner.session.Named()
	m := h.app.health
	if m == nil {
		fail(w, 409, "mount_watch_unavailable", "Mount watch is unavailable.")
		return
	}
	source, ok := m.source.(linuxMountWatchSource)
	if !ok {
		fail(w, 409, "mount_watch_unavailable", "Mount watch is unavailable.")
		return
	}
	var command *linuxmountwatch.Command
	if r.Method == "POST" {
		if !can {
			fail(w, 403, "operator_capability_required", "Shared administrator access is required.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		var body struct {
			RequestID             string `json:"requestId"`
			ExpectedRevision      uint64 `json:"expectedRevision,string"`
			SourceToken           string `json:"sourceToken"`
			Operation             string `json:"operation"`
			MountPoint            string `json:"mountPoint"`
			Filesystem            string `json:"filesystem"`
			FilesystemGroup       string `json:"filesystemGroup"`
			Threshold             int    `json:"threshold"`
			Recovery              int    `json:"recovery"`
			RetentionAcknowledged bool   `json:"retentionAcknowledged"`
			IncidentID            string `json:"incidentId"`
		}
		if !readObject(w, r, 8192, []string{"requestId", "expectedRevision", "sourceToken", "operation", "mountPoint", "filesystem", "filesystemGroup", "threshold", "recovery", "retentionAcknowledged", "incidentId"}, &body) {
			return
		}
		command = &linuxmountwatch.Command{RequestID: body.RequestID, ExpectedRevision: body.ExpectedRevision, SourceToken: body.SourceToken, Operation: body.Operation, Threshold: body.Threshold, Recovery: body.Recovery, RetentionAcknowledged: body.RetentionAcknowledged, IncidentID: body.IncidentID}
		if body.MountPoint != "" || body.Filesystem != "" || body.FilesystemGroup != "" {
			command.Target = &linuxmountwatch.Target{MountPoint: body.MountPoint, Filesystem: body.Filesystem, FilesystemGroup: body.FilesystemGroup}
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, e := m.store.LinuxMountWatchState(r.Context(), parts[3])
	if e != nil {
		mountWatchError(w, e)
		return
	}
	target := state.Policy.Target
	if command != nil && command.Operation == "enable" {
		target = command.Target
	}
	var out linuxmountwatch.View
	e = source.WithLinuxMountWatch(r.Context(), parts[3], target, h.app.csrf, func(in linuxmountwatch.Input, guard func(time.Time) error) error {
		checked := func(at time.Time) error {
			if owner.active == nil || !owner.active() {
				return store.ErrLinuxMountWatchSession
			}
			return guard(at)
		}
		next, now, e := m.store.UpdateLinuxMountWatches(r.Context(), in, command, false, m.source.Now, checked)
		if e != nil {
			return e
		}
		out = linuxmountwatch.Public(next, in, now, can)
		return checked(now)
	})
	if e != nil {
		mountWatchError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, out)
}
func mountWatchError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrLinuxMountWatchSession):
		fail(w, 401, "authentication_required", "Operator session ended.")
	case errors.Is(e, linuxmountwatch.ErrInvalid):
		fail(w, 400, "invalid_mount_watch", "Choose one eligible mount and valid thresholds.")
	case errors.Is(e, linuxmountwatch.ErrConflict), errors.Is(e, linuxmountwatch.ErrSource), errors.Is(e, store.ErrLimit):
		fail(w, 409, "mount_watch_conflict", "Mount watch changed or evidence is unavailable. Refresh before another action.")
	default:
		fail(w, 503, "mount_watch_unavailable", "Mount watch is unavailable. A write outcome may be uncertain; read status, never automatically retry.")
	}
}

// This independent local monitor never forwards incidents to Linux Health,
// alarms, AI, fleet groups or endpoint actions. Reads do not evaluate state.
func (s *Server) evaluateLinuxMountWatches(ctx context.Context, m *healthMonitor) error {
	source, ok := m.source.(linuxMountWatchSource)
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	states, e := m.store.LinuxMountWatchStates(ctx)
	if e != nil {
		return e
	}
	var first error
	for id, state := range states {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e = source.WithLinuxMountWatch(ctx, id, state.Policy.Target, s.csrf, func(in linuxmountwatch.Input, guard func(time.Time) error) error {
			_, _, e := m.store.UpdateLinuxMountWatches(ctx, in, nil, true, m.source.Now, guard)
			return e
		})
		if e != nil {
			// A bounded manager-local downgrade survives a source deadline. It never
			// enters an enrollment path or grants access to missing evidence.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			invalidation := m.store.InterruptLinuxMountWatch(cleanup, id)
			cancel()
			if invalidation != nil {
				e = errors.Join(e, invalidation)
			}
		}
		if first == nil && e != nil {
			first = e
		}
	}
	return first
}
