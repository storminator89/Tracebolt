package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"strings"
	"sync"
	"time"
)

type windowsCapacitySource interface {
	WindowsCapacityInputs(context.Context, time.Time) ([]windowscapacity.Input, error)
	Now() time.Time
}

type windowsCapacityMonitor struct {
	mu     sync.Mutex
	store  *store.Store
	source windowsCapacitySource
	// An unguessable, non-authorizing process epoch prevents restart or failed
	// evaluation from lending continuity to old transition timers.
	epoch string
	ready bool
}

func newWindowsCapacityMonitor(db *store.Store, source windowsCapacitySource) (*windowsCapacityMonitor, error) {
	m := &windowsCapacityMonitor{store: db, source: source}
	if err := m.resetEpoch(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *windowsCapacityMonitor) resetEpoch() error {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	m.epoch = hex.EncodeToString(raw[:])
	return nil
}

func windowsCapacityAuthority(inputs []windowscapacity.Input, now time.Time) (map[string]windowscapacity.Input, error) {
	contacts := make([]windowscontact.Input, 0, len(inputs))
	for _, in := range inputs {
		contacts = append(contacts, in.Input)
	}
	if _, err := windowsContactAuthority(contacts, now); err != nil {
		return nil, err
	}
	out := make(map[string]windowscapacity.Input, len(inputs))
	for _, in := range inputs {
		out[in.DeviceID] = in
	}
	return out, nil
}

func (m *windowsCapacityMonitor) evaluate(ctx context.Context) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if err != nil {
			m.ready = false
			m.epoch = ""
		}
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	if m.epoch == "" {
		if err = m.resetEpoch(); err != nil {
			return err
		}
	}
	if err = m.reconcileFleetMonitoring(ctx); err != nil {
		return err
	}
	states, err := m.store.WindowsCapacityStates(ctx)
	if err != nil {
		return err
	}
	resources, err := m.store.WindowsResourceStates(ctx)
	if err != nil {
		return err
	}
	services, err := m.store.WindowsServiceStates(ctx)
	if err != nil {
		return err
	}
	enabled := false
	for _, state := range states {
		if state.Policy.Enabled {
			enabled = true
			break
		}
	}
	for _, state := range resources {
		if state.Assessment.Policy.Enabled {
			enabled = true
			break
		}
	}
	for _, state := range services {
		if state.Policy.Enabled {
			enabled = true
			break
		}
	}
	if !enabled {
		m.ready = true
		return nil
	}
	now := m.source.Now().UTC()
	inputs, err := m.source.WindowsCapacityInputs(ctx, now)
	if err != nil {
		return err
	}
	authority, err := windowsCapacityAuthority(inputs, now)
	if err != nil {
		return err
	}
	if !contactReadTime(now, m.source.Now().UTC()) {
		return windowscapacity.ErrInvalid
	}
	for id, state := range states {
		if err = ctx.Err(); err != nil {
			return err
		}
		if !state.Policy.Enabled {
			continue
		}
		in, exists := authority[id]
		if !exists {
			// An omitted identity cannot lend continuity to a later return. Retain its
			// private binding/floors/history and explicitly invalidate current evidence.
			in = windowscapacity.Input{Input: windowscontact.Input{DeviceID: id, InvitationID: state.InvitationID, CertificateHash: state.CertificateHash}}
		}
		if _, err = m.store.EvaluateWindowsCapacity(ctx, in, now, m.epoch); err != nil {
			return err
		}
	}
	for _, resource := range resources {
		if err = ctx.Err(); err != nil {
			return err
		}
		state := resource.Assessment
		if !state.Policy.Enabled {
			continue
		}
		in, exists := authority[state.DeviceID]
		if !exists {
			in = windowscapacity.Input{Input: windowscontact.Input{DeviceID: state.DeviceID, InvitationID: state.InvitationID, CertificateHash: state.CertificateHash}}
		}
		if _, err = m.store.EvaluateWindowsResource(ctx, in, resource.Metric, now, m.epoch); err != nil {
			return err
		}
	}
	for id, state := range services {
		if err = ctx.Err(); err != nil {
			return err
		}
		if !state.Policy.Enabled {
			continue
		}
		in, exists := authority[id]
		if !exists {
			in = windowscapacity.Input{Input: windowscontact.Input{DeviceID: id, InvitationID: state.InvitationID, CertificateHash: state.CertificateHash}}
		}
		if _, err = m.store.EvaluateWindowsService(ctx, windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, now, m.epoch); err != nil {
			return err
		}
	}
	if !contactReadTime(now, m.source.Now().UTC()) {
		return windowscapacity.ErrInvalid
	}
	m.ready = true
	return nil
}

// RunWindowsCapacityMonitor runs independently of Linux checks, AI workers and
// browser visibility. It evaluates only existing disk, CPU, physical-RAM and selected-service metadata.
func (s *Server) RunWindowsCapacityMonitor(ctx context.Context, warn func()) error {
	s.mu.RLock()
	m := s.windowsCapacity
	s.mu.RUnlock()
	if m == nil {
		return nil
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastWarning time.Time
	for {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := m.evaluate(step)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		now := m.source.Now()
		if err != nil && warn != nil && (lastWarning.IsZero() || now.Before(lastWarning) || now.Sub(lastWarning) >= time.Minute) {
			warn()
			lastWarning = now
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// GET is read-only; policy writes are isolated shared-administrator mutations.
// Neither operation is an endpoint grant or permission to export observations.
func (h *operatorHandler) windowsCapacityAPI(w http.ResponseWriter, r *http.Request) {
	id, kind, mutation, valid := windowsPercentageRoute(r)
	if !valid {
		fail(w, 404, "not_found", "Windows percentage checks are unavailable.")
		return
	}
	if !mutation && r.Method != http.MethodGet || mutation && r.Method != http.MethodPost {
		if mutation {
			w.Header().Set("Allow", "POST")
		} else {
			w.Header().Set("Allow", "GET")
		}
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows capacity checks are not configured.")
		return
	}
	var policy struct {
		Enabled   bool   `json:"enabled"`
		Threshold int    `json:"thresholdPercent"`
		Expected  uint64 `json:"expectedRevision"`
	}
	if mutation {
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change this policy.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readObject(w, r, 256, []string{"enabled", "thresholdPercent", "expectedRevision"}, &policy) {
			return
		}
		if policy.Threshold < 50 || policy.Threshold > 99 || policy.Expected >= windowscapacity.MaxCounter {
			fail(w, 400, "invalid_windows_capacity_policy", "Choose a whole percentage from 50 through 99 and the current policy revision.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, err := m.source.WindowsCapacityInputs(r.Context(), now)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, now)
	if err != nil {
		fail(w, 503, "windows_capacity_unavailable", "Capacity authority is unavailable.")
		return
	}
	in, ok := authority[id]
	if !ok || !in.Authorized {
		fail(w, 404, "not_found", "Windows capacity checks are unavailable.")
		return
	}
	state, err := m.policyState(r.Context(), in.DeviceID, kind)
	if err != nil {
		fail(w, 503, "windows_capacity_unavailable", "Capacity state is temporarily unavailable.")
		return
	}
	if state.InvitationID != "" && (state.InvitationID != in.InvitationID || state.CertificateHash != in.CertificateHash) {
		fail(w, 409, "windows_capacity_conflict", "Capacity state belongs to another device identity.")
		return
	}
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		at := m.source.Now().UTC()
		if !contactReadTime(now, at) {
			fail(w, 503, "windows_capacity_unavailable", "Capacity time reference changed.")
			return false
		}
		current, e := m.source.WindowsCapacityInputs(r.Context(), at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(current, at)
		if e != nil {
			fail(w, 503, "windows_capacity_unavailable", "Capacity authority is unavailable.")
			return false
		}
		v, ok := latest[in.DeviceID]
		if !ok || !v.Authorized || v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil) {
			fail(w, 409, "windows_capacity_conflict", "Device authority changed. Refresh this view.")
			return false
		}
		end := m.source.Now().UTC()
		if !contactReadTime(now, end) || end.Before(at) || !end.Before(in.AuthorityUntil) {
			fail(w, 409, "windows_capacity_conflict", "Device authority or time reference changed. Refresh this view.")
			return false
		}
		in = v
		return operatorStillActive(w, r)
	}
	if mutation {
		if !recheck() {
			return
		}
		configure := func(authorityGuard func(time.Time) error) error {
			var e error
			state, e = m.configurePolicy(r.Context(), in, kind, policy.Enabled, policy.Threshold, policy.Expected, m.source.Now().UTC(), func() error {
				// No enrollment read while holding the operator SQLite transaction.
				// Recheck the already-admitted authority deadline and live session
				// after connection wait and again immediately before commit.
				end := m.source.Now().UTC()
				operator, admitted := operatorContext(r)
				if !admitted || operator.active == nil || !operator.active() || r.Context().Err() != nil || !contactReadTime(now, end) || !end.Before(in.AuthorityUntil) {
					return windowscapacity.ErrInvalid
				}
				if authorityGuard != nil {
					if e := authorityGuard(end); e != nil {
						return windowscapacity.ErrInvalid
					}
					final := m.source.Now().UTC()
					if final.Before(end) || !contactReadTime(now, final) || !final.Before(in.AuthorityUntil) || !operator.active() {
						return windowscapacity.ErrInvalid
					}
				}
				return nil
			})
			return e
		}
		if lease, ok := m.source.(windowsMonitoringAuthoritySource); ok {
			err = lease.WithWindowsMonitoringAuthority(r.Context(), []windowscontact.Input{in.Input}, configure)
		} else {
			// Legacy read-only fixtures/sources cannot detach an inherited target without its authority lease.
			assignments, e := m.store.FleetMonitoringAssignments(r.Context())
			err = e
			for _, a := range assignments {
				if a.Active && a.DeviceID == in.DeviceID && (a.Metric == string(kind) || kind == "" && a.Metric == "disk") {
					err = windowscapacity.ErrInvalid
				}
			}
			if err == nil {
				err = configure(nil)
			}
		}
		if errors.Is(err, windowscapacity.ErrInvalid) {
			fail(w, 409, "windows_capacity_conflict", "Policy changed or is unavailable. Refresh before saving again.")
			return
		}
		if err != nil {
			fail(w, 503, "windows_capacity_unavailable", "Policy save could not be confirmed. Refresh before saving again.")
			return
		}
	}
	if !recheck() {
		return
	}
	started := now
	now = m.source.Now().UTC()
	if !contactReadTime(started, now) || !now.Before(in.AuthorityUntil) {
		fail(w, 409, "windows_capacity_conflict", "Device authority or time reference changed. Refresh this view.")
		return
	}
	epoch := m.epoch
	if !m.ready {
		epoch = ""
	}
	// A policy save does not evaluate its source. Source/evaluator timestamps remain
	// original, and a newer accepted tuple requires a later monitor pass.
	var view any
	if kind == "" {
		view = state.View(in, now, epoch)
	} else {
		view, err = windowsresource.MakeView(state, in, kind, now, epoch)
		if err != nil {
			fail(w, 503, "windows_capacity_unavailable", "Resource state is unavailable.")
			return
		}
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw) > windowscapacity.MaxStateBytes {
		fail(w, 503, "windows_capacity_unavailable", "Capacity state is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	finished := m.source.Now().UTC()
	if !contactReadTime(started, finished) || finished.Before(now) || !finished.Before(in.AuthorityUntil) {
		fail(w, 409, "windows_capacity_conflict", "Device authority or time reference changed. Refresh this view.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// The route is the immutable metric binding. Body/query aliases cannot reinterpret
// a disk opt-in or select an arbitrary percentage source. Both contracts use the
// exact same operator/session/certificate checks above, including before release.
func windowsPercentageRoute(r *http.Request) (id string, kind windowsresource.Kind, mutation, valid bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || r.URL.RawQuery != "" {
		return
	}
	id = parts[3]
	switch parts[4] {
	case "windows-capacity":
		valid = len(parts) == 5 || len(parts) == 6 && parts[5] == "policy"
		mutation = len(parts) == 6
	case "windows-resource":
		if len(parts) < 6 {
			return
		}
		kind = windowsresource.Kind(parts[5])
		valid = windowsresource.ValidKind(kind) && (len(parts) == 6 || len(parts) == 7 && parts[6] == "policy")
		mutation = len(parts) == 7
	}
	return
}
func (m *windowsCapacityMonitor) policyState(ctx context.Context, id string, kind windowsresource.Kind) (windowscapacity.State, error) {
	if kind == "" {
		return m.store.WindowsCapacityState(ctx, id)
	}
	state, err := m.store.WindowsResourceState(ctx, id, kind)
	return state.Assessment, err
}
func (m *windowsCapacityMonitor) configurePolicy(ctx context.Context, in windowscapacity.Input, kind windowsresource.Kind, enabled bool, threshold int, expected uint64, at time.Time, guard ...func() error) (windowscapacity.State, error) {
	if kind == "" {
		return m.store.ConfigureWindowsCapacity(ctx, in, enabled, threshold, expected, at, guard...)
	}
	state, err := m.store.ConfigureWindowsResource(ctx, in, kind, enabled, threshold, expected, at, guard...)
	return state.Assessment, err
}
