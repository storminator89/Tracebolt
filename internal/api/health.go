package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/health"
	"localrmm/internal/store"
	"net/http"
	"strings"
	"sync"
	"time"
)

type healthSource interface {
	HealthInputs(context.Context, map[string][]string, time.Time) ([]health.Input, error)
	Now() time.Time
}
type healthMonitor struct {
	mu     sync.Mutex
	store  *store.Store
	source healthSource
}

func (m *healthMonitor) evaluate(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	states, e := m.store.HealthStates(ctx)
	if e != nil {
		return e
	}
	services := map[string][]string{}
	for id, state := range states {
		services[id] = state.MonitoredServices
	}
	now := m.source.Now().UTC()
	inputs, e := m.source.HealthInputs(ctx, services, now)
	if e != nil {
		return e
	}
	for _, input := range inputs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, e = m.store.UpdateHealth(ctx, input.DeviceID, func(s *health.State) error { s.Evaluate(input, now); return nil })
		if e != nil {
			return e
		}
	}
	return nil
}

// RunHealthMonitor evaluates accepted data independently of browser visibility.
// It exits before operator-store shutdown and never executes endpoint actions.
func (s *Server) RunHealthMonitor(ctx context.Context, warn func()) error {
	s.mu.RLock()
	m := s.health
	s.mu.RUnlock()
	if m == nil {
		return nil
	}
	ticker := time.NewTicker(health.Interval)
	defer ticker.Stop()
	var lastWarning time.Time
	for {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		e := m.evaluate(step)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		now := m.source.Now()
		if e != nil && warn != nil && (lastWarning.IsZero() || now.Sub(lastWarning) >= time.Minute) {
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
func (h *operatorHandler) healthAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "health" {
		fail(w, 404, "not_found", "Device health checks are unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
		if action != "acknowledge" && action != "maintenance" && action != "services" {
			fail(w, 404, "not_found", "Health action is unavailable.")
			return
		}
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	m := h.app.health
	if m == nil {
		fail(w, 409, "health_unavailable", "Health checks require an activated Linux v3 enrollment.")
		return
	}
	var mutate func(*health.State, time.Time) error
	if action != "" {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		switch action {
		case "acknowledge":
			var input struct {
				IncidentID string `json:"incidentId"`
			}
			if !readObject(w, r, 256, []string{"incidentId"}, &input) {
				return
			}
			if len(input.IncidentID) != 23 || !strings.HasPrefix(input.IncidentID, "health_") {
				fail(w, 400, "invalid_health_action", "Choose a current incident.")
				return
			}
			mutate = func(s *health.State, now time.Time) error { return s.Acknowledge(input.IncidentID, now) }
		case "maintenance":
			var input struct {
				Minutes int `json:"minutes"`
			}
			if !readObject(w, r, 256, []string{"minutes"}, &input) {
				return
			}
			if input.Minutes != 0 && input.Minutes != 15 && input.Minutes != 60 && input.Minutes != 240 {
				fail(w, 400, "invalid_health_action", "Choose a bounded maintenance window.")
				return
			}
			mutate = func(s *health.State, now time.Time) error { return s.Maintain(input.Minutes, now) }
		case "services":
			var input struct {
				Services []string `json:"services"`
			}
			if !readObject(w, r, 2048, []string{"services"}, &input) {
				return
			}
			names, e := health.Services(input.Services)
			if e != nil {
				fail(w, 400, "invalid_health_action", "Choose at most eight distinct service unit names.")
				return
			}
			mutate = func(s *health.State, now time.Time) error { return s.SetServices(names, now) }
		}
	}
	var release func()
	if mutate != nil {
		var ok bool
		release, ok = beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, e := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	allowed := false
	for _, in := range inputs {
		if in.DeviceID == parts[3] && in.Authorized {
			allowed = true
			break
		}
	}
	if !allowed {
		fail(w, 404, "not_found", "Device health checks are unavailable.")
		return
	}
	var state health.State
	if mutate != nil {
		state, e = m.store.UpdateHealth(r.Context(), parts[3], func(s *health.State) error { return mutate(s, now) })
	} else {
		state, e = m.store.HealthState(r.Context(), parts[3])
	}
	if errors.Is(e, health.ErrInvalid) {
		fail(w, 409, "health_conflict", "Health state changed or is unavailable; refresh before retrying.")
		return
	}
	if e != nil {
		fail(w, 503, "health_unavailable", "Health state is temporarily unavailable.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, state.View(parts[3], now))
}
