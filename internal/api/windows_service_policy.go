package api

import (
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"time"
)

// Shared by ordinary service policy saves and the additive one-time group path.
func (h *operatorHandler) withWindowsServicePolicyAuthority(r *http.Request, in windowscapacity.Input, started time.Time, configure func(func(time.Time) error) (windowsservicehealth.State, error)) (windowsservicehealth.State, error) {
	m := h.app.windowsCapacity
	lease, ok := m.source.(windowsIncidentAuthoritySource)
	if !ok {
		return windowsservicehealth.State{}, store.ErrWindowsMaintenanceConflict
	}
	var state windowsservicehealth.State
	err := lease.WithWindowsIncidentAuthority(r.Context(), in.Input, func(authorityGuard func(time.Time) error) error {
		guard := func(sampled time.Time) error {
			at := m.source.Now().UTC()
			operator, live := operatorContext(r)
			if !live || operator.active == nil || !operator.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(sampled) || !at.Before(in.AuthorityUntil) {
				return windowsservicehealth.ErrInvalid
			}
			if err := authorityGuard(at); err != nil {
				return windowsservicehealth.ErrInvalid
			}
			final := m.source.Now().UTC()
			if !contactReadTime(started, final) || final.Before(at) || !final.Before(in.AuthorityUntil) || !operator.active() || r.Context().Err() != nil {
				return windowsservicehealth.ErrInvalid
			}
			return nil
		}
		var err error
		state, err = configure(guard)
		return err
	})
	return state, err
}
