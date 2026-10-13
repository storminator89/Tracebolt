package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
)

type windowsMaintenanceTargetView struct {
	Key       string                           `json:"key"`
	DeviceID  string                           `json:"deviceId"`
	Domain    string                           `json:"domain"`
	Revision  uint64                           `json:"revision"`
	ChangedAt *time.Time                       `json:"changedAt"`
	Windows   []store.WindowsMaintenanceWindow `json:"windows"`
}
type windowsMaintenanceView struct {
	SchemaVersion      string                         `json:"schemaVersion"`
	ServerNow          time.Time                      `json:"serverNow"`
	AuthorityExpiresAt time.Time                      `json:"authorityExpiresAt"`
	Targets            []windowsMaintenanceTargetView `json:"targets"`
}

func maintenanceTarget(in windowscapacity.Input, domain string) store.WindowsMaintenanceTarget {
	return store.WindowsMaintenanceTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: domain}
}

// This is a separate planning projection, not a modification of the strict v1
// incident inbox. A device ID alone never joins maintenance onto retained rows.
func projectWindowsMaintenance(states []store.WindowsMaintenanceState, authority map[string]windowscapacity.Input, now time.Time) (windowsMaintenanceView, error) {
	v := windowsMaintenanceView{SchemaVersion: "tracebolt.windows-maintenance.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), Targets: []windowsMaintenanceTargetView{}}
	byKey := map[string]store.WindowsMaintenanceState{}
	for _, st := range states {
		byKey[st.Target.Key()] = st
	}
	ids := []string{}
	for id, in := range authority {
		if in.Authorized {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		in := authority[id]
		if !now.Before(in.AuthorityUntil) {
			return v, store.ErrWindowsMaintenanceConflict
		}
		if in.AuthorityUntil.Before(v.AuthorityExpiresAt) {
			v.AuthorityExpiresAt = in.AuthorityUntil
		}
		for _, domain := range store.WindowsMaintenanceDomains() {
			target := maintenanceTarget(in, domain)
			row := windowsMaintenanceTargetView{Key: target.Key(), DeviceID: id, Domain: domain, Windows: []store.WindowsMaintenanceWindow{}}
			if st, ok := byKey[row.Key]; ok {
				if st.Target != target || now.Before(st.ChangedAt) {
					return v, store.ErrWindowsMaintenanceConflict
				}
				row.Revision = st.Revision
				row.ChangedAt = inboxStamp(st.ChangedAt)
				row.Windows = st.Windows
			}
			v.Targets = append(v.Targets, row)
		}
	}
	return v, nil
}

func (h *operatorHandler) windowsMaintenanceAPI(w http.ResponseWriter, r *http.Request) {
	h.serveWindowsMaintenance(w, r, "")
}

func (h *operatorHandler) serveWindowsMaintenance(w http.ResponseWriter, r *http.Request, groupID string) {
	route := "/api/fleet/windows-maintenance"
	if groupID != "" {
		route = "/api/fleet/groups/" + groupID + "/maintenance"
	}
	start := r.URL.Path == route+"/start"
	end := r.URL.Path == route+"/end"
	mutation := start || end
	if r.URL.Path != route && !mutation {
		fail(w, 404, "not_found", "Windows maintenance is unavailable.")
		return
	}
	if !mutation && r.Method != "GET" || mutation && r.Method != "POST" {
		if mutation {
			w.Header().Set("Allow", "POST")
		} else {
			w.Header().Set("Allow", "GET")
		}
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_windows_maintenance", "Maintenance does not accept query parameters.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows maintenance is not configured.")
		return
	}
	var key, intent string
	var revision, endID, groupRevision uint64
	var endsAt time.Time
	if mutation {
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change planned maintenance.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if start {
			var body struct {
				GroupRevision uint64 `json:"groupRevision"`
				Key           string `json:"key"`
				Revision      uint64 `json:"revision"`
				EndsAt        string `json:"endsAt"`
				Intent        string `json:"intent"`
			}
			keys := []string{"key", "revision", "endsAt", "intent"}
			if groupID != "" {
				keys = append(keys, "groupRevision")
			}
			if !readObject(w, r, 512, keys, &body) {
				return
			}
			if groupID != "" && (body.GroupRevision < 1 || body.GroupRevision > store.MaxFleetGroupRevision) {
				fail(w, 400, "invalid_windows_maintenance", "Choose the exact reviewed group revision.")
				return
			}
			groupRevision = body.GroupRevision
			var err error
			endsAt, err = time.Parse(time.RFC3339Nano, body.EndsAt)
			if err != nil || endsAt.Location() != time.UTC || endsAt.Format(time.RFC3339Nano) != body.EndsAt || !store.ValidWindowsMaintenanceIntent(body.Intent) {
				fail(w, 400, "invalid_windows_maintenance", "Choose an explicit UTC end time and maintenance purpose.")
				return
			}
			key, revision, intent = body.Key, body.Revision, body.Intent
		} else {
			var body struct {
				GroupRevision uint64 `json:"groupRevision"`
				Key           string `json:"key"`
				Revision      uint64 `json:"revision"`
				WindowID      uint64 `json:"windowId"`
			}
			keys := []string{"key", "revision", "windowId"}
			if groupID != "" {
				keys = append(keys, "groupRevision")
			}
			if !readObject(w, r, 256, keys, &body) {
				return
			}
			if groupID != "" && (body.GroupRevision < 1 || body.GroupRevision > store.MaxFleetGroupRevision) {
				fail(w, 400, "invalid_windows_maintenance", "Choose the exact reviewed group revision.")
				return
			}
			groupRevision = body.GroupRevision
			if body.WindowID < 1 || body.WindowID > store.MaxWindowsMaintenanceRevision {
				fail(w, 400, "invalid_windows_maintenance", "Choose the exact active maintenance window.")
				return
			}
			key, revision, endID = body.Key, body.Revision, body.WindowID
		}
		if !enrollmentcrypto.ValidHash(key) || revision >= store.MaxWindowsMaintenanceRevision {
			fail(w, 400, "invalid_windows_maintenance", "Choose the exact current maintenance target and revision.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	// No source evaluation occurs. Match the existing monitor/enrollment/operator
	// ordering while serializing this manager's metadata requests.
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	inputs, err := m.source.WindowsCapacityInputs(r.Context(), started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, started)
	if err != nil {
		fail(w, 503, "windows_maintenance_unavailable", "Current Windows identity authority is unavailable.")
		return
	}
	var groupRead *fleetGroupMaintenanceRead
	if groupID != "" {
		groupRead, err = h.readFleetGroupMaintenance(r.Context(), groupID, started)
		if err != nil {
			fleetGroupMaintenanceError(w, err)
			return
		}
	}
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		// Resolve group storage before the final Windows source read: a SQLite
		// wait must not hide revocation or replacement from response admission.
		if groupID != "" {
			var e error
			groupRead, e = h.readFleetGroupMaintenance(r.Context(), groupID, started)
			if e != nil {
				fleetGroupMaintenanceError(w, e)
				return false
			}
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) {
			fail(w, 409, "windows_maintenance_conflict", "The time reference changed. Refresh maintenance.")
			return false
		}
		current, e := m.source.WindowsCapacityInputs(r.Context(), at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(current, at)
		if e != nil || len(latest) != len(authority) {
			fail(w, 409, "windows_maintenance_conflict", "Windows identity authority changed. Refresh maintenance.")
			return false
		}
		for id, in := range authority {
			v, ok := latest[id]
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
				fail(w, 409, "windows_maintenance_conflict", "Windows identity authority changed. Refresh maintenance.")
				return false
			}
		}
		final := m.source.Now().UTC()
		if !contactReadTime(started, final) || final.Before(at) {
			fail(w, 409, "windows_maintenance_conflict", "The time reference changed. Refresh maintenance.")
			return false
		}
		for _, in := range latest {
			if in.Authorized && !final.Before(in.AuthorityUntil) {
				fail(w, 409, "windows_maintenance_conflict", "Windows identity authority expired. Refresh maintenance.")
				return false
			}
		}
		authority = latest
		return operatorStillActive(w, r)
	}
	if mutation {
		var target store.WindowsMaintenanceTarget
		var in windowscapacity.Input
		for _, current := range authority {
			if !current.Authorized {
				continue
			}
			for _, domain := range store.WindowsMaintenanceDomains() {
				candidate := maintenanceTarget(current, domain)
				if candidate.Key() == key {
					target, in = candidate, current
				}
			}
		}
		if !target.Valid() {
			fail(w, 409, "windows_maintenance_conflict", "The exact device identity or scope changed. Refresh maintenance.")
			return
		}
		if !recheck() {
			return
		}
		lease, ok := m.source.(windowsIncidentAuthoritySource)
		if !ok {
			fail(w, 503, "windows_maintenance_unavailable", "Current Windows authority cannot be locked.")
			return
		}
		err = lease.WithWindowsIncidentAuthority(r.Context(), in.Input, func(authorityGuard func(time.Time) error) error {
			guard := func(sampled, deadline time.Time) error {
				at := m.source.Now().UTC()
				operator, live := operatorContext(r)
				if !live || operator.active == nil || !operator.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(sampled) || !at.Before(in.AuthorityUntil) || !deadline.IsZero() && !at.Before(deadline) {
					return store.ErrWindowsMaintenanceConflict
				}
				if e := authorityGuard(at); e != nil {
					return store.ErrWindowsMaintenanceConflict
				}
				final := m.source.Now().UTC()
				if !contactReadTime(started, final) || final.Before(at) || !final.Before(in.AuthorityUntil) || !deadline.IsZero() && !final.Before(deadline) || !operator.active() || r.Context().Err() != nil {
					return store.ErrWindowsMaintenanceConflict
				}
				return nil
			}
			if groupRead != nil {
				selection := store.FleetGroupMaintenanceSelection{Manager: groupRead.group.Manager, GroupID: groupID, GroupRevision: groupRevision, Identity: monitoringIdentity(groupRead.binding, in.Input)}
				if end {
					_, e := m.store.EndFleetGroupMaintenance(r.Context(), selection, target, revision, endID, m.source.Now, guard)
					return e
				}
				_, e := m.store.StartFleetGroupMaintenance(r.Context(), selection, target, revision, endsAt, intent, m.source.Now, guard)
				return e
			}
			_, e := m.store.ChangeWindowsMaintenance(r.Context(), target, revision, endsAt, intent, endID, m.source.Now, guard)
			return e
		})
		if errors.Is(err, store.ErrWindowsMaintenanceConflict) {
			fail(w, 409, "windows_maintenance_conflict", "The revision, window, time or authority changed. Refresh before reviewing again.")
			return
		}
		if errors.Is(err, store.ErrLimit) {
			fail(w, 409, "windows_maintenance_capacity", "The bounded maintenance metadata capacity is full.")
			return
		}
		if err != nil {
			fail(w, 503, "windows_maintenance_unavailable", "The maintenance change could not be confirmed. Refresh without repeating it.")
			return
		}
	}
	states, err := m.store.WindowsMaintenance(r.Context())
	if err != nil {
		fail(w, 503, "windows_maintenance_unavailable", "Retained maintenance metadata is unavailable.")
		return
	}
	if !recheck() {
		return
	}
	now := m.source.Now().UTC()
	var response any
	var authorityExpiresAt time.Time
	if groupRead != nil {
		var view fleetGroupMaintenanceView
		view, err = projectFleetGroupMaintenance(states, *groupRead, authority, now)
		response, authorityExpiresAt = view, view.AuthorityExpiresAt
	} else {
		var view windowsMaintenanceView
		view, err = projectWindowsMaintenance(states, authority, now)
		response, authorityExpiresAt = view, view.AuthorityExpiresAt
	}
	if err != nil {
		fail(w, 409, "windows_maintenance_conflict", "The recorded time or authority changed. Refresh maintenance.")
		return
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > 262144 || groupID != "" && len(raw)+1 > 262144 {
		fail(w, 503, "windows_maintenance_unavailable", "Maintenance metadata exceeds its bounded response.")
		return
	}
	defer clear(raw)
	final := m.source.Now().UTC()
	if !contactReadTime(started, final) || final.Before(now) || !final.Before(authorityExpiresAt) {
		fail(w, 409, "windows_maintenance_conflict", "Windows authority or the time reference changed. Refresh maintenance.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
