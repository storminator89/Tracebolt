package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"localrmm/internal/health"
)

var errHealthMaintenanceSession = errors.New("health_maintenance_session_ended")

type healthMaintenanceWindow struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"createdAt"`
	StartsAt  time.Time  `json:"startsAt"`
	EndsAt    time.Time  `json:"endsAt"`
	State     string     `json:"state"`
	ClosedAt  *time.Time `json:"closedAt"`
}
type healthMaintenanceRequest struct {
	RequestID string `json:"requestId"`
	Action    string `json:"action"`
	WindowID  string `json:"windowId"`
}
type healthMaintenanceView struct {
	SchemaVersion          string                    `json:"schemaVersion"`
	DeviceID               string                    `json:"deviceId"`
	ServerNow              time.Time                 `json:"serverNow"`
	Revision               uint64                    `json:"revision,string"`
	CanManage              bool                      `json:"canManage"`
	RemainingSlots         int                       `json:"remainingSlots"`
	LegacyMaintenanceUntil *time.Time                `json:"legacyMaintenanceUntil"`
	Window                 *healthMaintenanceWindow  `json:"window"`
	LastRequest            *healthMaintenanceRequest `json:"lastRequest"`
}

func (h *operatorHandler) healthMaintenanceSchedule(w http.ResponseWriter, r *http.Request, device string) {
	if r.Method != "GET" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	owner, ok := operatorContext(r)
	can := ok && !owner.session.Named()
	if r.Method == "POST" && !can {
		fail(w, 403, "operator_capability_required", "Existing Linux Health administrator access is required.")
		return
	}
	m := h.app.health
	if m == nil {
		fail(w, 409, "health_unavailable", "Linux Health is unavailable.")
		return
	}
	var command health.MaintenanceCommand
	if r.Method == "POST" {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readHealthMaintenanceCommand(w, r, &command) {
			return
		}
	}
	var release func()
	if r.Method == "POST" {
		var allowed bool
		release, allowed = beginOperatorMutation(w, r)
		if !allowed {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	allowed := false
	for _, in := range inputs {
		if in.DeviceID == device && in.Authorized {
			allowed = true
		}
	}
	if !allowed {
		fail(w, 404, "not_found", "Linux Health is unavailable.")
		return
	}
	var state health.State
	if r.Method == "POST" {
		state, err = m.store.UpdateHealth(r.Context(), device, func(s *health.State) error {
			fresh := m.source.Now().UTC()
			if fresh.Before(now) {
				return health.ErrInvalid
			}
			now = fresh
			if owner.active == nil || !owner.active() {
				return errHealthMaintenanceSession
			}
			return s.ApplyMaintenance(command, now)
		})
	} else {
		state, err = m.store.HealthStateAt(r.Context(), device, now, m.source.Now)
	}
	if errors.Is(err, errHealthMaintenanceSession) {
		fail(w, 401, "authentication_required", "Operator session ended.")
		return
	}
	if errors.Is(err, health.ErrInvalid) {
		fail(w, 409, "health_conflict", "Maintenance state changed or the fixed window is invalid. Read status before another action.")
		return
	}
	if err != nil {
		fail(w, 503, "health_unavailable", "Maintenance storage outcome may be uncertain. Read saved status; do not repeat a write.")
		return
	}
	if state.Schedule != nil && state.Schedule.ClockFloor.After(now) {
		now = state.Schedule.ClockFloor
	}
	out := healthMaintenanceView{SchemaVersion: "tracebolt.linux-maintenance-schedule-view.v1", DeviceID: device, ServerNow: now, CanManage: can, RemainingSlots: health.MaxMaintenanceWindows}
	if state.MaintenanceUntil != nil && now.Before(*state.MaintenanceUntil) {
		out.LegacyMaintenanceUntil = state.MaintenanceUntil
	}
	if state.Schedule != nil {
		s := state.Schedule
		out.Revision = s.Revision
		out.RemainingSlots -= len(s.Windows)
		x := s.Windows[len(s.Windows)-1]
		out.Window = &healthMaintenanceWindow{x.ID, x.CreatedAt, x.StartsAt, x.EndsAt, x.Status(now), x.ClosedAt}
		c := s.LastCommand
		out.LastRequest = &healthMaintenanceRequest{c.RequestID, c.Action, c.WindowID}
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, out)
}

// This endpoint alone has two explicitly nullable timestamp fields. Do not relax
// shared mutation decoders or accept omitted/duplicate/unknown command fields.
func readHealthMaintenanceCommand(w http.ResponseWriter, r *http.Request, out *health.MaintenanceCommand) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return false
	}
	invalid := func() bool {
		fail(w, 400, "invalid_json", "Exactly the expected typed maintenance fields are required.")
		return false
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return invalid()
	}
	fields := map[string]json.RawMessage{"requestId": nil, "expectedRevision": nil, "action": nil, "windowId": nil, "startsAt": nil, "endsAt": nil}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return invalid()
		}
		if _, ok = fields[key]; !ok {
			return invalid()
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return invalid()
		}
		fields[key] = value
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			if key != "startsAt" && key != "endsAt" {
				return invalid()
			}
		} else {
			var text string
			if json.Unmarshal(value, &text) != nil {
				return invalid()
			}
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != len(fields) {
		return invalid()
	}
	if _, err = d.Token(); err != io.EOF {
		return invalid()
	}
	if json.Unmarshal(raw, out) != nil {
		return invalid()
	}
	var revision string
	if json.Unmarshal(fields["expectedRevision"], &revision) != nil || revision != strconv.FormatUint(out.ExpectedRevision, 10) {
		return invalid()
	}
	for key, t := range map[string]*time.Time{"startsAt": out.StartsAt, "endsAt": out.EndsAt} {
		if t != nil {
			var text string
			if json.Unmarshal(fields[key], &text) != nil || text != t.Format(time.RFC3339) {
				return invalid()
			}
		}
	}
	return operatorStillActive(w, r)
}
