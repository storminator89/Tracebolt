package api

import (
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"strings"
	"time"
)

func (h *operatorHandler) windowsServiceAPI(w http.ResponseWriter, r *http.Request) {
	id, mutation, valid := windowsServiceRoute(r)
	complete := strings.Contains(r.URL.Path, "/windows-services/complete")
	if !valid {
		fail(w, 404, "not_found", "Windows service checks are unavailable.")
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
		fail(w, 404, "not_found", "Windows service checks are not configured.")
		return
	}
	var policy struct {
		Enabled  bool                             `json:"enabled"`
		Services []string                         `json:"services"`
		Expected uint64                           `json:"expectedRevision"`
		Source   *windowsservicehealth.Provenance `json:"source"`
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
		fields := []string{"enabled", "services", "expectedRevision"}
		if complete {
			fields = append(fields, "source")
		}
		if !readObject(w, r, 32<<10, fields, &policy) {
			return
		}
		validateNames := windowsservicehealth.Services
		if complete {
			validateNames = windowsservicehealth.CompleteServices
		}
		if _, err := validateNames(policy.Services); err != nil || policy.Enabled && len(policy.Services) == 0 || policy.Expected >= windowsservicehealth.MaxCounter {
			fail(w, 400, "invalid_windows_service_policy", "Choose at most eight exact reported names and the current policy revision.")
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
	if complete {
		initial, e := m.store.WindowsServiceState(r.Context(), id)
		if e != nil {
			fail(w, 503, "windows_service_unavailable", "Service state is unavailable.")
			return
		}
		names := initial.Policy.Services
		if mutation {
			names = policy.Services
		}
		r = r.WithContext(windowsservicehealth.WithCompleteSelections(r.Context(), map[string][]string{id: names}))
	}
	inputs, err := m.source.WindowsCapacityInputs(r.Context(), now)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, now)
	if err != nil {
		fail(w, 503, "windows_service_unavailable", "Service authority is unavailable.")
		return
	}
	in, ok := authority[id]
	if !ok || !in.Authorized {
		fail(w, 404, "not_found", "Windows service checks are unavailable.")
		return
	}
	state, err := m.store.WindowsServiceState(r.Context(), in.DeviceID)
	if err != nil {
		fail(w, 503, "windows_service_unavailable", "Service state is temporarily unavailable.")
		return
	}
	if complete && state.DeviceID == "" {
		state = windowsservicehealth.NewComplete()
	}
	if complete != (state.SchemaVersion == windowsservicehealth.CompleteStateSchema) {
		fail(w, 409, "windows_service_source_conflict", "This policy uses another explicit source version.")
		return
	}
	if state.InvitationID != "" && (state.InvitationID != in.InvitationID || state.CertificateHash != in.CertificateHash) {
		fail(w, 409, "windows_service_conflict", "Service state belongs to another device identity.")
		return
	}
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		at := m.source.Now().UTC()
		if !contactReadTime(now, at) {
			fail(w, 503, "windows_service_unavailable", "Service time reference changed.")
			return false
		}
		current, e := m.source.WindowsCapacityInputs(r.Context(), at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(current, at)
		if e != nil {
			fail(w, 503, "windows_service_unavailable", "Service authority is unavailable.")
			return false
		}
		v, ok := latest[in.DeviceID]
		if !ok || !v.Authorized || v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil) || complete && v.CurrentLeaf != in.CurrentLeaf {
			fail(w, 409, "windows_service_conflict", "Device authority changed. Refresh this view.")
			return false
		}
		end := m.source.Now().UTC()
		if !contactReadTime(now, end) || end.Before(at) || !end.Before(in.AuthorityUntil) {
			fail(w, 409, "windows_service_conflict", "Device authority or time reference changed. Refresh this view.")
			return false
		}
		in = v
		return operatorStillActive(w, r)
	}
	if mutation {
		if !recheck() {
			return
		}
		configure := func(guard func(time.Time) error) (windowsservicehealth.State, error) {
			return m.store.ConfigureWindowsServiceGuarded(r.Context(), windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: complete, Selection: policy.Source}, policy.Enabled, policy.Services, policy.Expected, m.source.Now, guard)
		}
		if complete {
			state, err = h.withWindowsCompleteServicePolicyAuthority(r, in, policy.Source, now, configure)
		} else {
			state, err = h.withWindowsServicePolicyAuthority(r, in, now, configure)
		}
		if errors.Is(err, windowsservicehealth.ErrInvalid) {
			fail(w, 409, "windows_service_conflict", "Policy changed or is unavailable. Refresh before saving again.")
			return
		}
		if err != nil {
			fail(w, 503, "windows_service_unavailable", "Policy save could not be confirmed. Refresh before saving again.")
			return
		}
	}
	if !recheck() {
		return
	}
	started := now
	now = m.source.Now().UTC()
	if !contactReadTime(started, now) || !now.Before(in.AuthorityUntil) {
		fail(w, 409, "windows_service_conflict", "Device authority or time reference changed. Refresh this view.")
		return
	}
	epoch := m.epoch
	if !m.ready {
		epoch = ""
	}
	// A policy save does not evaluate its source. Source/evaluator timestamps remain
	// original, and a newer accepted tuple requires a later monitor pass.
	view := state.View(windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, now, epoch)
	raw, err := encodeWindowsServiceView(view)
	if err != nil {
		fail(w, 503, "windows_service_unavailable", "Service state is unavailable.")
		return
	}
	defer clear(raw)
	finished := m.source.Now().UTC()
	if !contactReadTime(started, finished) || finished.Before(now) || !finished.Before(in.AuthorityUntil) {
		fail(w, 409, "windows_service_conflict", "Device authority or time reference changed. Refresh this view.")
		return
	}
	if complete && view.Inventory != nil && (view.Inventory.Source == nil || !view.Inventory.Source.Fresh(finished)) {
		fail(w, 409, "windows_service_conflict", "The reviewed source expired. Refresh this view.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func windowsServiceRoute(r *http.Request) (id string, mutation, valid bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) < 5 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-services" || r.URL.RawQuery != "" {
		return
	}
	id = p[3]
	if len(p) >= 6 && p[5] == "complete" {
		mutation = len(p) == 7
		valid = len(p) == 6 || len(p) == 7 && p[6] == "policy"
		return
	}
	mutation = len(p) == 6
	valid = len(p) == 5 || len(p) == 6 && p[5] == "policy"
	return
}

// Include the framing newline in the browser's exact response-byte budget.
func encodeWindowsServiceView(view windowsservicehealth.View) ([]byte, error) {
	raw, err := json.Marshal(view)
	if err != nil || len(raw)+1 > windowsservicehealth.MaxViewBytes {
		return nil, windowsservicehealth.ErrInvalid
	}
	return append(raw, '\n'), nil
}
