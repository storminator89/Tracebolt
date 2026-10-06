package api

import (
	"errors"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/operatorauth"
	"net/http"
)

func (h *operatorHandler) alarmSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_request", "Alarm settings do not accept query parameters.")
		return
	}
	if r.URL.Path == "/api/alerts/settings" && r.Method == "GET" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(w, 400, "invalid_request", "Alarm settings reads do not accept a body.")
			return
		}
		h.writeAlarmSettings(w, r)
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var err error
	if r.URL.Path == "/api/alerts/settings" {
		var in alarmChangeRequest
		if !readObject(w, r, 6144, []string{"expectedRevision", "operation", "endpoint", "payloadSharingAcknowledged", "plaintextAcknowledged"}, &in) {
			return
		}
		actor, release, ok := h.beginAlarmMutation(w, r)
		if !ok {
			return
		}
		defer release()
		err = h.alarmSettings.Change(r.Context(), alarmdelivery.SettingsChange{ExpectedRevision: in.ExpectedRevision, Operation: in.Operation, Endpoint: in.Endpoint, PayloadSharingAcknowledged: in.PayloadSharingAcknowledged, PlaintextAcknowledged: in.PlaintextAcknowledged}, actor)
		in.Endpoint = ""
		release()
	} else {
		var in struct {
			ExpectedRevision string `json:"expectedRevision"`
			RequestID        string `json:"requestId"`
			TestAcknowledged bool   `json:"testAcknowledged"`
		}
		if !readObject(w, r, 512, []string{"expectedRevision", "requestId", "testAcknowledged"}, &in) {
			return
		}
		if !in.TestAcknowledged {
			fail(w, 400, "alarm_test_acknowledgement_required", "Confirm the synthetic test payload and configured destination before sending.")
			return
		}
		actor, release, ok := h.beginAlarmMutation(w, r)
		if !ok {
			return
		}
		defer release()
		err = h.alarmSettings.Test(r.Context(), in.ExpectedRevision, in.RequestID, actor)
		release()
	}
	if err != nil {
		alarmSettingsError(w, err)
		return
	}
	h.writeAlarmSettings(w, r)
}

type alarmChangeRequest struct {
	ExpectedRevision           string `json:"expectedRevision"`
	Operation                  string `json:"operation"`
	Endpoint                   string `json:"endpoint"`
	PayloadSharingAcknowledged bool   `json:"payloadSharingAcknowledged"`
	PlaintextAcknowledged      bool   `json:"plaintextAcknowledged"`
}

func (alarmChangeRequest) String() string   { return "api.alarmChangeRequest{redacted}" }
func (alarmChangeRequest) GoString() string { return "api.alarmChangeRequest{redacted}" }
func (h *operatorHandler) beginAlarmMutation(w http.ResponseWriter, r *http.Request) (string, func(), bool) {
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authenticated alarm administrator is required.")
		return "", nil, false
	}
	if op.session.Named() {
		return h.app.beginOperatorCapability(w, r, operatorauth.ManageAlarms)
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return "", nil, false
	}
	return "shared-administrator", release, true
}
func (h *operatorHandler) writeAlarmSettings(w http.ResponseWriter, r *http.Request) {
	v, e := h.alarmSettings.View(r.Context())
	if e != nil {
		alarmSettingsError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, v)
}
func alarmSettingsError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, alarmdelivery.ErrSettingsConflict):
		fail(w, 409, "alarm_settings_changed", "Alarm settings changed. Refresh and review the current destination before trying again.")
	case errors.Is(e, alarmdelivery.ErrSettingsBusy):
		fail(w, 409, "alarm_settings_busy", "An alarm attempt or settings change is in progress. Refresh before trying again.")
	case errors.Is(e, alarmdelivery.ErrTestLimited):
		fail(w, 429, "alarm_test_limited", "Only one new test per minute is allowed and queue capacity must be available. Refresh before trying again.")
	case errors.Is(e, alarmdelivery.ErrConfiguration), errors.Is(e, alarmdelivery.ErrInvalid):
		fail(w, 400, "invalid_alarm_settings", "Use a public HTTPS destination on port 443 and confirm the requested payload sharing.")
	default:
		fail(w, 503, "alarm_settings_unavailable", "Alarm settings could not be confirmed. Refresh before any further change; a blocked controller requires manager restart and review.")
	}
}
