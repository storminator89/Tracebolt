package api

import "net/http"

// Explicit startup or browser configuration is the send authority. This endpoint
// is read-only and never returns destination, credentials or provider content.
func (h *operatorHandler) alarmStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	status, e := h.app.store.AlarmStatus(r.Context())
	if e != nil {
		fail(w, 503, "alarm_status_unavailable", "External alarm status is temporarily unavailable.")
		return
	}
	if h.alarmSettings != nil {
		status.Enabled = status.Enabled && h.alarmSettings.DeliveryEnabled()
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, status)
}
