package api

import "net/http"

// Startup configuration is the only send authority. This authenticated endpoint
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
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, status)
}
