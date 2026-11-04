package api

import (
	"encoding/json"
	"localrmm/internal/applicationcheck"
	"net/http"
	"time"
)

// Reading this redacted in-memory snapshot never resolves a name, probes a
// target, changes configuration, or changes manager health.
func (h *operatorHandler) applicationCheckStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.Header.Get("Accept") == applicationcheck.HistoryMediaType {
		h.applicationCheckHistory(w, r)
		return
	}
	w.Header().Add("Vary", "Accept")
	status := h.applicationChecks.Status()
	if h.applicationCheckSettings != nil {
		status = h.applicationCheckSettings.Status()
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, status)
}

// An explicit representation keeps the existing v1/v2 status contract intact.
func (h *operatorHandler) applicationCheckHistory(w http.ResponseWriter, r *http.Request) {
	if !operatorStillActive(w, r) {
		return
	}
	// Bound the configuration lease even for a slow operator connection.
	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(time.Now().Add(2*time.Second)) != nil {
		fail(w, 503, "application_history_unavailable", "Observation history is unavailable.")
		return
	}
	publish := func(view applicationcheck.HistoryView) {
		raw, err := json.Marshal(view)
		if err != nil || len(raw) > applicationcheck.HistoryMaxBytes {
			fail(w, 503, "application_history_unavailable", "Observation history is unavailable.")
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		w.Header().Set("Content-Type", applicationcheck.HistoryMediaType)
		w.Header().Add("Vary", "Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}
	if h.applicationCheckSettings != nil {
		if !h.applicationCheckSettings.WithHistory(publish) {
			fail(w, 503, "application_history_busy", "Application check configuration is changing. Reload the current view.")
		}
		return
	}
	publish(h.applicationChecks.History())
}
