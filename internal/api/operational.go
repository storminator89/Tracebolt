package api

import (
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

func (s *Server) operationalView(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "operational" || !validID(parts[3]) {
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	s.mu.RLock()
	source := s.lanOperational
	s.mu.RUnlock()
	now := time.Now().UTC()
	if source != nil {
		view, e := source(r.Context(), parts[3], now)
		if errors.Is(e, enrollmentstate.ErrNotFound) {
			fail(w, 404, "not_found", "Device not found.")
			return
		}
		if errors.Is(e, enrollmentstore.ErrBusy) {
			w.Header().Set("Retry-After", "2")
			fail(w, 429, "storage_busy", "Operational storage is busy; retry shortly.")
			return
		}
		if errors.Is(e, enrollmentstore.ErrOperationalBusy) {
			w.Header().Set("Retry-After", "2")
			fail(w, 429, "operational_busy", "Operational data is busy; retry shortly.")
			return
		}
		if e != nil {
			s.internal(w)
			return
		}
		write(w, 200, view)
		return
	}
	devices, e := s.devices()
	if e != nil {
		s.internal(w)
		return
	}
	for _, d := range devices {
		if d.ID == parts[3] {
			write(w, 200, enrollmentstore.EmptyOperationalView(d.ID, now))
			return
		}
	}
	fail(w, 404, "not_found", "Device not found.")
}
