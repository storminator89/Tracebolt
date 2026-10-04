package api

import (
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"strings"
	"time"
)

func (s *Server) packageView(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "packages" || !validID(parts[3]) {
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	s.mu.RLock()
	provider := s.lanPackages
	s.mu.RUnlock()
	now := time.Now().UTC()
	if provider != nil {
		view, e := provider(r.Context(), parts[3], now)
		if errors.Is(e, enrollmentstate.ErrNotFound) {
			fail(w, 404, "not_found", "Device not found.")
			return
		}
		if errors.Is(e, enrollmentstore.ErrBusy) || errors.Is(e, enrollmentstore.ErrOperationalBusy) {
			w.Header().Set("Retry-After", "2")
			fail(w, 429, "storage_busy", "Stored package observations are busy; retry shortly.")
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
			write(w, 200, enrollmentstore.EmptyPackageView(d.ID, now))
			return
		}
	}
	fail(w, 404, "not_found", "Device not found.")
}
