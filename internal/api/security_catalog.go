package api

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/offlinecatalog"
	"net/http"
	"regexp"
	"time"
)

var catalogRevisionPattern = regexp.MustCompile(`^revision_[0-9a-f]{32}$`)

func (s *Server) catalogState() (*offlinecatalog.Store, chan struct{}, time.Time) {
	s.mu.RLock()
	catalog, slots, clock := s.catalogStore, s.catalogImports, s.catalogNow
	s.mu.RUnlock()
	now := time.Now().UTC()
	if clock != nil {
		now = clock().UTC()
	}
	return catalog, slots, now
}
func (s *Server) catalogAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	catalog, slots, now := s.catalogState()
	if r.URL.Path == "/api/security/catalog" && r.Method == "GET" {
		write(w, 200, catalog.View(now))
		return
	}
	if catalog == nil || slots == nil {
		catalogError(w, offlinecatalog.ErrUnavailable)
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if !s.authorizeJSONMutation(w, r) {
		return
	}
	if len(r.Header.Values("Origin")) != 1 || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength < 0 || len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_catalog", "A bounded unencoded JSON request is required.")
		return
	}
	if r.URL.Path == "/api/security/catalog/clear" {
		if len(r.Header.Values("X-Tracebolt-Catalog-Revision")) != 0 {
			catalogError(w, offlinecatalog.ErrInvalid)
			return
		}
		var input struct {
			ExpectedRevision string `json:"expectedRevision"`
		}
		if !readObject(w, r, 1024, []string{"expectedRevision"}, &input) {
			return
		}
		if !catalogRevisionPattern.MatchString(input.ExpectedRevision) {
			catalogError(w, offlinecatalog.ErrInvalid)
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		_, _, now = s.catalogState()
		view, e := catalog.Clear(r.Context(), input.ExpectedRevision, now)
		release()
		if e != nil {
			catalogError(w, e)
			return
		}
		write(w, 200, view)
		return
	}
	revisions := r.Header.Values("X-Tracebolt-Catalog-Revision")
	if len(revisions) != 1 || !catalogRevisionPattern.MatchString(revisions[0]) {
		catalogError(w, offlinecatalog.ErrInvalid)
		return
	}
	// Reject an already stale edit before reading its file. The final atomic
	// replacement still checks the revision again after parsing/session lease.
	if catalog.View(now).Revision != revisions[0] {
		catalogError(w, offlinecatalog.ErrChanged)
		return
	}
	// At most one bounded body/parser operation; no unbounded waiting queue.
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "catalog_busy", "Catalog import is busy; retry shortly.")
		return
	}
	if r.ContentLength > offlinecatalog.MaxBytes {
		catalogError(w, offlinecatalog.ErrTooLarge)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(offlinecatalog.MaxBytes)))
	if e != nil {
		var maximum *http.MaxBytesError
		if errors.As(e, &maximum) {
			catalogError(w, offlinecatalog.ErrTooLarge)
		} else {
			catalogError(w, offlinecatalog.ErrInvalid)
		}
		return
	}
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	candidate, e := offlinecatalog.Parse(r.Context(), raw, now)
	if e != nil {
		catalogError(w, e)
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	_, _, now = s.catalogState()
	view, e := catalog.Replace(r.Context(), revisions[0], candidate, now)
	release()
	if e != nil {
		catalogError(w, e)
		return
	}
	write(w, 200, view)
}
func catalogError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, offlinecatalog.ErrTooLarge):
		fail(w, 413, "catalog_too_large", "Catalog exceeds the fixed size or record limit.")
	case errors.Is(e, offlinecatalog.ErrUnsupportedRelease):
		fail(w, 400, "unsupported_catalog_release", "Only the normalized Debian 13/Trixie format is supported.")
	case errors.Is(e, offlinecatalog.ErrChanged):
		fail(w, 409, "catalog_changed", "Catalog configuration changed; refresh before continuing.")
	case errors.Is(e, offlinecatalog.ErrUnavailable):
		fail(w, 404, "catalog_unavailable", "Offline catalog import is not configured for this profile.")
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		fail(w, 503, "catalog_unavailable", "Catalog import was interrupted.")
	default:
		fail(w, 400, "invalid_catalog", "Catalog format is invalid or unsupported.")
	}
}
