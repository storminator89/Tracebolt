package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"localrmm/internal/debianversion"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/offlinecatalog"
	"net/http"
	"strings"
	"time"
)

const maxSecurityReviewResponseBytes = 65 * 1024

type securityReviewView struct {
	SchemaVersion    string                       `json:"schemaVersion"`
	DeviceID         string                       `json:"deviceId"`
	ServerNow        time.Time                    `json:"serverNow"`
	MaxAgeSeconds    int64                        `json:"maxAgeSeconds"`
	CollectionStatus string                       `json:"collectionStatus"`
	ReceivedAt       *time.Time                   `json:"receivedAt"`
	Sequence         *uint64                      `json:"sequence"`
	Review           *offlinecatalog.ReviewResult `json:"review"`
}

// Reviews are read-only, conditional interpretations of one current stored
// observation and one unverified imported catalog. They never alter CVE/update
// coverage, create cases, execute a package manager, or enter AI packets.
func (s *Server) securityReview(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "devices" || !validID(parts[3]) || parts[4] != "security" || parts[5] != "review" {
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_request", "This endpoint does not accept a body or query parameters.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	s.mu.RLock()
	provider, profile, slots, comparator := s.lanPackages, s.aiCollectionProfile, s.catalogReviews, s.reviewComparator
	s.mu.RUnlock()
	catalog, _, now := s.catalogState()
	out := securityReviewView{SchemaVersion: "tracebolt.advisory-review-view.v1", DeviceID: parts[3], ServerNow: now, MaxAgeSeconds: int64(lanstore.SampleMaxAge / time.Second), CollectionStatus: "not_configured"}
	if provider == nil || profile != enrollmentcrypto.CollectionProfilePackages || slots == nil || catalog == nil {
		devices, e := s.devices()
		if e != nil {
			s.internal(w)
			return
		}
		for _, d := range devices {
			if d.ID == parts[3] {
				write(w, 200, out)
				return
			}
		}
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "review_busy", "Advisory review is busy; retry shortly.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	source, e := provider(ctx, parts[3], now)
	if e != nil {
		if operatorStillActive(w, r) {
			s.securityReviewError(w, e)
		}
		return
	}
	if source.DeviceID != parts[3] {
		s.internal(w)
		return
	}
	out.CollectionStatus, out.ReceivedAt, out.Sequence = source.Status, source.ReceivedAt, source.Sequence
	if source.Status != "fresh" {
		if operatorStillActive(w, r) {
			write(w, 200, out)
		}
		return
	}
	if !reviewSourceFresh(source, now) {
		s.internal(w)
		return
	}
	revision := catalog.View(now).Revision
	if comparator == nil {
		comparator = debianversion.Comparator{}
	}
	result, e := catalog.Review(ctx, revision, *source.Snapshot, comparator)
	if e != nil {
		if operatorStillActive(w, r) {
			s.securityReviewError(w, e)
		}
		return
	}
	// Recheck current authority/sequence after the bounded pure computation. A
	// catalog replacement or a new/expired/revoked observation discards the result.
	_, _, finished := s.catalogState()
	current, e := provider(ctx, parts[3], finished)
	if e != nil {
		if operatorStillActive(w, r) {
			s.securityReviewError(w, e)
		}
		return
	}
	if !reviewSourceFresh(current, finished) || !sameReviewSource(source, current) || catalog.View(finished).Revision != revision {
		fail(w, 409, "review_changed", "Observation or catalog changed; refresh before reviewing.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if ctx.Err() != nil {
		s.securityReviewError(w, ctx.Err())
		return
	}
	out.ServerNow = finished
	out.Review = &result
	raw, e := json.Marshal(out)
	if e != nil || len(raw)+1 > maxSecurityReviewResponseBytes {
		s.internal(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(append(raw, '\n'))
}

func reviewSourceFresh(v enrollmentstore.PackageView, now time.Time) bool {
	return v.Status == "fresh" && v.Snapshot != nil && v.Sequence != nil && *v.Sequence > 0 && v.ReceivedAt != nil && !now.Before(*v.ReceivedAt) && !now.Before(v.Snapshot.CollectedAt) && now.Sub(*v.ReceivedAt) <= lanstore.SampleMaxAge && now.Sub(v.Snapshot.CollectedAt) <= lanstore.SampleMaxAge
}
func sameReviewSource(a, b enrollmentstore.PackageView) bool {
	if a.DeviceID != b.DeviceID || a.Sequence == nil || b.Sequence == nil || *a.Sequence != *b.Sequence || a.ReceivedAt == nil || b.ReceivedAt == nil || !a.ReceivedAt.Equal(*b.ReceivedAt) {
		return false
	}
	ar, ae := json.Marshal(a.Snapshot)
	br, be := json.Marshal(b.Snapshot)
	return ae == nil && be == nil && sha256.Sum256(ar) == sha256.Sum256(br)
}
func (s *Server) securityReviewError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device not found.")
	case errors.Is(e, enrollmentstore.ErrBusy), errors.Is(e, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Stored package observations are busy; retry shortly.")
	case errors.Is(e, offlinecatalog.ErrChanged):
		fail(w, 409, "review_changed", "Observation or catalog changed; refresh before reviewing.")
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		fail(w, 503, "review_unavailable", "Advisory review was interrupted.")
	default:
		s.internal(w)
	}
}
