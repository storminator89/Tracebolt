package api

import (
	"errors"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
	"net/http"
	"time"
)

type httpTestIngress struct {
	verifier *signedhttp.Verifier
	store    LANObservationStore
}

// NewHTTPTestIngressHandler must only be wired to the separate plaintext test
// profile with its own approval/replay database. It is never a TLS fallback.
func NewHTTPTestIngressHandler(registry *lantrust.Registry, store LANObservationStore, origin string) (http.Handler, error) {
	if store == nil {
		return nil, errors.New("durable observation store is required")
	}
	v, e := signedhttp.New(signedhttp.Config{Origin: origin, Registry: registry})
	if e != nil {
		return nil, e
	}
	return &httpTestIngress{v, store}, nil
}
func (h *httpTestIngress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	verified, e := h.verifier.Verify(r)
	if e != nil {
		status, code := 403, "signed_agent_unauthorized"
		switch {
		case errors.Is(e, signedhttp.ErrTooLarge):
			status, code = 413, "payload_too_large"
		case errors.Is(e, signedhttp.ErrUnavailable):
			status, code = 503, "registry_unavailable"
		case errors.Is(e, signedhttp.ErrRequest):
			status, code = 400, "invalid_signed_request"
		}
		fail(w, status, code, "Signed HTTP test telemetry could not be accepted.")
		return
	}
	now := time.Now().UTC()
	frame, e := lanstore.ValidateFrame(verified.Body, now)
	if e != nil {
		status, code := 400, "invalid_frame"
		if errors.Is(e, lanstore.ErrStale) {
			status, code = 409, "stale_sample"
		}
		fail(w, status, code, "Telemetry did not match the bounded observation contract.")
		return
	}
	if verified.Sequence != frame.Sequence || !verified.SignedAt.Equal(frame.Observation.GeneratedAt) {
		fail(w, 400, "signature_frame_mismatch", "Signature metadata and observation must match.")
		return
	}
	// SaveObservation rechecks durable approval/revocation and commits sample and
	// replay state together. Verification alone never consumes a sequence number.
	receipt, e := h.store.SaveObservation(r.Context(), verified.Agent, frame.Sequence, frame.Observation.GeneratedAt, frame.Observation.Observation, verified.Body, now)
	if e != nil {
		switch {
		case errors.Is(e, lanstore.ErrReplay):
			fail(w, 409, "replayed_sample", "Sequence or observation is not newer; freshness was not refreshed.")
		case errors.Is(e, lanstore.ErrBinding):
			fail(w, 403, "agent_unauthorized", "Agent approval changed before telemetry commit.")
		default:
			fail(w, 503, "storage_unavailable", "Telemetry could not be durably stored.")
		}
		return
	}
	write(w, 200, receipt)
}
