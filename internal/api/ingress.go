package api

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type LANObservationStore interface {
	SaveObservation(context.Context, lantrust.Agent, uint64, time.Time, model.Device, []byte, time.Time) (lanstore.Receipt, error)
}
type ingressHandler struct {
	registry  *lantrust.Registry
	store     LANObservationStore
	authority string
}

func NewLANIngressHandler(registry *lantrust.Registry, store LANObservationStore, origin string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if registry == nil || store == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || origin != "https://"+u.Host || u.Host != strings.ToLower(u.Host) || u.Port() == "443" {
		return nil, errors.New("explicit canonical HTTPS agent origin, registry and storage required")
	}
	return &ingressHandler{registry: registry, store: store, authority: u.Host}, nil
}
func (h *ingressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || !r.TLS.HandshakeComplete {
		fail(w, 403, "mtls_required", "Verified mutual TLS is required.")
		return
	}
	if r.Host != h.authority {
		fail(w, 403, "invalid_host", "Unexpected agent authority.")
		return
	}
	if r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		fail(w, 403, "agent_surface_only", "Browser and bearer credentials are not accepted on agent ingress.")
		return
	}
	agent, err := h.registry.Authenticate(r)
	if err != nil {
		if errors.Is(err, lantrust.ErrRegistryUnavailable) {
			fail(w, 503, "registry_unavailable", "Agent trust is unavailable.")
		} else {
			fail(w, 403, "agent_unauthorized", "Agent certificate is not approved.")
		}
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/agent/telemetry" || r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		fail(w, 404, "not_found", "Agent endpoint unavailable.")
		return
	}
	if len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_framing", "Chunked telemetry is unsupported.")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required", "JSON is required.")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, lanstore.MaxFrameBytes))
	if err != nil {
		fail(w, 413, "payload_too_large", "Telemetry frame exceeds its byte limit.")
		return
	}
	now := time.Now().UTC()
	frame, err := lanstore.ValidateFrame(raw, now)
	if err != nil {
		if errors.Is(err, lanstore.ErrStale) {
			fail(w, 409, "stale_sample", "Observation timestamps are outside the accepted window.")
		} else {
			fail(w, 400, "invalid_frame", "Telemetry did not match the bounded observation contract.")
		}
		return
	}
	// Recheck after parsing as well, so revocation during a slow body does not authorize a write.
	agent, err = h.registry.Authenticate(r)
	if err != nil {
		fail(w, 403, "agent_unauthorized", "Agent approval changed before telemetry commit.")
		return
	}
	receipt, err := h.store.SaveObservation(r.Context(), agent, frame.Sequence, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, now)
	if err != nil {
		switch {
		case errors.Is(err, lanstore.ErrReplay):
			fail(w, 409, "replayed_sample", "Sequence or observation is not newer; freshness was not refreshed.")
		case errors.Is(err, lanstore.ErrBinding):
			fail(w, 403, "agent_unauthorized", "Agent approval changed before telemetry commit.")
		default:
			fail(w, 503, "storage_unavailable", "Telemetry could not be durably stored.")
		}
		return
	}
	write(w, 200, receipt)
}
