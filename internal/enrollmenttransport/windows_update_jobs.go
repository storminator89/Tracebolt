package enrollmenttransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsupdatejob"
)

const windowsUpdateJobsPrefix = "/v1/windows-update-jobs/"

// ConfigureWindowsUpdateJobs is a trusted, once-only construction seam. Merely
// starting ingress never provisions a key, local executor, grant, or job store.
// A file-backed source fixture or a different enrollment store cannot be wired.
func (h *Ingress) ConfigureWindowsUpdateJobs(m *windowsupdatejob.Manager) error {
	if !h.valid() || h.windowsUpdateJobs != nil || h.windowsUpdateRegistry != nil || !m.EnrollmentOwned() || !m.OperatorPolicyConfigured() || !m.MatchesStore(h.store) || !m.MatchesBinding(h.store.Config().Binding) || h.profile != "tls" || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return ErrConfiguration
	}
	h.windowsUpdateJobs = m
	return nil
}

// ConfigureWindowsUpdateRegistry is explicit trusted startup, not registration.
func (h *Ingress) ConfigureWindowsUpdateRegistry(registry *windowsupdatejob.Registry) error {
	if !h.valid() || registry == nil || h.windowsUpdateJobs != nil || h.windowsUpdateRegistry != nil || h.profile != "tls" || !registry.MatchesBinding(h.store.Config().Binding) {
		return ErrConfiguration
	}
	for _, m := range registry.Managers() {
		if !m.MatchesStore(h.store) {
			return ErrConfiguration
		}
	}
	h.windowsUpdateRegistry = registry
	return nil
}
func windowsUpdateJobBodyLimit(path string) int64 {
	switch path {
	case windowsUpdateJobsPrefix + "poll":
		return 2
	case windowsUpdateJobsPrefix + "readiness-claim", windowsUpdateJobsPrefix + "install-claim", windowsUpdateJobsPrefix + "retire-claim":
		return 128
	case windowsUpdateJobsPrefix + "report":
		return windowsupdatejob.MaxRelayBytes
	default:
		return 0
	}
}

// Framing is deliberately independent of the service-action and signed-HTTP
// protocols. Observer certificate possession never authenticates an executor.
func validWindowsUpdateJobRequest(r *http.Request, authority string) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.Host != authority || windowsUpdateJobBodyLimit(r.URL.Path) == 0 || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Scheme != "" && r.URL.Scheme != "https" || r.URL.Host != "" && r.URL.Host != authority || r.RequestURI != "" && r.RequestURI != r.URL.Path || r.Body == nil || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return false
	}
	size, contentTypes, lengths := 128, 0, 0
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "origin" || lower == "authorization" || lower == "proxy-authorization" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-fetch-") || strings.HasPrefix(lower, "x-tracebolt-") || lower == "content-encoding" || lower == "trailer" || lower == "transfer-encoding" || lower == "expect" || lower == "upgrade" || lower == "host" {
			return false
		}
		if lower == "content-type" {
			contentTypes += len(values)
			if len(values) != 1 || values[0] != "application/json" {
				return false
			}
		}
		if lower == "content-length" {
			lengths += len(values)
			if len(values) != 1 || values[0] != strconv.FormatInt(r.ContentLength, 10) {
				return false
			}
		}
		for _, value := range values {
			size += len(key) + len(value) + 4
			if size > signedhttp.MaxHeaderBytes {
				return false
			}
		}
	}
	return contentTypes == 1 && lengths <= 1
}

func decodeWindowsUpdateJobClaim(raw []byte) (string, bool) {
	var claim struct {
		JobID string `json:"jobId"`
	}
	if json.Unmarshal(raw, &claim) != nil || !enrollmentcrypto.ValidID(claim.JobID, "update_") {
		return "", false
	}
	canonical, err := json.Marshal(claim)
	return claim.JobID, err == nil && bytes.Equal(raw, canonical)
}

func (h *Ingress) windowsUpdateJobRequest(w http.ResponseWriter, r *http.Request) {
	if h.windowsUpdateJobs == nil && h.windowsUpdateRegistry == nil || h.profile != "tls" || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		failure(w, http.StatusNotFound, "windows_update_jobs_not_configured")
		return
	}
	if r == nil || r.URL == nil || windowsUpdateJobBodyLimit(r.URL.Path) == 0 {
		failure(w, http.StatusNotFound, "not_found")
		return
	}
	if !validWindowsUpdateJobRequest(r, h.authority) {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	limit := windowsUpdateJobBodyLimit(r.URL.Path)
	if r.ContentLength > limit {
		failure(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	if !h.verifiedTLS(r, h.now()) {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	release, ok := h.admitCertificate(r.TLS.PeerCertificates[0].Raw)
	if !ok {
		w.Header().Set("Retry-After", "15")
		failure(w, http.StatusTooManyRequests, "ingress_busy")
		return
	}
	defer release()
	r = withVerifiedTLSCertificate(r)
	// The same authenticated leaf and trusted live clock reach the manager's
	// enrollment-owned transaction, including its final current-leaf check.
	r = r.WithContext(enrollmentstore.WithOverviewClock(r.Context(), h.now))
	identity, err := h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
	if err != nil {
		storeFailure(w, err)
		return
	}
	// Route only from the currently authenticated identity, before reading or
	// interpreting a claimed target, job ID, or signed report envelope.
	manager := h.windowsUpdateJobs
	if h.windowsUpdateRegistry != nil {
		manager = h.windowsUpdateRegistry.Manager(identity.Approval.DeviceID)
	}
	if manager == nil || identity.Approval.DeviceID != manager.Binding().DeviceID || "sha256:"+identity.Issuance.CertificateHash != manager.Binding().IncarnationDigest {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > limit {
		failure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.verifiedTLS(r, h.now()) {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	out := []byte("{}")
	switch r.URL.Path {
	case windowsUpdateJobsPrefix + "poll":
		if !bytes.Equal(raw, []byte("{}")) {
			failure(w, http.StatusBadRequest, "invalid_request")
			return
		}
		pending, e := manager.Pending(r.Context())
		err = e
		if err == nil {
			out, err = json.Marshal(pending)
		}
	case windowsUpdateJobsPrefix + "readiness-claim", windowsUpdateJobsPrefix + "install-claim", windowsUpdateJobsPrefix + "retire-claim":
		id, ok := decodeWindowsUpdateJobClaim(raw)
		if !ok {
			failure(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if r.URL.Path == windowsUpdateJobsPrefix+"readiness-claim" {
			out, err = manager.ClaimReadiness(r.Context(), id)
		} else if r.URL.Path == windowsUpdateJobsPrefix+"retire-claim" {
			out, err = manager.ClaimRetirement(r.Context(), id)
		} else {
			out, err = manager.Claim(r.Context(), id)
		}
	case windowsUpdateJobsPrefix + "report":
		// Report alone verifies canonical fixed-shape, purpose-bound metadata
		// signed by the separately pinned executor key. Never call Submit.
		err = manager.Report(r.Context(), raw)
	}
	if err != nil {
		windowsUpdateJobFailure(w, err)
		return
	}
	// Claims have already durably consumed delivery. Any final rejection or
	// response loss must never return or automatically retry an envelope.
	if !h.verifiedTLS(r, h.now()) {
		failure(w, http.StatusForbidden, "agent_unauthorized")
		return
	}
	if len(out) == 0 || len(out) > windowsupdatejob.MaxRelayBytes {
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func windowsUpdateJobFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, windowsupdatejob.ErrInvalid):
		failure(w, http.StatusBadRequest, "windows_update_job_invalid")
	case errors.Is(err, windowsupdatejob.ErrAuthority):
		failure(w, http.StatusForbidden, "agent_unauthorized")
	case errors.Is(err, windowsupdatejob.ErrConsumed), errors.Is(err, windowsupdatejob.ErrConflict):
		failure(w, http.StatusConflict, "windows_update_job_consumed")
	case errors.Is(err, windowsupdatejob.ErrExpired):
		failure(w, http.StatusConflict, "windows_update_job_expired")
	case errors.Is(err, windowsupdatejob.ErrUnavailable):
		failure(w, http.StatusConflict, "windows_update_job_unavailable")
	case errors.Is(err, windowsupdatejob.ErrIntegrity), errors.Is(err, windowsupdatejob.ErrUncertain):
		failure(w, http.StatusServiceUnavailable, "storage_unavailable")
	default:
		storeFailure(w, err)
	}
}
