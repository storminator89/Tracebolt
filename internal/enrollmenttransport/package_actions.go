package enrollmenttransport

import (
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packagewire"
	"net/http"
)

// ConfigurePackageActions is called once during trusted construction, before
// either listener starts. It cannot enable a different store or transport.
func (h *Ingress) ConfigurePackageActions(m *packagecontroller.Manager) error {
	if h == nil || h.packages != nil || !m.MatchesBinding(h.store.Config().Binding) || m.TransportProfile() != map[string]string{"tls": "production-tls", "http-test": "disposable-http-test"}[h.profile] {
		return ErrConfiguration
	}
	h.packages = m
	return nil
}
func (h *Ingress) packageActions(w http.ResponseWriter, r *http.Request) {
	if h.packages == nil || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "package_action_not_configured")
		return
	}
	if err := packagewire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, packagewire.ErrTooLarge) {
			failure(w, 413, "payload_too_large")
		} else {
			failure(w, 400, "invalid_request")
		}
		return
	}
	var identity enrollmentstate.Snapshot
	var raw []byte
	var seq uint64
	if h.profile == "tls" {
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
		release, ok := h.admitCertificate(r.TLS.PeerCertificates[0].Raw)
		if !ok {
			failure(w, 429, "ingress_busy")
			return
		}
		defer release()
		var err error
		identity, err = h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
		if err != nil {
			storeFailure(w, err)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, packagewire.BodyLimit(r.URL.Path)+1))
		if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > packagewire.BodyLimit(r.URL.Path) {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := packagewire.New(packagewire.Config{Origin: h.origin, Registry: authorizer, Now: h.now})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				storeFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, packagewire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, packagewire.ErrTooLarge) {
				failure(w, 413, "payload_too_large")
			} else {
				failure(w, 403, "agent_unauthorized")
			}
			return
		}
		release, ok := h.admitCertificate(verified.CertificateDER)
		if !ok {
			failure(w, 429, "ingress_busy")
			return
		}
		defer release()
		identity, raw, seq = authorizer.snapshot, verified.Body, verified.Sequence
		if identity.Approval.DeviceID != verified.Agent.ID || identity.Issuance.CertificateHash != verified.Agent.FingerprintSHA256 {
			failure(w, 403, "agent_unauthorized")
			return
		}
	}

	match := func(n uint64) bool { return h.profile == "tls" || seq == n }
	var out any = struct{}{}
	var err error
	switch r.URL.Path {
	case packagewire.CapabilitiesPath:
		c, e := packagewire.DecodeCapabilities(raw)
		if e != nil || !match(1) {
			failure(w, 400, "invalid_package_action")
			return
		}
		err = h.packages.Report(r.Context(), identity.Approval.DeviceID, "sha256:"+identity.Issuance.CertificateHash, c)
	case packagewire.PeekPath:
		if packagewire.DecodePeek(raw) != nil || !match(1) {
			failure(w, 400, "invalid_package_action")
			return
		}
		out, err = h.packages.Peek(r.Context(), identity.Approval.DeviceID, "sha256:"+identity.Issuance.CertificateHash)
	case packagewire.ClaimPath:
		claim, e := packagewire.DecodeClaim(raw)
		if e != nil || !match(claim.Sequence) {
			failure(w, 400, "invalid_package_action")
			return
		}
		out, err = h.packages.Claim(r.Context(), identity.Approval.DeviceID, "sha256:"+identity.Issuance.CertificateHash, claim)
	case packagewire.ResultPath:
		result, e := packagewire.DecodeResult(raw)
		if e != nil || !match(result.Sequence) {
			failure(w, 400, "invalid_package_action")
			return
		}
		err = h.packages.Accept(r.Context(), identity.Approval.DeviceID, "sha256:"+identity.Issuance.CertificateHash, result)
	default:
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		packageActionFailure(w, err)
		return
	}
	raw, err = json.Marshal(out)
	if err != nil || len(raw) > packagewire.MaxBodyBytes {
		failure(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func packageActionFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, packageupdate.ErrNotFound):
		failure(w, 404, "package_action_not_found")
	case errors.Is(e, packageupdate.ErrConflict):
		failure(w, 409, "package_action_consumed")
	case errors.Is(e, packageupdate.ErrExpired):
		failure(w, 409, "package_action_expired")
	case errors.Is(e, packageupdate.ErrInvalid):
		failure(w, 400, "package_action_invalid")
	case errors.Is(e, packageupdate.ErrUnavailable), errors.Is(e, packageupdate.ErrCapacity), errors.Is(e, packagecontroller.ErrConfiguration):
		failure(w, 409, "package_action_unavailable")
	default:
		storeFailure(w, e)
	}
}
