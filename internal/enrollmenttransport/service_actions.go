package enrollmenttransport

import (
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionmanager"
	"localrmm/internal/actionwire"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
)

// ConfigureServiceActions is called once during trusted construction, before
// either listener starts. It cannot enable a different store or transport.
func (h *Ingress) ConfigureServiceActions(m *actionmanager.Manager) error {
	if h == nil || h.actions != nil || !m.Matches(h.store) || m.TransportProfile() != actionmanager.Profile(h.profile) {
		return ErrConfiguration
	}
	h.actions = m
	return nil
}
func (h *Ingress) serviceActions(w http.ResponseWriter, r *http.Request) {
	if h.actions == nil || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "service_action_not_configured")
		return
	}
	if err := actionwire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, actionwire.ErrTooLarge) {
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, actionwire.BodyLimit(r.URL.Path)+1))
		if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > actionwire.BodyLimit(r.URL.Path) {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := actionwire.New(actionwire.Config{Origin: h.origin, Registry: authorizer, Now: h.now})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				storeFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, actionwire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, actionwire.ErrTooLarge) {
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
	case actionwire.CapabilitiesPath:
		c, e := actionwire.DecodeCapabilities(raw)
		if e != nil || !match(1) {
			failure(w, 400, "invalid_service_action")
			return
		}
		err = h.actions.Report(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, c)
	case actionwire.PeekPath:
		if actionwire.DecodePeek(raw) != nil || !match(1) {
			failure(w, 400, "invalid_service_action")
			return
		}
		out, err = h.actions.Peek(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash)
	case actionwire.ClaimPath:
		claim, e := actionwire.DecodeClaim(raw)
		if e != nil || !match(claim.Sequence) {
			failure(w, 400, "invalid_service_action")
			return
		}
		out, err = h.actions.Claim(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, claim)
	case actionwire.ResultPath:
		result, e := actionwire.DecodeResult(raw)
		if e != nil || !match(result.Sequence) {
			failure(w, 400, "invalid_service_action")
			return
		}
		err = h.actions.Accept(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, result)
	default:
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		serviceActionFailure(w, err)
		return
	}
	raw, err = json.Marshal(out)
	if err != nil || len(raw) > 16384 {
		failure(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func serviceActionFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, actionjob.ErrNotFound):
		failure(w, 404, "service_action_not_found")
	case errors.Is(e, actionjob.ErrConflict), errors.Is(e, actionjob.ErrConsumed):
		failure(w, 409, "service_action_consumed")
	case errors.Is(e, actionjob.ErrExpired):
		failure(w, 409, "service_action_expired")
	case errors.Is(e, actionjob.ErrInvalid):
		failure(w, 400, "service_action_invalid")
	case errors.Is(e, actionjob.ErrUnavailable), errors.Is(e, actionjob.ErrCapacity), errors.Is(e, actionmanager.ErrConfiguration):
		failure(w, 409, "service_action_unavailable")
	default:
		storeFailure(w, e)
	}
}
