package enrollmenttransport

import (
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/systemwire"
	"net/http"
)

// inventory runs under the listener's existing global admission slot. Identity
// exclusion is acquired only after TLS or HTTP signature possession verification.
func (h *Ingress) systemObservation(w http.ResponseWriter, r *http.Request) {
	if h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "system_inventory_not_configured")
		return
	}
	if err := systemwire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, systemwire.ErrTooLarge) {
			failure(w, 413, "payload_too_large")
		} else {
			failure(w, 400, "invalid_request")
		}
		return
	}
	var identity enrollmentstate.Snapshot
	var raw []byte
	var sequence uint64
	var release func()
	if h.profile == "tls" {
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
		var ok bool
		release, ok = h.admitCertificate(r.TLS.PeerCertificates[0].Raw)
		if !ok {
			w.Header().Set("Retry-After", "15")
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
		if err != nil || len(raw) > systemwire.MaxBodyBytes || int64(len(raw)) != r.ContentLength {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := systemwire.New(systemwire.Config{Origin: h.origin, Registry: authorizer})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				storeFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, systemwire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, systemwire.ErrTooLarge) {
				failure(w, 413, "payload_too_large")
			} else {
				failure(w, 403, "agent_unauthorized")
			}
			return
		}
		der := verified.CertificateDER
		var ok bool
		release, ok = h.admitCertificate(der)
		if !ok {
			w.Header().Set("Retry-After", "15")
			failure(w, 429, "ingress_busy")
			return
		}
		defer release()
		identity, raw, sequence = authorizer.snapshot, verified.Body, verified.Sequence
		if identity.Approval.DeviceID != verified.Agent.ID || identity.Issuance.CertificateHash != verified.Agent.FingerprintSHA256 {
			failure(w, 403, "agent_unauthorized")
			return
		}
	}
	frame, err := systemwire.Decode(raw)
	if err != nil || (h.profile == "http-test" && frame.Sequence != sequence) {
		failure(w, 400, "invalid_system_observation")
		return
	}
	receipt, err := h.store.SaveSystemObservation(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now().UTC())
	if err != nil {
		if errors.Is(err, enrollmentstore.ErrSystemConflict) {
			failure(w, 409, "system_observation_conflict")
		} else if errors.Is(err, enrollmentstore.ErrSystemCapacity) {
			failure(w, 409, "system_observation_resource_limit")
		} else if errors.Is(err, enrollmentstore.ErrInventoryBusy) {
			w.Header().Set("Retry-After", "15")
			failure(w, 429, "storage_busy")
		} else {
			storeFailure(w, err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}
