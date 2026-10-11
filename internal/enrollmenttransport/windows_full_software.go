package enrollmenttransport

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsfullsoftwarewire"
)

// Separate purpose-bound ingress, under the existing listener/global and
// per-certificate admission bounds. Public certificate lookup is never proof.
func (h *Ingress) windowsFullSoftware(w http.ResponseWriter, r *http.Request) {
	if h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		failure(w, 404, "not_found")
		return
	}
	if e := windowsfullsoftwarewire.ValidateShape(r, h.authority, h.profile); e != nil {
		if errors.Is(e, windowsfullsoftwarewire.ErrTooLarge) {
			failure(w, 413, "payload_too_large")
		} else {
			failure(w, 400, "windows_full_software_invalid")
		}
		return
	}
	var identity enrollmentstate.Snapshot
	var raw []byte
	var sequence uint64
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
		var e error
		identity, e = h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
		if e != nil {
			storeFailure(w, e)
			return
		}
		raw, e = io.ReadAll(io.LimitReader(r.Body, windowsfullsoftware.MaxChunkBytes+1))
		if e != nil || len(raw) > windowsfullsoftware.MaxChunkBytes || int64(len(raw)) != r.ContentLength {
			failure(w, 400, "windows_full_software_invalid")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		auth := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, e := windowsfullsoftwarewire.New(windowsfullsoftwarewire.Config{Origin: h.origin, Registry: auth, Now: h.now})
		if e != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, e := verifier.Verify(r)
		if e != nil {
			if auth.busy {
				failure(w, 429, "storage_busy")
			} else if errors.Is(e, windowsfullsoftwarewire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
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
		identity, raw, sequence = auth.snapshot, verified.Body, verified.Sequence
		if identity.Approval.DeviceID != verified.Agent.ID || identity.Issuance.CertificateHash != verified.Agent.FingerprintSHA256 {
			failure(w, 403, "agent_unauthorized")
			return
		}
	}
	m, e := windowsfullsoftware.DecodeMessage(raw)
	if e != nil || m.Operation != strings.TrimPrefix(r.URL.Path, windowsfullsoftwarewire.PathPrefix) || m.DeviceID != identity.Approval.DeviceID || h.profile == "http-test" && m.WireSequence() != sequence {
		failure(w, 400, "windows_full_software_invalid")
		return
	}
	ctx := enrollmentstore.WithWindowsFullSoftwareClock(r.Context(), h.now)
	ctx = enrollmentstore.WithWindowsFullSoftwareIngressOrigin(ctx, h.origin)
	receipt, e := h.store.ApplyWindowsFullSoftware(ctx, identity.InvitationID, identity.Issuance.CertificateHash, m, raw, h.now().UTC())
	if e != nil {
		switch {
		case errors.Is(e, windowsfullsoftware.ErrInvalid):
			failure(w, 400, "windows_full_software_invalid")
		case errors.Is(e, windowsfullsoftware.ErrConflict), errors.Is(e, windowsfullsoftware.ErrExpired):
			failure(w, 409, "windows_full_software_restart_required")
		case errors.Is(e, windowsfullsoftware.ErrBudget):
			failure(w, 409, "windows_full_software_resource_limit")
		case errors.Is(e, windowsfullsoftware.ErrUnavailable):
			failure(w, 409, "windows_full_software_unavailable")
		default:
			storeFailure(w, e)
		}
		return
	}
	body, e := json.Marshal(receipt)
	if e != nil || len(body) > 2048 {
		failure(w, 503, "storage_unavailable")
		return
	}
	// Marshal may cross scope, revocation or original-expiry boundaries. This
	// read-only final authority check cannot refresh the durable receipt.
	finalNow, e := h.store.RecheckWindowsFullSoftware(ctx, identity.InvitationID, identity.Issuance.CertificateHash, m.Consent, h.now().UTC())
	if e != nil {
		storeFailure(w, e)
		return
	}
	if m.Manifest != nil && !finalNow.Before(m.Manifest.ExpiresAt) || m.AttemptedAt != nil && !finalNow.Before(m.AttemptedAt.Add(windowsfullsoftware.Retention)) {
		failure(w, 409, "windows_full_software_restart_required")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
