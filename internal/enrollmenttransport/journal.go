package enrollmenttransport

import (
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalwire"
	"net/http"
)

func (h *Ingress) journalRequest(w http.ResponseWriter, r *http.Request) {
	if h.journal == nil || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "journal_not_configured")
		return
	}
	if err := journalwire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, journalwire.ErrTooLarge) {
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, journalwire.BodyLimit(r.URL.Path)+1))
		if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > journalwire.BodyLimit(r.URL.Path) {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := journalwire.New(journalwire.Config{Origin: h.origin, Registry: authorizer, Now: h.now})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				storeFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, journalwire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, journalwire.ErrTooLarge) {
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
	var out any
	var err error
	switch r.URL.Path {
	case journalwire.GenerationPath:
		report, e := journalwire.DecodeGenerationReport(raw)
		if e != nil || !match(report.Sequence) {
			failure(w, 400, "invalid_journal_generation")
			return
		}
		out, err = h.store.AcceptJournalGeneration(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, report, h.now().UTC())
	case journalwire.PeekPath:
		if journalwire.DecodePeek(raw) != nil || !match(1) {
			failure(w, 400, "invalid_journal_request")
			return
		}
		out, err = h.store.PeekJournalRequest(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, h.now().UTC())
		if errors.Is(err, journalrequest.ErrConsumed) {
			current, e := h.store.JournalRequestStatus(r.Context(), identity.Approval.DeviceID, h.now().UTC())
			if e != nil {
				journalFailure(w, e)
				return
			}
			if current.Description.CertificateHash != identity.Issuance.CertificateHash {
				failure(w, 403, "agent_unauthorized")
				return
			}
			if current.State == journalrequest.Accepted {
				failure(w, 409, "journal_accepted")
				return
			}
		}
	case journalwire.ClaimPath:
		claim, e := journalwire.DecodeClaim(raw)
		if e != nil || !match(claim.Identity.Sequence) {
			failure(w, 400, "invalid_journal_request")
			return
		}
		out, err = h.store.ClaimJournalRequest(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, claim, h.now().UTC())
	case journalwire.ResultPath:
		result, e := journalwire.DecodeResult(raw)
		if e != nil || !match(result.Claim.Identity.Sequence) {
			failure(w, 400, "invalid_journal_result")
			return
		}
		out, err = h.journal.Accept(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, identity.Approval.DeviceID, result, h.now().UTC())
	case journalwire.StatusPath:
		input, e := journalwire.DecodeStatusInput(raw)
		if e != nil || !match(input.Identity.Sequence) {
			failure(w, 400, "invalid_journal_request")
			return
		}
		// Check the exact leaf again after body parsing; device ID alone cannot let
		// an old credential report status under replacement authority.
		current, e := h.store.JournalRequestStatus(r.Context(), identity.Approval.DeviceID, h.now().UTC())
		if e != nil {
			journalFailure(w, e)
			return
		}
		if current.Description.CertificateHash != identity.Issuance.CertificateHash {
			failure(w, 403, "agent_unauthorized")
			return
		}
		out, err = h.journal.LocalStatus(r.Context(), identity.Approval.DeviceID, input, h.now().UTC())
	default:
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		journalFailure(w, err)
		return
	}
	raw, err = json.Marshal(out)
	if err != nil {
		failure(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func journalFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, journalrequest.ErrNotFound):
		failure(w, 404, "journal_not_found")
	case errors.Is(err, enrollmentstore.ErrJournalGenerationStale):
		failure(w, 409, "journal_generation_stale")
	case errors.Is(err, journalrequest.ErrNotReady):
		failure(w, 409, "journal_not_ready")
	case errors.Is(err, journalrequest.ErrConsumed):
		failure(w, 409, "journal_consumed")
	case errors.Is(err, journalrequest.ErrConflict):
		failure(w, 409, "journal_conflict")
	case errors.Is(err, journalrequest.ErrExpired):
		failure(w, 409, "journal_expired")
	case errors.Is(err, journalrequest.ErrCanceled):
		failure(w, 409, "journal_canceled")
	case errors.Is(err, journalrequest.ErrInvalid):
		failure(w, 400, "invalid_journal_request")
	case errors.Is(err, journalcache.ErrCapacity), errors.Is(err, journalcache.ErrBusy):
		failure(w, 429, "journal_capacity")
	case errors.Is(err, enrollmentstore.ErrInventoryBusy):
		failure(w, 429, "storage_busy")
	default:
		storeFailure(w, err)
	}
}
