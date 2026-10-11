package enrollmenttransport

import (
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"net/http"
	"time"
)

// ConfigureWindowsHistory attaches the exact manager-owned ephemeral cache.
// It is startup-only and cannot change collection profile or create local consent.
func (h *Ingress) ConfigureWindowsHistory(cache *windowshistorycache.Cache) error {
	if !h.valid() || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || cache == nil || !cache.Matches(h.store) || h.windowsHistory != nil {
		return ErrConfiguration
	}
	h.windowsHistory = cache
	return nil
}
func windowsHistoryPath(path string) bool {
	switch path {
	case windowshistorywire.CapabilityPath, windowshistorywire.PeekPath, windowshistorywire.ClaimPath, windowshistorywire.ResultPath, windowshistorywire.StatusPath:
		return true
	}
	return false
}

func (h *Ingress) windowsHistoryRequest(w http.ResponseWriter, r *http.Request) {
	if h.windowsHistory == nil || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || !h.windowsHistory.Matches(h.store) {
		failure(w, 404, "windows_history_not_configured")
		return
	}
	if err := windowshistorywire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, windowshistorywire.ErrTooLarge) {
			failure(w, 413, "payload_too_large")
		} else {
			failure(w, 400, "invalid_request")
		}
		return
	}
	var identity enrollmentstate.Snapshot
	var raw, certificate []byte
	var sequence uint64
	if h.profile == "tls" {
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
		certificate = r.TLS.PeerCertificates[0].Raw
		release, ok := h.admitCertificate(certificate)
		if !ok {
			failure(w, 429, "ingress_busy")
			return
		}
		defer release()
		var err error
		r = withVerifiedTLSCertificate(r)
		identity, err = h.store.AuthorizeCertificate(r.Context(), certificate, h.now())
		if err != nil {
			storeFailure(w, err)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(r.Body, windowshistorywire.BodyLimit(r.URL.Path)+1))
		if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > windowshistorywire.BodyLimit(r.URL.Path) {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := windowshistorywire.New(windowshistorywire.Config{Origin: h.origin, Registry: authorizer, Now: h.now})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			switch {
			case authorizer.busy:
				storeFailure(w, enrollmentstore.ErrBusy)
			case errors.Is(err, windowshistorywire.ErrUnavailable):
				failure(w, 503, "storage_unavailable")
			case errors.Is(err, windowshistorywire.ErrTooLarge):
				failure(w, 413, "payload_too_large")
			default:
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
		identity, raw, sequence, certificate = authorizer.snapshot, verified.Body, verified.Sequence, verified.CertificateDER
		if identity.Approval.DeviceID != verified.Agent.ID || identity.Issuance.CertificateHash != verified.Agent.FingerprintSHA256 {
			failure(w, 403, "agent_unauthorized")
			return
		}
	}
	device, cert := identity.Approval.DeviceID, identity.Issuance.CertificateHash
	match := func(n uint64) bool { return h.profile == "tls" || sequence == n }
	var out []byte
	var expiry time.Time
	var replyIdentity *windowshistoryrequest.Identity
	var err error
	switch r.URL.Path {
	case windowshistorywire.CapabilityPath:
		input, e := windowshistorywire.DecodeCapability(raw)
		if e != nil || !match(input.Sequence) {
			failure(w, 400, "invalid_windows_history_capability")
			return
		}
		reply, e := h.windowsHistory.ReportCapability(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowshistorywire.EncodeCapability(reply)
		}
	case windowshistorywire.PeekPath:
		if windowshistorywire.DecodePeek(raw) != nil || !match(1) {
			failure(w, 400, "invalid_windows_history_request")
			return
		}
		reply, e := h.windowsHistory.Peek(r.Context(), device, cert, h.now().UTC())
		err = e
		if err == nil {
			if reply == nil {
				out = []byte("null")
			} else {
				out, err = windowshistorywire.EncodeDescription(*reply)
				expiry = reply.ExpiresAt
				if cutoff := reply.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge); cutoff.Before(expiry) {
					expiry = cutoff
				}
				id := reply.Identity
				replyIdentity = &id
			}
		}
	case windowshistorywire.ClaimPath:
		input, e := windowshistorywire.DecodeClaim(raw)
		if e != nil || !match(input.Identity.Sequence) {
			failure(w, 400, "invalid_windows_history_request")
			return
		}
		reply, e := h.windowsHistory.Claim(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowshistorywire.EncodeGrant(reply)
			expiry = reply.Description.ExpiresAt
			if cutoff := reply.Description.HeaderCollectedAt.Add(windowshistoryrequest.MaxHeaderAge); cutoff.Before(expiry) {
				expiry = cutoff
			}
			id := reply.Description.Identity
			replyIdentity = &id
		}
	case windowshistorywire.ResultPath:
		input, e := windowshistorywire.DecodeResult(raw)
		if e != nil || !match(input.Claim.Identity.Sequence) {
			failure(w, 400, "invalid_windows_history_result")
			return
		}
		reply, e := h.windowsHistory.Accept(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowshistorywire.EncodeReceipt(reply)
			expiry = reply.ExpiresAt
		}
	case windowshistorywire.StatusPath:
		input, e := windowshistorywire.DecodeStatusInput(raw)
		if e != nil || !match(input.Claim.Identity.Sequence) {
			failure(w, 400, "invalid_windows_history_request")
			return
		}
		err = h.windowsHistory.ReportStatus(r.Context(), device, cert, input, h.now().UTC())
		if err == nil {
			out = []byte("{}")
		}
	default:
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		windowsHistoryFailure(w, err)
		return
	}
	// Authorization and immutable expiry are checked after parsing, commit and
	// encoding. An ambiguous/lost claim reply remains consumed; never recollect.
	now := h.now().UTC()
	current, err := h.store.AuthorizeCertificate(r.Context(), certificate, now)
	if err != nil {
		storeFailure(w, err)
		return
	}
	if r.Context().Err() != nil || current.Approval.DeviceID != device || current.Issuance.CertificateHash != cert || (h.profile == "tls" && !h.verifiedTLS(r, now)) {
		failure(w, 403, "agent_unauthorized")
		return
	}
	if !expiry.IsZero() && !now.Before(expiry) {
		failure(w, 409, "windows_history_request_expired")
		return
	}
	if replyIdentity != nil {
		if err := h.windowsHistory.AuthorizeReply(r.Context(), device, cert, *replyIdentity, h.now().UTC()); err != nil {
			windowsHistoryFailure(w, err)
			return
		}
	}
	if !expiry.IsZero() && !h.now().UTC().Before(expiry) {
		failure(w, 409, "windows_history_request_expired")
		return
	}
	if len(out) == 0 || len(out) > windowshistorywire.MaxMetadataBytes {
		failure(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(out)
}
func windowsHistoryFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, windowshistoryrequest.ErrInvalid), errors.Is(err, windowshistorywire.ErrContract):
		failure(w, 400, "invalid_windows_history_request")
	case errors.Is(err, windowshistoryrequest.ErrDisabled):
		failure(w, 409, "windows_history_disabled")
	case errors.Is(err, windowshistoryrequest.ErrConflict):
		failure(w, 409, "windows_history_request_conflict")
	case errors.Is(err, windowshistoryrequest.ErrConsumed):
		failure(w, 409, "windows_history_request_consumed")
	case errors.Is(err, windowshistoryrequest.ErrExpired):
		failure(w, 409, "windows_history_request_expired")
	case errors.Is(err, windowshistoryrequest.ErrCanceled):
		failure(w, 409, "windows_history_request_canceled")
	case errors.Is(err, windowshistorycache.ErrSession):
		failure(w, 409, "windows_history_operator_session_unavailable")
	case errors.Is(err, windowshistorycache.ErrUnavailable), errors.Is(err, enrollmentstore.ErrWindowsHistoryUnavailable):
		failure(w, 409, "windows_history_unavailable")
	case errors.Is(err, enrollmentstore.ErrWindowsHistoryCapacity):
		failure(w, 429, "windows_history_capacity")
	default:
		storeFailure(w, err)
	}
}
