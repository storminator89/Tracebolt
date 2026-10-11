package enrollmenttransport

import (
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"net/http"
	"time"
)

// ConfigureWindowsEventContent attaches the exact manager-owned ephemeral cache.
// It is startup-only and cannot change collection profile or create local consent.
func (h *Ingress) ConfigureWindowsEventContent(cache *windowseventcache.Cache) error {
	if !h.valid() || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || cache == nil || !cache.Matches(h.store) || h.windowsEvents != nil {
		return ErrConfiguration
	}
	h.windowsEvents = cache
	return nil
}
func windowsEventPath(path string) bool {
	switch path {
	case windowseventwire.CapabilityPath, windowseventwire.PeekPath, windowseventwire.ClaimPath, windowseventwire.ResultPath, windowseventwire.StatusPath:
		return true
	}
	return false
}

func (h *Ingress) windowsEventRequest(w http.ResponseWriter, r *http.Request) {
	if h.windowsEvents == nil || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || !h.windowsEvents.Matches(h.store) {
		failure(w, 404, "windows_event_content_not_configured")
		return
	}
	if err := windowseventwire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, windowseventwire.ErrTooLarge) {
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, windowseventwire.BodyLimit(r.URL.Path)+1))
		if err != nil || int64(len(raw)) != r.ContentLength || int64(len(raw)) > windowseventwire.BodyLimit(r.URL.Path) {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := windowseventwire.New(windowseventwire.Config{Origin: h.origin, Registry: authorizer, Now: h.now})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			switch {
			case authorizer.busy:
				storeFailure(w, enrollmentstore.ErrBusy)
			case errors.Is(err, windowseventwire.ErrUnavailable):
				failure(w, 503, "storage_unavailable")
			case errors.Is(err, windowseventwire.ErrTooLarge):
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
	var replyIdentity *windowseventrequest.Identity
	var err error
	switch r.URL.Path {
	case windowseventwire.CapabilityPath:
		input, e := windowseventwire.DecodeCapability(raw)
		if e != nil || !match(input.Sequence) {
			failure(w, 400, "invalid_windows_event_capability")
			return
		}
		reply, e := h.windowsEvents.ReportCapability(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowseventwire.EncodeCapability(reply)
		}
	case windowseventwire.PeekPath:
		if windowseventwire.DecodePeek(raw) != nil || !match(1) {
			failure(w, 400, "invalid_windows_event_request")
			return
		}
		reply, e := h.windowsEvents.Peek(r.Context(), device, cert, h.now().UTC())
		err = e
		if err == nil {
			if reply == nil {
				out = []byte("null")
			} else {
				out, err = windowseventwire.EncodeDescription(*reply)
				expiry = reply.ExpiresAt
				if cutoff := reply.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge); cutoff.Before(expiry) {
					expiry = cutoff
				}
				id := reply.Identity
				replyIdentity = &id
			}
		}
	case windowseventwire.ClaimPath:
		input, e := windowseventwire.DecodeClaim(raw)
		if e != nil || !match(input.Identity.Sequence) {
			failure(w, 400, "invalid_windows_event_request")
			return
		}
		reply, e := h.windowsEvents.Claim(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowseventwire.EncodeGrant(reply)
			expiry = reply.Description.ExpiresAt
			if cutoff := reply.Description.HeaderCollectedAt.Add(windowseventrequest.MaxHeaderAge); cutoff.Before(expiry) {
				expiry = cutoff
			}
			id := reply.Description.Identity
			replyIdentity = &id
		}
	case windowseventwire.ResultPath:
		input, e := windowseventwire.DecodeResult(raw)
		if e != nil || !match(input.Claim.Identity.Sequence) {
			failure(w, 400, "invalid_windows_event_result")
			return
		}
		reply, e := h.windowsEvents.Accept(r.Context(), device, cert, input, h.now().UTC())
		err = e
		if err == nil {
			out, err = windowseventwire.EncodeReceipt(reply)
			expiry = reply.ExpiresAt
		}
	case windowseventwire.StatusPath:
		input, e := windowseventwire.DecodeStatusInput(raw)
		if e != nil || !match(input.Claim.Identity.Sequence) {
			failure(w, 400, "invalid_windows_event_request")
			return
		}
		err = h.windowsEvents.ReportStatus(r.Context(), device, cert, input, h.now().UTC())
		if err == nil {
			out = []byte("{}")
		}
	default:
		failure(w, 404, "not_found")
		return
	}
	if err != nil {
		windowsEventFailure(w, err)
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
		failure(w, 409, "windows_event_request_expired")
		return
	}
	if replyIdentity != nil {
		if err := h.windowsEvents.AuthorizeReply(r.Context(), device, cert, *replyIdentity, h.now().UTC()); err != nil {
			windowsEventFailure(w, err)
			return
		}
	}
	if !expiry.IsZero() && !h.now().UTC().Before(expiry) {
		failure(w, 409, "windows_event_request_expired")
		return
	}
	if len(out) == 0 || len(out) > windowseventwire.MaxMetadataBytes {
		failure(w, 503, "storage_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(out)
}
func windowsEventFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, windowseventrequest.ErrInvalid), errors.Is(err, windowseventwire.ErrContract):
		failure(w, 400, "invalid_windows_event_request")
	case errors.Is(err, windowseventrequest.ErrDisabled):
		failure(w, 409, "windows_event_content_disabled")
	case errors.Is(err, windowseventrequest.ErrConflict):
		failure(w, 409, "windows_event_request_conflict")
	case errors.Is(err, windowseventrequest.ErrConsumed):
		failure(w, 409, "windows_event_request_consumed")
	case errors.Is(err, windowseventrequest.ErrExpired):
		failure(w, 409, "windows_event_request_expired")
	case errors.Is(err, windowseventrequest.ErrCanceled):
		failure(w, 409, "windows_event_request_canceled")
	case errors.Is(err, windowseventcache.ErrSession):
		failure(w, 409, "windows_event_operator_session_unavailable")
	case errors.Is(err, windowseventcache.ErrUnavailable), errors.Is(err, enrollmentstore.ErrWindowsEventUnavailable):
		failure(w, 409, "windows_event_content_unavailable")
	case errors.Is(err, enrollmentstore.ErrWindowsEventCapacity):
		failure(w, 429, "windows_event_content_capacity")
	default:
		storeFailure(w, err)
	}
}
