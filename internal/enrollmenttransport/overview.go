package enrollmenttransport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// overview runs under the listener's existing global admission slot. Identity
// exclusion is acquired only after TLS or HTTP signature possession verification.
func (h *Ingress) overview(w http.ResponseWriter, r *http.Request) {
	if h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "overview_not_configured")
		return
	}
	if err := overviewwire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, overviewwire.ErrTooLarge) {
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, overviewwire.MaxBodyBytes+1))
		if err != nil || len(raw) > overviewwire.MaxBodyBytes || int64(len(raw)) != r.ContentLength {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := overviewwire.New(overviewwire.Config{Origin: h.origin, Registry: authorizer})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				overviewStoreFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, overviewwire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, overviewwire.ErrTooLarge) {
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
	operation := strings.TrimPrefix(r.URL.Path, overviewwire.PathPrefix)
	message, err := overviewwire.DecodeMessage(operation, raw)
	if err != nil || (h.profile == "http-test" && sequence != message.Sequence) {
		failure(w, 400, "invalid_overview_request")
		return
	}
	binding := enrollmentstore.OverviewBinding{Section: message.Section, Sequence: message.Sequence, GenerationID: message.GenerationID, ManifestHash: message.ManifestHash}
	now := h.now().UTC()
	ctx := enrollmentstore.WithOverviewClock(r.Context(), h.now)
	var result any
	switch operation {
	case "begin":
		var v overviewledger.BeginReceipt
		v, err = h.store.OverviewBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, *message.Manifest, now)
		result = map[string]any{"startedAt": v.StartedAt, "expiresAt": v.ExpiresAt}
	case "append":
		var v overviewledger.ChunkReceipt
		v, err = h.store.OverviewAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, *message.Chunk, now)
		result = map[string]any{"ordinal": v.Ordinal, "rows": v.Rows, "receivedAt": v.ReceivedAt}
	case "finalize":
		var v overviewledger.Completion
		v, err = h.store.OverviewFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
		result = map[string]any{"collectedAt": v.Manifest.CollectedAt, "completedAt": v.CompletedAt}
	case "abort":
		err = h.store.OverviewAbort(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
		result = map[string]any{"aborted": true}
	case "failure":
		var v enrollmentstore.OverviewFailureReceipt
		v, err = h.store.OverviewFailure(ctx, identity.InvitationID, identity.Issuance.CertificateHash, enrollmentstore.OverviewFailureReport{Section: message.Section, Sequence: message.Sequence, GenerationID: message.GenerationID, AttemptedAt: message.FailureAt, Reason: message.FailureReason}, now)
		result = map[string]any{"attemptedAt": v.Failure.AttemptedAt, "receivedAt": v.ReceivedAt, "reason": v.Failure.Reason}
	case "status":
		var v enrollmentstore.OverviewSectionStatus
		v, err = h.store.OverviewStatus(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
		if err == nil && v.Transfer == nil {
			err = enrollmentstore.ErrStorage
		}
		if err == nil {
			x := v.Transfer
			completed := ""
			if !x.CompletedAt.IsZero() {
				completed = x.CompletedAt.UTC().Format(time.RFC3339Nano)
			}
			result = map[string]any{"state": x.State, "acceptedChunks": x.AcceptedChunks, "expectedChunks": x.Manifest.ChunkCount, "acceptedRows": x.AcceptedRows, "startedAt": x.StartedAt, "expiresAt": x.ExpiresAt, "completedAt": completed}
		}
	}
	if err != nil {
		overviewStoreFailure(w, err)
		return
	}
	digest := sha256.Sum256(raw)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": "tracebolt.overview-response.v1", "operation": operation, "section": message.Section, "sequence": strconv.FormatUint(message.Sequence, 10), "generationId": message.GenerationID, "manifestHash": message.ManifestHash, "requestSha256": hex.EncodeToString(digest[:]), "result": result})
}
func overviewStoreFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollmentstore.ErrOverviewNotConfigured):
		failure(w, 409, "overview_not_configured")
	case errors.Is(err, enrollmentstore.ErrOverviewBusy), errors.Is(err, enrollmentstore.ErrBusy):
		w.Header().Set("Retry-After", "15")
		failure(w, 429, "storage_busy")
	case errors.Is(err, overviewledger.ErrQuota), errors.Is(err, inventoryledger.ErrQuota):
		failure(w, 409, "overview_resource_limit")
	case errors.Is(err, overviewledger.ErrConflict), errors.Is(err, overviewledger.ErrIncomplete), errors.Is(err, overviewledger.ErrExpired), errors.Is(err, overviewledger.ErrNotFound):
		failure(w, 409, "overview_state_conflict")
	case errors.Is(err, overviewledger.ErrInvalid):
		failure(w, 400, "invalid_overview_request")
	default:
		storeFailure(w, err)
	}
}
