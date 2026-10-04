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
	"localrmm/internal/inventorywire"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// inventory runs under the listener's existing global admission slot. Identity
// exclusion is acquired only after TLS or HTTP signature possession verification.
func (h *Ingress) inventory(w http.ResponseWriter, r *http.Request) {
	if h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		failure(w, 404, "inventory_not_configured")
		return
	}
	if err := inventorywire.ValidateShape(r, h.authority, h.profile); err != nil {
		if errors.Is(err, inventorywire.ErrTooLarge) {
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
		raw, err = io.ReadAll(io.LimitReader(r.Body, inventorywire.MaxBodyBytes+1))
		if err != nil || len(raw) > inventorywire.MaxBodyBytes || int64(len(raw)) != r.ContentLength {
			failure(w, 400, "invalid_request")
			return
		}
		if !h.verifiedTLS(r, h.now()) {
			failure(w, 403, "agent_unauthorized")
			return
		}
	} else {
		authorizer := &publicAuthorizer{store: h.store, ctx: r.Context(), now: h.now}
		verifier, err := inventorywire.New(inventorywire.Config{Origin: h.origin, Registry: authorizer})
		if err != nil {
			failure(w, 503, "storage_unavailable")
			return
		}
		verified, err := verifier.Verify(r)
		if err != nil {
			if authorizer.busy {
				inventoryStoreFailure(w, enrollmentstore.ErrBusy)
			} else if errors.Is(err, inventorywire.ErrUnavailable) {
				failure(w, 503, "storage_unavailable")
			} else if errors.Is(err, inventorywire.ErrTooLarge) {
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
	operation := strings.TrimPrefix(r.URL.Path, inventorywire.PathPrefix)
	message, err := inventorywire.DecodeMessage(operation, raw)
	if err != nil || (h.profile == "http-test" && sequence != message.Sequence) {
		failure(w, 400, "invalid_inventory_request")
		return
	}
	binding := enrollmentstore.InventoryBinding{Sequence: message.Sequence, GenerationID: message.GenerationID, ManifestHash: message.ManifestHash}
	now := h.now().UTC()
	var result any
	switch operation {
	case "begin":
		var v inventoryledger.BeginReceipt
		v, err = h.store.InventoryBegin(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, binding, *message.Manifest, now)
		result = map[string]any{"startedAt": v.StartedAt, "expiresAt": v.ExpiresAt}
	case "append":
		var v inventoryledger.ChunkReceipt
		v, err = h.store.InventoryAppend(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, binding, *message.Chunk, now)
		result = map[string]any{"ordinal": v.Ordinal, "rows": v.Rows, "receivedAt": v.ReceivedAt}
	case "finalize":
		var v inventoryledger.Completion
		v, err = h.store.InventoryFinalize(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
		result = map[string]any{"collectedAt": v.Manifest.CollectedAt, "completedAt": v.CompletedAt}
	case "abort":
		err = h.store.InventoryAbort(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
		result = map[string]any{"aborted": true}
	case "failure":
		var v enrollmentstore.InventoryFailureReceipt
		v, err = h.store.InventoryFailure(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, enrollmentstore.InventoryFailureReport{Sequence: message.Sequence, GenerationID: message.GenerationID, AttemptedAt: message.FailureAt, Reason: message.FailureReason}, now)
		result = map[string]any{"attemptedAt": v.Failure.AttemptedAt, "receivedAt": v.ReceivedAt, "reason": v.Failure.Reason}
	case "status":
		var v enrollmentstore.InventoryStatus
		v, err = h.store.InventoryStatus(r.Context(), identity.InvitationID, identity.Issuance.CertificateHash, binding, now)
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
		inventoryStoreFailure(w, err)
		return
	}
	digest := sha256.Sum256(raw)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemaVersion": "tracebolt.inventory-response.v1", "operation": operation, "sequence": strconv.FormatUint(message.Sequence, 10), "generationId": message.GenerationID, "manifestHash": message.ManifestHash, "requestSha256": hex.EncodeToString(digest[:]), "result": result})
}
func inventoryStoreFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollmentstore.ErrInventoryBusy), errors.Is(err, enrollmentstore.ErrBusy):
		w.Header().Set("Retry-After", "15")
		failure(w, 429, "storage_busy")
	case errors.Is(err, inventoryledger.ErrQuota):
		failure(w, 409, "inventory_resource_limit")
	case errors.Is(err, inventoryledger.ErrConflict), errors.Is(err, inventoryledger.ErrIncomplete), errors.Is(err, inventoryledger.ErrExpired), errors.Is(err, inventoryledger.ErrNotFound):
		failure(w, 409, "inventory_state_conflict")
	case errors.Is(err, inventoryledger.ErrInvalid):
		failure(w, 400, "invalid_inventory_request")
	default:
		storeFailure(w, err)
	}
}
