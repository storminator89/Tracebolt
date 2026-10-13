package enrollmenttransport

import (
	"errors"
	"io"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventorywire"
	"net/http"
)

const macOSInventoryControlPath = "/v1/macos/inventory/control"
const macOSInventoryReportPath = "/v1/macos/inventory/report"

func macOSInventoryPath(path string) bool {
	return path == macOSInventoryControlPath || path == macOSInventoryReportPath
}
func (h *Ingress) macOSInventory(w http.ResponseWriter, r *http.Request) {
	if h.profile != "tls" || h.store.Config().Platform != "darwin" || h.store.Config().Binding.CollectionProfile != macosinventorywire.Profile {
		failure(w, 404, "not_found")
		return
	}
	if !validRequestPath(r, h.authority, "tls", r.URL.Path) {
		failure(w, 400, "macos_inventory_invalid")
		return
	}
	limit := macosinventorywire.MaxReportBytes
	control := r.URL.Path == macOSInventoryControlPath
	if control {
		limit = macosinventorywire.MaxControlBytes
	}
	if r.ContentLength > int64(limit) {
		failure(w, 413, "payload_too_large")
		return
	}
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
	r = withVerifiedTLSCertificate(r)
	identity, e := h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
	if e != nil {
		storeFailure(w, e)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, int64(limit+1)))
	if e != nil || len(raw) > limit || int64(len(raw)) != r.ContentLength {
		failure(w, 400, "macos_inventory_invalid")
		return
	}
	if !h.verifiedTLS(r, h.now()) {
		failure(w, 403, "agent_unauthorized")
		return
	}
	ctx := enrollmentstore.WithMacOSInventoryIngressOrigin(r.Context(), h.origin)
	ctx = enrollmentstore.WithMacOSInventoryClock(ctx, h.now)
	var receipt []byte
	if control {
		receipt, e = h.store.ApplyMacOSInventoryControl(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now().UTC())
	} else {
		receipt, e = h.store.ApplyMacOSInventoryReport(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now().UTC())
	}
	if e != nil {
		switch {
		case errors.Is(e, macosinventorywire.ErrInvalid), errors.Is(e, macosinventorywire.ErrBounds):
			failure(w, 400, "macos_inventory_invalid")
		case errors.Is(e, macosinventorywire.ErrConflict), errors.Is(e, macosinventorywire.ErrDisabled), errors.Is(e, macosinventorywire.ErrExpired):
			failure(w, 409, "macos_inventory_conflict")
		default:
			storeFailure(w, e)
		}
		return
	}
	if len(receipt) > macosinventorywire.MaxReceiptBytes {
		failure(w, 503, "storage_unavailable")
		return
	}
	// The store already committed, then rechecked the exact request and original
	// receipt against live authority. Recheck normal TLS time at the output edge.
	if !h.verifiedTLS(r, h.now()) {
		failure(w, 403, "agent_unauthorized")
		return
	}
	if control {
		e = h.store.RecheckMacOSInventoryControl(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now().UTC())
	} else {
		e = h.store.RecheckMacOSInventoryReport(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, h.now().UTC())
	}
	if e != nil {
		if errors.Is(e, macosinventorywire.ErrConflict) || errors.Is(e, macosinventorywire.ErrExpired) || errors.Is(e, macosinventorywire.ErrDisabled) {
			failure(w, 409, "macos_inventory_conflict")
		} else {
			storeFailure(w, e)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(receipt)
}
