package enrollmenttransport

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/signedhttp"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"strconv"
	"strings"
)

const windowsManagedMSIPrefix = "/v1/windows-managed-msi/"

func (h *Ingress) ConfigureWindowsManagedMSI(m *windowsmanagedmsimanager.Manager) error {
	if !h.valid() || m == nil || h.windowsManagedMSI != nil || !m.OperatorPolicyConfigured() || !m.MatchesStore(h.store) || !m.MatchesBinding(h.store.Config().Binding) || h.profile != "tls" || h.store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return ErrConfiguration
	}
	h.windowsManagedMSI = m
	return nil
}
func managedMSIBodyLimit(path string) int64 {
	switch path {
	case windowsManagedMSIPrefix + "poll":
		return 2
	case windowsManagedMSIPrefix + "chunk":
		return 512
	case windowsManagedMSIPrefix + "report":
		return msi.MaxFrameBytes
	default:
		return 0
	}
}
func validManagedMSIRequest(r *http.Request, authority string) bool {
	if r == nil || r.URL == nil || r.Method != "POST" || r.Host != authority || managedMSIBodyLimit(r.URL.Path) == 0 || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || r.URL.Scheme != "" && r.URL.Scheme != "https" || r.URL.Host != "" && r.URL.Host != authority || r.RequestURI != "" && r.RequestURI != r.URL.Path || r.Body == nil || r.ContentLength <= 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return false
	}
	size, types, lengths := 128, 0, 0
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "origin" || lower == "authorization" || lower == "proxy-authorization" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-fetch-") || strings.HasPrefix(lower, "x-tracebolt-") || lower == "content-encoding" || lower == "trailer" || lower == "transfer-encoding" || lower == "expect" || lower == "upgrade" || lower == "host" || lower == "range" || lower == "content-range" || lower == "content-disposition" {
			return false
		}
		if lower == "content-type" {
			types += len(values)
			if len(values) != 1 || values[0] != "application/json" {
				return false
			}
		}
		if lower == "content-length" {
			lengths += len(values)
			if len(values) != 1 || values[0] != strconv.FormatInt(r.ContentLength, 10) {
				return false
			}
		}
		for _, v := range values {
			size += len(key) + len(v) + 4
			if size > signedhttp.MaxHeaderBytes {
				return false
			}
		}
	}
	return types == 1 && lengths <= 1
}
func (h *Ingress) windowsManagedMSIRequest(w http.ResponseWriter, r *http.Request) {
	manager := h.windowsManagedMSI
	if manager == nil || h.profile != "tls" {
		failure(w, 404, "windows_managed_msi_not_configured")
		return
	}
	if !validManagedMSIRequest(r, h.authority) || r.ContentLength > managedMSIBodyLimit(r.URL.Path) {
		failure(w, 400, "invalid_request")
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
	r = r.WithContext(enrollmentstore.WithOverviewClock(r.Context(), h.now))
	authorize := func() bool {
		if !h.verifiedTLS(r, h.now()) {
			return false
		}
		identity, e := h.store.AuthorizeCertificate(r.Context(), r.TLS.PeerCertificates[0].Raw, h.now())
		return e == nil && identity.Approval.DeviceID == manager.Binding().DeviceID && "sha256:"+identity.Issuance.CertificateHash == manager.Binding().IncarnationDigest
	}
	if !authorize() {
		failure(w, 403, "agent_unauthorized")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, managedMSIBodyLimit(r.URL.Path)+1))
	if e != nil || int64(len(raw)) != r.ContentLength || !authorize() {
		failure(w, 400, "invalid_request")
		return
	}
	out := []byte("{}")
	var permit []byte
	var chunkDigest string
	switch r.URL.Path {
	case windowsManagedMSIPrefix + "poll":
		if !bytes.Equal(raw, []byte("{}")) {
			failure(w, 400, "invalid_request")
			return
		}
		var p msi.PollResponse
		p, e = manager.Poll(r.Context())
		permit = p.Permit
		if e == nil {
			out, e = json.Marshal(p)
		}
	case windowsManagedMSIPrefix + "chunk":
		var q msi.ChunkRequest
		if msi.Canonical(raw, &q, 512) != nil {
			failure(w, 400, "invalid_request")
			return
		}
		var c msi.Chunk
		c, e = manager.Chunk(r.Context(), q)
		chunkDigest = q.PermitDigest
		if e == nil {
			out, e = json.Marshal(c)
		}
	case windowsManagedMSIPrefix + "report":
		var q msi.ReportRequest
		if msi.Canonical(raw, &q, msi.MaxFrameBytes) != nil {
			failure(w, 400, "invalid_request")
			return
		}
		e = manager.Report(r.Context(), q.Report)
	}
	if e != nil {
		failure(w, 409, "windows_managed_msi_unavailable")
		return
	}
	if len(out) > msi.MaxFrameBytes || !authorize() || manager.CheckRelease(r.Context(), permit, chunkDigest) != nil {
		failure(w, 403, "agent_unauthorized")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(out)
}
