package api

import (
	"encoding/json"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"strings"
)

func windowsManagedMSICatalogueRoute(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	switch r.URL.Path {
	case "/api/windows-managed-msi/catalogue":
		return "", true
	case "/api/windows-managed-msi/catalogue/reserve":
		return "reserve", true
	}
	return "", false
}
func (h *operatorHandler) windowsManagedMSICatalogueAPI(w http.ResponseWriter, r *http.Request) {
	op, ok := windowsManagedMSICatalogueRoute(r)
	if !ok {
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		managedMSIError(w, msi.ErrInvalid)
		return
	}
	for _, header := range []string{"Content-Encoding", "Range", "Content-Range", "Content-Disposition", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		if len(r.Header.Values(header)) != 0 {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
	}
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() || h.insecureHTTPTest {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	actor := owner.session.ActorID()
	if !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIDeliver) && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIInstall) {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	cap := h.managedMSIReadCapability(actor)
	if op != "" {
		cap = operatorauth.WindowsManagedMSIDeliver
	}
	r = r.WithContext(h.managedMSIContext(r, cap))
	registry := h.windowsManagedMSIRegistry
	if op == "reserve" {
		if !registry.Catalogue() {
			managedMSIError(w, msi.ErrUnavailable)
			return
		}
		current, release, ok := h.app.beginOperatorCapability(w, r, cap)
		if !ok {
			return
		}
		release()
		if current != actor {
			managedMSIError(w, msi.ErrAuthority)
			return
		}
		var in struct {
			Revision                string          `json:"revision"`
			Package                 json.RawMessage `json:"package"`
			NativeAcceptanceDigest  string          `json:"nativeAcceptanceDigest"`
			PublisherStatus         string          `json:"publisherStatus"`
			PublisherEvidenceDigest string          `json:"publisherEvidenceDigest"`
		}
		if !readObject(w, r, 4096, []string{"revision", "package", "nativeAcceptanceDigest", "publisherStatus", "publisherEvidenceDigest"}, &in) {
			return
		}
		selection, ok := decodeSoftwarePackageSelection(in.Package)
		if !ok {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
		if e := registry.Artifact().ReserveCatalogueUpload(r.Context(), actor, in.Revision, selection, in.NativeAcceptanceDigest, in.PublisherStatus, in.PublisherEvidenceDigest); e != nil {
			managedMSIError(w, e)
			return
		}
	}
	view, e := registry.CatalogueView(r.Context())
	if e != nil {
		managedMSIError(w, e)
		return
	}
	if !view.Enabled {
		view.ServerNow = h.auth.Now().Unix()
	}
	if e = msi.CheckFinal(r.Context()); e != nil {
		managedMSIError(w, e)
		return
	}
	if operatorStillActive(w, r) {
		write(w, 200, view)
	}
}

// Catalogue GET selection is exact, canonical and read-only. Old singleton
// endpoints continue to reject every query. Mutation pins remain in strict JSON.
func pinWindowsMSICatalogueGET(w http.ResponseWriter, r **http.Request, enabled bool, op string) bool {
	raw := (*r).URL.RawQuery
	if raw == "" {
		if enabled && op == "" {
			managedMSIError(w, msi.ErrInvalid)
			return false
		}
		return true
	}
	const prefix = "artifactRetiredCount="
	if !enabled || op != "" || (*r).Method != "GET" || !strings.HasPrefix(raw, prefix) {
		managedMSIError(w, msi.ErrInvalid)
		return false
	}
	value := strings.TrimPrefix(raw, prefix)
	if _, e := msi.ParseCatalogueOccurrence(value); e != nil {
		managedMSIError(w, e)
		return false
	}
	ctx, e := windowsmanagedmsimanager.WithArtifactRetiredCount((*r).Context(), value)
	if e != nil {
		managedMSIError(w, e)
		return false
	}
	*r = (*r).WithContext(ctx)
	return true
}
