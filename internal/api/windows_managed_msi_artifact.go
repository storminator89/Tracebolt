package api

import (
	"encoding/json"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"strings"
)

func windowsManagedMSIArtifactRoute(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	const base = "/api/windows-managed-msi/artifact"
	if r.URL.Path == base {
		return "", true
	}
	if !strings.HasPrefix(r.URL.Path, base+"/") {
		return "", false
	}
	op := strings.TrimPrefix(r.URL.Path, base+"/")
	return op, op == "reserve" || op == "upload" || op == "complete" || op == "reserve-reusable" || op == "retire"
}

// No arbitrary path, URL or installation API exists in shared custody. V3 alone
// supports explicitly reviewed retirement of exact app-owned bytes and a later
// explicit upload. V1/v2 cannot retire or replace. Membership grants no delivery
// or installation authority.
func (h *operatorHandler) windowsManagedMSIArtifactAPI(w http.ResponseWriter, r *http.Request) {
	op, ok := windowsManagedMSIArtifactRoute(r)
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
	registry := h.windowsManagedMSIRegistry
	if registry == nil || registry.Artifact() == nil || h.insecureHTTPTest {
		managedMSIError(w, msi.ErrUnavailable)
		return
	}
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	actor := owner.session.ActorID()
	cap := operatorauth.WindowsManagedMSIDeliver
	if op == "" {
		cap = h.managedMSIReadCapability(actor)
	}
	r = r.WithContext(h.managedMSIContext(r, cap))
	if op != "" {
		current, release, ok := h.app.beginOperatorCapability(w, r, cap)
		if !ok {
			return
		}
		release()
		if current != actor {
			managedMSIError(w, msi.ErrAuthority)
			return
		}
	}
	var e error
	switch op {
	case "retire":
		var in struct {
			RetiredCount string `json:"retiredCount"`
			ArtifactID   string `json:"artifactId"`
			Acknowledged bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 256, []string{"artifactId", "retiredCount", "acknowledged"}, &in) {
			return
		}
		if !pinManagedMSIArtifactOccurrence(w, &r, in.RetiredCount) {
			return
		}
		e = registry.Artifact().RetireArtifact(r.Context(), actor, in.ArtifactID, in.Acknowledged)
	case "reserve-reusable":
		var in struct {
			ExpectedArtifactID      string          `json:"expectedArtifactId"`
			RetiredCount            string          `json:"retiredCount"`
			Package                 json.RawMessage `json:"package"`
			NativeAcceptanceDigest  string          `json:"nativeAcceptanceDigest"`
			PublisherStatus         string          `json:"publisherStatus"`
			PublisherEvidenceDigest string          `json:"publisherEvidenceDigest"`
		}
		if !readObject(w, r, 4096, []string{"package", "nativeAcceptanceDigest", "publisherStatus", "publisherEvidenceDigest", "retiredCount", "expectedArtifactId"}, &in) {
			return
		}
		selection, ok := decodeSoftwarePackageSelection(in.Package)
		if !ok {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
		ctx, err := windowsmanagedmsimanager.WithArtifactReserveOccurrence(r.Context(), in.RetiredCount, in.ExpectedArtifactID)
		if err != nil {
			managedMSIError(w, err)
			return
		}
		r = r.WithContext(ctx)
		e = registry.Artifact().ReserveReusableUpload(r.Context(), actor, selection, in.NativeAcceptanceDigest, in.PublisherStatus, in.PublisherEvidenceDigest)
	case "reserve":
		var in struct {
			Package                json.RawMessage `json:"package"`
			NativeAcceptanceDigest string          `json:"nativeAcceptanceDigest"`
		}
		if !readObject(w, r, 4096, []string{"package", "nativeAcceptanceDigest"}, &in) {
			return
		}
		selection, ok := decodeSoftwarePackageSelection(in.Package)
		if !ok {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
		e = registry.Artifact().ReserveUpload(r.Context(), actor, selection, in.NativeAcceptanceDigest)
	case "upload":
		var in struct {
			windowsmanagedmsimanager.UploadChunk
			RetiredCount string `json:"retiredCount,omitempty"`
		}
		fields := []string{"packageDigest", "index", "digest", "data"}
		if registry.Artifact().Reusable() {
			fields = append(fields, "retiredCount")
		}
		if !readObject(w, r, msi.MaxFrameBytes, fields, &in) {
			return
		}
		if registry.Artifact().Reusable() && !pinManagedMSIArtifactOccurrence(w, &r, in.RetiredCount) {
			return
		}
		e = registry.Artifact().Upload(r.Context(), actor, in.UploadChunk)
	case "complete":
		var in struct {
			RetiredCount string `json:"retiredCount,omitempty"`
		}
		fields := []string{}
		limit := int64(2)
		if registry.Artifact().Reusable() {
			fields = append(fields, "retiredCount")
			limit = 128
		}
		if !readObject(w, r, limit, fields, &in) {
			return
		}
		if registry.Artifact().Reusable() && !pinManagedMSIArtifactOccurrence(w, &r, in.RetiredCount) {
			return
		}
		e = registry.Artifact().CompleteUpload(r.Context(), actor)
	}
	if e != nil {
		managedMSIError(w, e)
		return
	}
	view, e := registry.ArtifactView(r.Context())
	if e != nil {
		managedMSIError(w, e)
		return
	}
	if e = msi.CheckFinal(r.Context()); e != nil {
		managedMSIError(w, e)
		return
	}
	if operatorStillActive(w, r) {
		write(w, 200, view)
	}
}

func pinManagedMSIArtifactOccurrence(w http.ResponseWriter, r **http.Request, value string) bool {
	ctx, err := windowsmanagedmsimanager.WithArtifactRetiredCount((*r).Context(), value)
	if err != nil {
		managedMSIError(w, err)
		return false
	}
	*r = (*r).WithContext(ctx)
	return true
}
