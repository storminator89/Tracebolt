package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"strings"
)

func windowsManagedMSIRoute(r *http.Request) (string, string, bool) {
	if r == nil || r.URL == nil {
		return "", "", false
	}
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-managed-msi" {
		return "", "", false
	}
	op := ""
	if len(p) == 6 {
		op = p[5]
		switch op {
		case "reserve", "upload", "complete", "deliver", "review", "review-coordinated", "approve":
		default:
			return "", "", false
		}
	}
	return p[3], op, true
}
func (h *operatorHandler) managedMSIContext(r *http.Request, cap operatorauth.Capability) context.Context {
	owner, ok := operatorContext(r)
	return msi.WithFinalCheck(enrollmentstore.WithOverviewClock(r.Context(), h.auth.Now), func() error {
		if !ok || !owner.session.Named() || !h.auth.Now().Before(owner.session.ExpiresAt) || owner.session.Lifetime().Err() != nil || owner.active == nil || !owner.active() || cap != "" && !h.auth.ActorHasCapability(owner.session.ActorID(), cap) {
			return msi.ErrAuthority
		}
		return nil
	})
}
func (h *operatorHandler) windowsManagedMSIAPI(w http.ResponseWriter, r *http.Request) {
	device, op, ok := windowsManagedMSIRoute(r)
	if !ok {
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		managedMSIError(w, msi.ErrInvalid)
		return
	}
	for _, header := range []string{"Content-Encoding", "Range", "Content-Range", "Content-Disposition", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		if len(r.Header.Values(header)) != 0 {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
	}
	manager := h.windowsManagedMSI
	if manager == nil || h.insecureHTTPTest || manager.Binding().DeviceID != device {
		managedMSIError(w, msi.ErrUnavailable)
		return
	}
	cap := operatorauth.Capability("")
	if op != "" {
		cap = operatorauth.WindowsManagedMSIDeliver
		if op == "review" || op == "review-coordinated" || op == "approve" {
			cap = operatorauth.WindowsManagedMSIInstall
		}
	}
	r = r.WithContext(h.managedMSIContext(r, cap))
	owner, valid := operatorContext(r)
	if !valid || !owner.session.Named() {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	actor := owner.session.ActorID()
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
		e = manager.ReserveUpload(r.Context(), actor, selection, in.NativeAcceptanceDigest)
	case "upload":
		var in windowsmanagedmsimanager.UploadChunk
		if !readObject(w, r, msi.MaxFrameBytes, []string{"packageDigest", "index", "digest", "data"}, &in) {
			return
		}
		e = manager.Upload(r.Context(), actor, in)
	case "complete":
		var in struct{}
		if !readObject(w, r, 2, []string{}, &in) {
			return
		}
		e = manager.CompleteUpload(r.Context(), actor)
	case "deliver":
		var in struct {
			TransferID   string `json:"transferId"`
			Acknowledged bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 512, []string{"transferId", "acknowledged"}, &in) {
			return
		}
		e = manager.Deliver(r.Context(), actor, in.TransferID, in.Acknowledged)
	case "review", "review-coordinated":
		var in struct {
			PackageReviewAccepted     bool `json:"packageReviewAccepted"`
			SynchronousReviewAccepted bool `json:"synchronousReviewAccepted,omitempty"`
			TermsAccepted             bool `json:"termsAccepted"`
			MaintenanceAcknowledged   bool `json:"maintenanceAcknowledged"`
		}
		fields := []string{"packageReviewAccepted", "termsAccepted", "maintenanceAcknowledged"}
		if op == "review-coordinated" {
			fields = append(fields, "synchronousReviewAccepted")
		}
		if !readObject(w, r, 512, fields, &in) {
			return
		}
		e = manager.Review(r.Context(), actor, in.PackageReviewAccepted, in.TermsAccepted, in.MaintenanceAcknowledged, in.SynchronousReviewAccepted)
	case "approve":
		var in struct {
			ReadinessDigest string `json:"readinessDigest"`
			Acknowledged    bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 512, []string{"readinessDigest", "acknowledged"}, &in) {
			return
		}
		e = manager.Approve(r.Context(), actor, in.ReadinessDigest, in.Acknowledged)
	}
	if e != nil {
		managedMSIError(w, e)
		return
	}
	v, e := manager.View(r.Context())
	if e != nil {
		managedMSIError(w, e)
		return
	}
	if operatorStillActive(w, r) {
		write(w, 200, v)
	}
}
func managedMSIError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, msi.ErrInvalid):
		fail(w, 400, "windows_managed_msi_invalid", "The exact managed MSI request is invalid.")
	case errors.Is(e, msi.ErrAuthority):
		fail(w, 403, "windows_managed_msi_authority", "Current identity, session or separate managed MSI permission is unavailable.")
	default:
		fail(w, 409, "windows_managed_msi_unavailable", "Managed MSI state is unavailable, expired, consumed or unconfirmed. Read saved status; do not repeat upload, delivery or installation.")
	}
}
