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
	"strconv"
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
		case "reserve", "upload", "complete", "deliver", "review", "review-coordinated", "approve", "retire", "schedule", "cancel-schedule":
		default:
			return "", "", false
		}
	}
	return p[3], op, true
}
func (h *operatorHandler) managedMSIContext(r *http.Request, cap operatorauth.Capability) context.Context {
	owner, ok := operatorContext(r)
	return msi.WithFinalCheck(enrollmentstore.WithOverviewClock(r.Context(), h.auth.Now), func() error {
		if !ok || !owner.session.Named() || !h.auth.Now().Before(owner.session.ExpiresAt) || owner.session.Lifetime().Err() != nil || owner.active == nil || !owner.active() || cap != "" && !h.auth.ActorHasCapability(owner.session.ActorID(), cap) || windowsManagedMSIScheduleOperation(r) && !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsManagedMSISchedule) {
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
	if r.URL.RawPath != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
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
	if h.windowsManagedMSIRegistry != nil {
		manager = h.windowsManagedMSIRegistry.Manager(device)
	}
	if manager == nil || h.insecureHTTPTest || manager.Binding().DeviceID != device {
		managedMSIError(w, msi.ErrUnavailable)
		return
	}
	if !pinWindowsMSICatalogueGET(w, &r, manager.Catalogue(), op) {
		return
	}
	cap := operatorauth.Capability("")
	if op != "" {
		cap = operatorauth.WindowsManagedMSIDeliver
		if op == "review" || op == "review-coordinated" || op == "approve" || op == "retire" || windowsManagedMSIScheduleOperation(r) {
			cap = operatorauth.WindowsManagedMSIInstall
		}
	}
	owner, valid := operatorContext(r)
	if !valid || !owner.session.Named() {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	actor := owner.session.ActorID()
	if manager.Fleet() && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIDeliver) && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIInstall) {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	if manager.Fleet() && op == "" {
		cap = h.managedMSIReadCapability(actor)
	}
	r = r.WithContext(h.managedMSIContext(r, cap))
	if op != "" {
		current, release, ok := h.app.beginOperatorCapability(w, r, cap)
		if !ok {
			return
		}
		release()
		if current != actor || windowsManagedMSIScheduleOperation(r) && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSISchedule) {
			managedMSIError(w, msi.ErrAuthority)
			return
		}

	}
	var e error
	switch op {
	case "schedule":
		var in struct {
			msi.ScheduleRequest
			Batch *msi.WorklistDispatchReference `json:"batch,omitempty"`
		}
		if !readManagedMSIBatchObjectBounded(w, r, manager.Reusable(), []string{"artifactId", "artifactRetiredCount", "bindingDigest", "transferId", "jobSequence", "readinessDigest", "startAt", "endAt", "packageReviewAccepted", "termsAccepted", "serviceRiskAccepted", "synchronousActionsAccepted", "scheduleAccepted"}, &in, 4096) {
			return
		}
		q := msi.WorklistRequest{DeviceID: device, Operation: "schedule", ArtifactID: in.ArtifactID, ArtifactRetiredCount: strconv.FormatUint(in.ArtifactRetiredCount, 10), BindingDigest: in.BindingDigest, TransferID: in.TransferID, JobSequence: strconv.FormatUint(in.JobSequence, 10), ReadinessDigest: in.ReadinessDigest, StartAt: in.StartAt, EndAt: in.EndAt}
		acks := msi.WorklistAcknowledgements{PackageReviewAccepted: in.PackageReviewAccepted, TermsAccepted: in.TermsAccepted, SynchronousReviewAccepted: in.SynchronousActionsAccepted, ServiceRiskAccepted: in.ServiceRiskAccepted, ScheduleAccepted: in.ScheduleAccepted}
		ctx, err := h.managedMSIBatchContext(r, in.Batch, q, acks)
		if err != nil {
			e = err
			break
		}
		e = manager.Schedule(ctx, actor, in.ScheduleRequest)
	case "cancel-schedule":
		var in struct {
			ScheduleDigest string `json:"scheduleDigest"`
		}
		if !readObject(w, r, 256, []string{"scheduleDigest"}, &in) {
			return
		}
		e = manager.CancelSchedule(r.Context(), actor, in.ScheduleDigest)
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
			Batch                *msi.WorklistDispatchReference `json:"batch,omitempty"`
			ArtifactRetiredCount string                         `json:"artifactRetiredCount,omitempty"`
			ArtifactID           string                         `json:"artifactId,omitempty"`
			BindingDigest        string                         `json:"bindingDigest,omitempty"`
			TransferID           string                         `json:"transferId"`
			Acknowledged         bool                           `json:"acknowledged"`
		}
		fields := []string{"transferId", "acknowledged"}
		if manager.Fleet() {
			fields = append(fields, "artifactId", "bindingDigest")
		}
		if manager.Reusable() {
			fields = append(fields, "artifactRetiredCount")
		}
		if !readManagedMSIBatchObject(w, r, manager.Reusable(), fields, &in) {
			return
		}
		if manager.Reusable() {
			ctx, err := windowsmanagedmsimanager.WithArtifactRetiredCount(r.Context(), in.ArtifactRetiredCount)
			if err != nil {
				managedMSIError(w, err)
				return
			}
			r = r.WithContext(ctx)
		}
		ctx, err := h.managedMSIBatchContext(r, in.Batch, msi.WorklistRequest{DeviceID: device, Operation: op, ArtifactID: in.ArtifactID, ArtifactRetiredCount: in.ArtifactRetiredCount, BindingDigest: in.BindingDigest, TransferID: in.TransferID}, msi.WorklistAcknowledgements{Acknowledged: in.Acknowledged})
		if err != nil {
			managedMSIError(w, err)
			return
		}
		if manager.Fleet() {
			e = manager.DeliverArtifact(ctx, actor, in.TransferID, in.Acknowledged, in.ArtifactID, in.BindingDigest)
		} else {
			e = manager.Deliver(ctx, actor, in.TransferID, in.Acknowledged)
		}
	case "review", "review-coordinated":
		var in struct {
			Batch                     *msi.WorklistDispatchReference `json:"batch,omitempty"`
			ArtifactRetiredCount      string                         `json:"artifactRetiredCount,omitempty"`
			TransferID                string                         `json:"transferId,omitempty"`
			JobSequence               string                         `json:"jobSequence,omitempty"`
			ArtifactID                string                         `json:"artifactId,omitempty"`
			BindingDigest             string                         `json:"bindingDigest,omitempty"`
			PackageReviewAccepted     bool                           `json:"packageReviewAccepted"`
			SynchronousReviewAccepted bool                           `json:"synchronousReviewAccepted,omitempty"`
			TermsAccepted             bool                           `json:"termsAccepted"`
			MaintenanceAcknowledged   bool                           `json:"maintenanceAcknowledged"`
		}
		fields := []string{"packageReviewAccepted", "termsAccepted", "maintenanceAcknowledged"}
		if manager.Fleet() {
			fields = append(fields, "artifactId", "bindingDigest")
		}
		if op == "review-coordinated" {
			fields = append(fields, "synchronousReviewAccepted")
		}
		if manager.Reusable() {
			fields = append(fields, "artifactRetiredCount", "transferId", "jobSequence")
		}
		if !readManagedMSIBatchObject(w, r, manager.Reusable(), fields, &in) {
			return
		}
		if manager.Reusable() {
			ctx, err := windowsmanagedmsimanager.WithJobOccurrence(r.Context(), in.ArtifactRetiredCount, in.TransferID, in.JobSequence)
			if err != nil {
				managedMSIError(w, err)
				return
			}
			r = r.WithContext(ctx)
		}
		if manager.Fleet() {
			if e = manager.CheckArtifactReference(r.Context(), in.ArtifactID, in.BindingDigest); e != nil {
				managedMSIError(w, e)
				return
			}
		}
		ctx, err := h.managedMSIBatchContext(r, in.Batch, msi.WorklistRequest{DeviceID: device, Operation: op, ArtifactID: in.ArtifactID, ArtifactRetiredCount: in.ArtifactRetiredCount, BindingDigest: in.BindingDigest, TransferID: in.TransferID, JobSequence: in.JobSequence}, msi.WorklistAcknowledgements{PackageReviewAccepted: in.PackageReviewAccepted, TermsAccepted: in.TermsAccepted, MaintenanceAcknowledged: in.MaintenanceAcknowledged, SynchronousReviewAccepted: in.SynchronousReviewAccepted})
		if err != nil {
			managedMSIError(w, err)
			return
		}
		e = manager.Review(ctx, actor, in.PackageReviewAccepted, in.TermsAccepted, in.MaintenanceAcknowledged, in.SynchronousReviewAccepted)
	case "retire":
		var in struct {
			Batch                *msi.WorklistDispatchReference `json:"batch,omitempty"`
			ArtifactRetiredCount string                         `json:"artifactRetiredCount,omitempty"`
			TransferID           string                         `json:"transferId,omitempty"`
			JobSequence          string                         `json:"jobSequence,omitempty"`
			ArtifactID           string                         `json:"artifactId"`
			BindingDigest        string                         `json:"bindingDigest"`
			ResultDigest         string                         `json:"resultDigest"`
			Acknowledged         bool                           `json:"acknowledged"`
		}
		fields := []string{"artifactId", "bindingDigest", "resultDigest", "acknowledged"}
		if manager.Reusable() {
			fields = append(fields, "artifactRetiredCount", "transferId", "jobSequence")
		}
		if !readManagedMSIBatchObject(w, r, manager.Reusable(), fields, &in) {
			return
		}
		if manager.Reusable() {
			ctx, err := windowsmanagedmsimanager.WithJobOccurrence(r.Context(), in.ArtifactRetiredCount, in.TransferID, in.JobSequence)
			if err != nil {
				managedMSIError(w, err)
				return
			}
			r = r.WithContext(ctx)
		}
		if e = manager.CheckArtifactReference(r.Context(), in.ArtifactID, in.BindingDigest); e != nil {
			managedMSIError(w, e)
			return
		}
		ctx, err := h.managedMSIBatchContext(r, in.Batch, msi.WorklistRequest{DeviceID: device, Operation: op, ArtifactID: in.ArtifactID, ArtifactRetiredCount: in.ArtifactRetiredCount, BindingDigest: in.BindingDigest, TransferID: in.TransferID, JobSequence: in.JobSequence, ResultDigest: in.ResultDigest}, msi.WorklistAcknowledgements{Acknowledged: in.Acknowledged})
		if err != nil {
			managedMSIError(w, err)
			return
		}
		e = manager.Retire(ctx, actor, in.ResultDigest, in.Acknowledged)
	case "approve":
		var in struct {
			Batch                *msi.WorklistDispatchReference `json:"batch,omitempty"`
			ArtifactRetiredCount string                         `json:"artifactRetiredCount,omitempty"`
			TransferID           string                         `json:"transferId,omitempty"`
			JobSequence          string                         `json:"jobSequence,omitempty"`
			ArtifactID           string                         `json:"artifactId,omitempty"`
			BindingDigest        string                         `json:"bindingDigest,omitempty"`
			ReadinessDigest      string                         `json:"readinessDigest"`
			Acknowledged         bool                           `json:"acknowledged"`
		}
		fields := []string{"readinessDigest", "acknowledged"}
		if manager.Fleet() {
			fields = append(fields, "artifactId", "bindingDigest")
		}
		if manager.Reusable() {
			fields = append(fields, "artifactRetiredCount", "transferId", "jobSequence")
		}
		if !readManagedMSIBatchObject(w, r, manager.Reusable(), fields, &in) {
			return
		}
		if manager.Reusable() {
			ctx, err := windowsmanagedmsimanager.WithJobOccurrence(r.Context(), in.ArtifactRetiredCount, in.TransferID, in.JobSequence)
			if err != nil {
				managedMSIError(w, err)
				return
			}
			r = r.WithContext(ctx)
		}
		if manager.Fleet() {
			if e = manager.CheckArtifactReference(r.Context(), in.ArtifactID, in.BindingDigest); e != nil {
				managedMSIError(w, e)
				return
			}
		}
		ctx, err := h.managedMSIBatchContext(r, in.Batch, msi.WorklistRequest{DeviceID: device, Operation: op, ArtifactID: in.ArtifactID, ArtifactRetiredCount: in.ArtifactRetiredCount, BindingDigest: in.BindingDigest, TransferID: in.TransferID, JobSequence: in.JobSequence, ReadinessDigest: in.ReadinessDigest}, msi.WorklistAcknowledgements{Acknowledged: in.Acknowledged})
		if err != nil {
			managedMSIError(w, err)
			return
		}
		e = manager.Approve(ctx, actor, in.ReadinessDigest, in.Acknowledged)
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

// Pin one current capability before any shared artifact or per-device wait.
// Later removal cannot fall back to another capability using an old response.
func (h *operatorHandler) managedMSIReadCapability(actor string) operatorauth.Capability {
	if h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIDeliver) {
		return operatorauth.WindowsManagedMSIDeliver
	}
	return operatorauth.WindowsManagedMSIInstall
}

// Scheduling is a separate prospective authority, required alongside installation.
func windowsManagedMSIScheduleOperation(r *http.Request) bool {
	_, op, ok := windowsManagedMSIRoute(r)
	return ok && (op == "schedule" || op == "cancel-schedule")
}
