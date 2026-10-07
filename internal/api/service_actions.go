package api

import (
	"context"
	"errors"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"net/http"
	"strings"
	"time"
)

// A trusted construction seam; requests cannot provide an implementation.
type serviceActionManager interface {
	ViewAt(context.Context, string) (actionjob.Record, time.Time, error)
	Preview(context.Context, string, string, string) (actionjob.Record, error)
	Approve(context.Context, string, string, string, string) (actionjob.Record, error)
	TransportProfile() string
	Available() bool
}

type serviceActionTarget struct {
	Unit             string   `json:"unit"`
	UnitPolicyDigest string   `json:"unitPolicyDigest"`
	AffectedServices []string `json:"affectedServices,omitempty"`
}
type serviceActionResult struct {
	Phase         string                       `json:"phase"`
	Reason        actionstate.NotStartedReason `json:"reason,omitempty"`
	Outcome       actionstate.Outcome          `json:"outcome,omitempty"`
	ObservedState actionstate.ObservedState    `json:"observedState,omitempty"`
}
type serviceActionJob struct {
	ID             string               `json:"id"`
	Unit           string               `json:"unit"`
	ActorID        string               `json:"actorId"`
	ApprovedAt     time.Time            `json:"approvedAt"`
	StartDeadline  time.Time            `json:"startDeadline"`
	State          string               `json:"state"`
	EnvelopeDigest string               `json:"envelopeDigest"`
	Result         *serviceActionResult `json:"result"`
}
type serviceActionView struct {
	Scope            string                          `json:"scope,omitempty"`
	ReviewNotice     string                          `json:"reviewNotice,omitempty"`
	ExcludedServices []actionhelper.ServiceExclusion `json:"excludedServices,omitempty"`
	SchemaVersion    string                          `json:"schemaVersion"`
	DeviceID         string                          `json:"deviceId"`
	ServerNow        time.Time                       `json:"serverNow"`
	Configured       bool                            `json:"configured"`
	Available        bool                            `json:"available"`
	Reason           string                          `json:"reason"`
	Services         []serviceActionTarget           `json:"services"`
	Preview          *actionjob.Preview              `json:"preview"`
	Job              *serviceActionJob               `json:"job"`
}

func serviceActionRoute(r *http.Request) (string, string, bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 && len(parts) != 6 {
		return "", "", false
	}
	if parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "service-actions" {
		return "", "", false
	}
	op := ""
	if len(parts) == 6 {
		op = parts[5]
		if op != "preview" && op != "approve" {
			return "", "", false
		}
	}
	return parts[3], op, true
}
func (h *operatorHandler) serviceActions(w http.ResponseWriter, r *http.Request) {
	device, op, ok := serviceActionRoute(r)
	if !ok {
		fail(w, 404, "not_found", "Service action is unavailable.")
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if op == "" {
		h.writeServiceActions(w, r, device)
		return
	}
	actor, release, ok := h.app.beginOperatorCapability(w, r, operatorauth.RestartService)
	if !ok {
		return
	}
	defer release()
	if h.actions == nil || h.actions.TransportProfile() != actionmanager.Profile(map[bool]string{true: "http-test", false: "tls"}[h.insecureHTTPTest]) {
		fail(w, 409, "service_action_unavailable", "Service actions are not configured.")
		return
	}
	var err error
	switch op {
	case "preview":
		var in struct {
			Unit string `json:"unit"`
		}
		if !readObject(w, r, 512, []string{"unit"}, &in) {
			return
		}
		_, err = h.actions.Preview(r.Context(), device, actor, in.Unit)
	case "approve":
		var in struct {
			PreviewID     string `json:"previewId"`
			PreviewDigest string `json:"previewDigest"`
		}
		if !readObject(w, r, 1024, []string{"previewId", "previewDigest"}, &in) {
			return
		}
		_, err = h.actions.Approve(r.Context(), device, in.PreviewID, in.PreviewDigest, actor)
	}
	release()
	if err != nil {
		serviceActionError(w, err)
		return
	}
	h.writeServiceActions(w, r, device)
}
func (h *operatorHandler) writeServiceActions(w http.ResponseWriter, r *http.Request, device string) {
	now := h.auth.Now().UTC()
	view := serviceActionView{SchemaVersion: "tracebolt.service-action-view.v1", DeviceID: device, ServerNow: now, Reason: "not_configured", Services: []serviceActionTarget{}}
	// Even the unavailable response resolves the device instead of inventing it.
	if h.actions == nil {
		devices, e := h.app.devices()
		if e != nil {
			h.app.internal(w)
			return
		}
		found := false
		for _, d := range devices {
			if d.ID == device {
				found = true
			}
		}
		if !found {
			fail(w, 404, "not_found", "Device is unavailable.")
			return
		}
	} else {
		record, observedAt, e := h.actions.ViewAt(r.Context(), device)
		if e != nil {
			serviceActionError(w, e)
			return
		}
		now = observedAt
		view.ServerNow = now
		view.Configured = true
		view.Reason = record.Ready(h.actions.TransportProfile(), now)
		view.Preview = usableServicePreview(record, h.actions.TransportProfile(), now)
		if !h.actions.Available() {
			view.Reason = "not_configured"
			view.Preview = nil
		}
		if record.Capabilities != nil {
			if record.Capabilities.Version == actionhelper.CapabilitiesVersionV2 {
				view.SchemaVersion = "tracebolt.service-action-view.v2"
				view.Scope = record.Capabilities.Scope
				view.ReviewNotice = record.Capabilities.ReviewNotice
				view.ExcludedServices = append([]actionhelper.ServiceExclusion(nil), record.Capabilities.ExcludedServices...)
			}
			for _, s := range record.Capabilities.Services {
				view.Services = append(view.Services, serviceActionTarget{Unit: s.Unit, UnitPolicyDigest: s.UnitPolicyDigest, AffectedServices: append([]string(nil), s.AffectedServices...)})
			}
		}
		if len(record.Jobs) > 0 {
			j := record.Jobs[len(record.Jobs)-1]
			view.Job = &serviceActionJob{ID: j.Preview.ID, Unit: j.Preview.Plan.Unit, ActorID: j.Preview.ActorID, ApprovedAt: j.Approval.ApprovedAt, StartDeadline: j.Deadline(), State: j.State(now), EnvelopeDigest: j.Identity().EnvelopeDigest}
			if len(j.Results) > 0 {
				x := j.Results[len(j.Results)-1]
				view.Job.Result = &serviceActionResult{x.Phase, x.Reason, x.Outcome, x.ObservedState}
			}
		}
	}
	operator, ok := operatorContext(r)
	can := false
	if ok && operator.session.Named() {
		for _, c := range operator.session.Capabilities() {
			if c == operatorauth.RestartService {
				can = true
			}
		}
	}
	if !can {
		view.Reason = "operator_capability_required"
		view.Preview = nil
	} else if view.Preview != nil && view.Preview.ActorID != operator.session.ActorID() {
		view.Preview = nil
	}
	view.Available = view.Reason == "ready"
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, view)
}
func serviceActionError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, actionjob.ErrInvalid):
		fail(w, 400, "service_action_invalid", "The service action request is invalid.")
	case errors.Is(e, actionjob.ErrConflict), errors.Is(e, actionjob.ErrConsumed):
		fail(w, 409, "service_action_conflict", "This action changed or was already claimed. Read its saved status; do not retry it as a new action.")
	case errors.Is(e, actionjob.ErrExpired):
		fail(w, 409, "service_action_expired", "The original action approval window expired.")
	case errors.Is(e, actionjob.ErrNotFound):
		fail(w, 404, "service_action_not_found", "No pending service action exists.")
	default:
		fail(w, 409, "service_action_unavailable", "The service action is unavailable. Its execution was not confirmed.")
	}
}

// Unapproved previews are not durable jobs. A changed or stale availability
// projection must not trap the UI on an obsolete preview; approval independently
// compares the original stored preview and current policy again.
func usableServicePreview(r actionjob.Record, profile string, now time.Time) *actionjob.Preview {
	p := r.Preview
	if p == nil || r.Ready(profile, now) != "ready" || !now.Before(p.ExpiresAt) || r.Capabilities == nil || p.TransportProfile != profile || p.RootPolicyDigest != r.Capabilities.RootPolicyDigest || p.KeyID != r.Capabilities.KeyID {
		return nil
	}
	for _, s := range r.Capabilities.Services {
		if s.Unit == p.Plan.Unit && s.UnitPolicyDigest == p.Plan.UnitPolicyDigest {
			if r.Capabilities.Version == actionhelper.CapabilitiesVersionV2 {
				currentImpact, err := actionpermit.AffectedServicesDigest(s.AffectedServices)
				previewImpact, previewErr := actionpermit.AffectedServicesDigest(p.AffectedServices)
				if err != nil || previewErr != nil || p.Version != actionjob.PreviewVersionV2 || p.Plan.Version != actionpermit.PlanVersionV2 || currentImpact != p.Plan.AffectedServicesDigest || previewImpact != currentImpact || p.Scope != r.Capabilities.Scope || p.ReviewNotice != r.Capabilities.ReviewNotice {
					return nil
				}
			} else if p.Version != actionjob.PreviewVersion || p.Plan.Version != actionpermit.PlanVersion {
				return nil
			}
			return p
		}
	}
	return nil
}
