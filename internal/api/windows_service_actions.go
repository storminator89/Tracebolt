package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowsactionmanager"
	"net/http"
	"strings"
	"time"
)

type windowsServiceActionManager interface {
	ViewAt(context.Context, string) (windowsactionjob.Record, time.Time, error)
	Preview(context.Context, string, string, string, string) (windowsactionjob.Record, error)
	Approve(context.Context, string, string, string, string) (windowsactionjob.Record, error)
	TransportProfile() string
	Available() bool
}
type windowsServiceActionJob struct {
	Identity      windowsaction.Identity `json:"identity"`
	Target        string                 `json:"target"`
	Operation     string                 `json:"operation"`
	ActorID       string                 `json:"actorId"`
	ApprovedAt    time.Time              `json:"approvedAt"`
	StartDeadline time.Time              `json:"startDeadline"`
	State         string                 `json:"state"`
	Result        *windowsaction.Result  `json:"result"`
}
type windowsServiceActionView struct {
	SchemaVersion string                    `json:"schemaVersion"`
	DeviceID      string                    `json:"deviceId"`
	ServerNow     time.Time                 `json:"serverNow"`
	Configured    bool                      `json:"configured"`
	Available     bool                      `json:"available"`
	Reason        string                    `json:"reason"`
	Target        *string                   `json:"target"`
	Preview       *windowsactionjob.Preview `json:"preview"`
	Job           *windowsServiceActionJob  `json:"job"`
}

func windowsServiceActionRoute(r *http.Request) (string, string, bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-service-actions" {
		return "", "", false
	}
	op := ""
	if len(p) == 6 {
		op = p[5]
		if op != "preview" && op != "approve" {
			return "", "", false
		}
	}
	return p[3], op, true
}
func (h *operatorHandler) windowsServiceActions(w http.ResponseWriter, r *http.Request) {
	device, op, ok := windowsServiceActionRoute(r)
	if !ok {
		fail(w, 404, "not_found", "Windows service action is unavailable.")
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if op == "" {
		h.writeWindowsServiceActions(w, r, device)
		return
	}
	actor, release, ok := h.app.beginOperatorCapability(w, r, operatorauth.WindowsServiceControl)
	if !ok {
		return
	}
	defer release()
	if h.windowsActions == nil || h.windowsActions.TransportProfile() != windowsactionmanager.Profile(map[bool]string{true: "http-test", false: "tls"}[h.insecureHTTPTest]) {
		windowsServiceActionError(w, windowsaction.ErrUnavailable)
		return
	}
	var e error
	if op == "preview" {
		var in struct {
			Target    string `json:"target"`
			Operation string `json:"operation"`
		}
		if !readObject(w, r, 512, []string{"target", "operation"}, &in) {
			return
		}
		_, e = h.windowsActions.Preview(r.Context(), device, actor, in.Target, in.Operation)
	} else {
		var in struct {
			PreviewID     string `json:"previewId"`
			PreviewDigest string `json:"previewDigest"`
		}
		if !readObject(w, r, 1024, []string{"previewId", "previewDigest"}, &in) {
			return
		}
		_, e = h.windowsActions.Approve(r.Context(), device, in.PreviewID, in.PreviewDigest, actor)
	}
	release()
	if e != nil {
		windowsServiceActionError(w, e)
		return
	}
	h.writeWindowsServiceActions(w, r, device)
}
func (h *operatorHandler) writeWindowsServiceActions(w http.ResponseWriter, r *http.Request, device string) {
	v := windowsServiceActionView{SchemaVersion: "tracebolt.windows-service-action-view.v1", DeviceID: device, ServerNow: h.auth.Now().UTC(), Reason: "not_configured"}
	if h.windowsActions == nil {
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
			fail(w, 404, "not_found", "Device unavailable.")
			return
		}
	} else {
		record, now, e := h.windowsActions.ViewAt(r.Context(), device)
		if e != nil {
			windowsServiceActionError(w, e)
			return
		}
		v.ServerNow = now
		v.Configured = true
		v.Target = &record.Binding.Target
		v.Reason = record.Ready(now)
		if record.Preview != nil && v.Reason == "ready" && now.Before(record.Preview.ExpiresAt) {
			v.Preview = record.Preview
		}
		if !h.windowsActions.Available() {
			v.Reason = "not_configured"
			v.Preview = nil
		}
		if len(record.Jobs) > 0 {
			j := record.Jobs[len(record.Jobs)-1]
			v.Job = &windowsServiceActionJob{Identity: j.Identity(), Target: j.Preview.Binding.Target, Operation: j.Preview.Operation, ActorID: j.Preview.ActorID, ApprovedAt: j.ApprovedAt, StartDeadline: j.Deadline(), State: j.State(now)}
			if len(j.Results) > 0 {
				result := j.Results[len(j.Results)-1]
				v.Job.Result = &result
			}
		}
	}
	owner, ok := operatorContext(r)
	can := false
	if ok && owner.session.Named() {
		for _, c := range owner.session.Capabilities() {
			if c == operatorauth.WindowsServiceControl {
				can = true
			}
		}
	}
	if !can {
		v.Reason = "operator_capability_required"
		v.Preview = nil
	} else if v.Preview != nil && v.Preview.ActorID != owner.session.ActorID() {
		v.Preview = nil
	}
	v.Available = v.Reason == "ready"
	if operatorStillActive(w, r) {
		write(w, 200, v)
	}
}
func windowsServiceActionError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, windowsaction.ErrInvalid):
		fail(w, 400, "windows_action_invalid", "The action request is invalid.")
	case errors.Is(e, windowsactionjob.ErrNotFound):
		fail(w, 404, "windows_action_not_found", "No pending action exists.")
	case errors.Is(e, windowsaction.ErrExpired):
		fail(w, 409, "windows_action_expired", "The original action deadline expired.")
	case errors.Is(e, windowsactionjob.ErrConflict), errors.Is(e, windowsaction.ErrConsumed):
		fail(w, 409, "windows_action_conflict", "Action changed or was consumed. Read saved status; do not submit a replacement.")
	case errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentstate.ErrExpired):
		fail(w, 403, "agent_unauthorized", "Current Windows identity authority is unavailable.")
	case errors.Is(e, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device unavailable.")
	default:
		fail(w, 409, "windows_action_unavailable", "The service action is unavailable. Execution is unconfirmed.")
	}
}
