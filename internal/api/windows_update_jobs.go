package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsupdatejob"
)

func windowsUpdateJobRoute(r *http.Request) (string, string, bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-update-jobs" {
		return "", "", false
	}
	op := ""
	if len(p) == 6 {
		op = p[5]
		if op != "request" && op != "approve" && op != "preview" {
			return "", "", false
		}
	}
	return p[3], op, true
}
func (h *operatorHandler) windowsUpdateJobsAPI(w http.ResponseWriter, r *http.Request) {
	device, op, ok := windowsUpdateJobRoute(r)
	if !ok {
		fail(w, 404, "not_found", "Update job unavailable.")
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	r = r.WithContext(h.windowsUpdateJobContext(r, op != ""))
	if op == "" {
		h.writeWindowsUpdateJobs(w, r, device)
		return
	}
	actor, release, ok := h.app.beginOperatorCapability(w, r, operatorauth.WindowsUpdateInstall)
	if !ok {
		return
	}
	// No session lease spans client-controlled body reads.
	release()
	if h.windowsUpdateJobs == nil || h.insecureHTTPTest {
		windowsUpdateJobError(w, windowsupdatejob.ErrUnavailable)
		return
	}
	var mutate func() error
	var selectedID string
	if op == "request" {
		var in struct {
			RequestID string `json:"requestId"`
			UpdateID  string `json:"updateId"`
			Revision  uint32 `json:"revision"`
		}
		if !readObject(w, r, 512, []string{"requestId", "updateId", "revision"}, &in) {
			return
		}
		selectedID = in.RequestID
		mutate = func() error {
			return h.windowsUpdateJobs.Request(r.Context(), device, actor, in.RequestID, windowsupdatejob.Selection{UpdateID: in.UpdateID, Revision: in.Revision})
		}
	} else if op == "preview" {
		var in struct {
			RequestID string `json:"requestId"`
		}
		if !readObject(w, r, 512, []string{"requestId"}, &in) {
			return
		}
		selectedID = in.RequestID
		mutate = func() error { return h.windowsUpdateJobs.Review(r.Context(), device, actor, in.RequestID) }
	} else {
		var in struct {
			PreviewID     string `json:"previewId"`
			PreviewDigest string `json:"previewDigest"`
			Acknowledged  bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 1024, []string{"previewId", "previewDigest", "acknowledged"}, &in) {
			return
		}
		selectedID = in.PreviewID
		mutate = func() error {
			return h.windowsUpdateJobs.Approve(r.Context(), device, actor, in.PreviewID, in.PreviewDigest, in.Acknowledged)
		}
	}
	currentActor, release, ok := h.app.beginOperatorCapability(w, r, operatorauth.WindowsUpdateInstall)
	if !ok {
		return
	}
	defer release()
	if currentActor != actor {
		windowsUpdateJobError(w, windowsupdatejob.ErrAuthority)
		return
	}
	e := mutate()
	release()
	if e != nil {
		windowsUpdateJobError(w, e)
		return
	}
	h.writeWindowsUpdateJobs(w, r, device, selectedID)
}

// Supply the live clock and session guard through the manager to the same
// enrollment commit fence. A timestamp sampled before SQLite waits is not enough.
func (h *operatorHandler) windowsUpdateJobContext(r *http.Request, mutation bool) context.Context {
	ctx := enrollmentstore.WithOverviewClock(r.Context(), h.auth.Now)
	owner, ok := operatorContext(r)
	return windowsupdatejob.WithFinalCheck(ctx, func() error {
		if !ok || !h.auth.Now().Before(owner.session.ExpiresAt) || owner.session.Lifetime().Err() != nil || owner.active == nil || !owner.active() {
			return windowsupdatejob.ErrAuthority
		}
		if mutation && (!owner.session.Named() || !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsUpdateInstall)) {
			return windowsupdatejob.ErrAuthority
		}
		return nil
	})
}
func (h *operatorHandler) writeWindowsUpdateJobs(w http.ResponseWriter, r *http.Request, device string, ids ...string) {
	v := windowsupdatejob.View{Version: windowsupdatejob.Version, DeviceID: device, ServerNow: h.auth.Now().UTC().Unix(), Reason: "executor_not_configured"}
	owner, ok := operatorContext(r)
	can := false
	if ok && owner.session.Named() {
		for _, c := range owner.session.Capabilities() {
			if c == operatorauth.WindowsUpdateInstall {
				can = true
			}
		}
	}
	if h.windowsUpdateJobs == nil {
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
		var e error
		v, e = h.windowsUpdateJobs.View(r.Context(), device, owner.session.ActorID(), ids...)
		if e != nil {
			windowsUpdateJobError(w, e)
			return
		}
	}
	if !can {
		v.Available = false
		v.Reason = "operator_capability_required"
		if v.Job != nil {
			v.Job.Preview = nil
		}
	}
	if h.insecureHTTPTest {
		v.Available = false
		v.Reason = "tls_required"
		if v.Job != nil {
			v.Job.Preview = nil
		}
	}
	if operatorStillActive(w, r) {
		write(w, 200, v)
	}
}
func windowsUpdateJobError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, windowsupdatejob.ErrInvalid):
		fail(w, 400, "windows_update_job_invalid", "The exact update request is invalid.")
	case errors.Is(e, windowsupdatejob.ErrAuthority):
		fail(w, 403, "windows_update_job_authority", "Current identity or local update authority is unavailable.")
	case errors.Is(e, windowsupdatejob.ErrExpired):
		fail(w, 409, "windows_update_job_expired", "The original update review expired.")
	case errors.Is(e, windowsupdatejob.ErrConflict), errors.Is(e, windowsupdatejob.ErrConsumed):
		fail(w, 409, "windows_update_job_conflict", "Read saved status before submitting another request.")
	default:
		fail(w, 409, "windows_update_job_unavailable", "The update job is unavailable or its result is unconfirmed. Read saved status; do not retry installation.")
	}
}
