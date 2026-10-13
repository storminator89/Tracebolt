package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsupdatejob"
)

func windowsUpdateQueryAllowed(u *url.URL) bool {
	if u == nil {
		return false
	}
	_, op, ok := windowsUpdateJobRoute(&http.Request{URL: u})
	if !ok || op != "" {
		return false
	}
	if u.RawQuery == "history=1" {
		return true
	}
	return strings.HasPrefix(u.RawQuery, "jobId=") && enrollmentcrypto.ValidID(strings.TrimPrefix(u.RawQuery, "jobId="), "update_")
}
func windowsUpdateJobRoute(r *http.Request) (string, string, bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-update-jobs" {
		return "", "", false
	}
	op := ""
	if len(p) == 6 {
		op = p[5]
		if op != "request" && op != "approve" && op != "preview" && op != "retire" && !windowsUpdateDownloadOperation(op) && !windowsUpdateScheduleOperation(op) {
			return "", "", false
		}
	}
	return p[3], op, true
}
func windowsUpdateDownloadOperation(op string) bool {
	return op == "request-download" || op == "preview-download" || op == "approve-download" || op == "retire-download"
}
func windowsUpdateCapability(op string) operatorauth.Capability {
	if windowsUpdateDownloadOperation(op) {
		return operatorauth.WindowsUpdateDownload
	}
	return operatorauth.WindowsUpdateInstall
}
func windowsUpdateScheduleOperation(op string) bool {
	return op == "schedule" || op == "cancel-schedule" || op == "revoke-scheduling"
}

// One short purpose-specific capability lease also fences the separately required live
// scheduling capability. Never nest session leases or hold one during body reads.
func (h *operatorHandler) beginWindowsUpdateMutation(w http.ResponseWriter, r *http.Request, op string) (string, func(), bool) {
	actor, release, ok := h.app.beginOperatorCapability(w, r, windowsUpdateCapability(op))
	if !ok {
		return "", nil, false
	}
	if windowsUpdateScheduleOperation(op) && !h.auth.ActorHasCapability(actor, operatorauth.WindowsUpdateSchedule) {
		release()
		fail(w, 403, "operator_capability_required", "Separate named Windows update install and scheduling permissions are required.")
		return "", nil, false
	}
	return actor, release, true
}
func (h *operatorHandler) windowsUpdateManager(device string) *windowsupdatejob.Manager {
	if h.windowsUpdateRegistry != nil {
		return h.windowsUpdateRegistry.Manager(device)
	}
	if h.windowsUpdateJobs != nil && h.windowsUpdateJobs.Binding().DeviceID == device {
		return h.windowsUpdateJobs
	}
	return nil
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
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			windowsUpdateJobError(w, windowsupdatejob.ErrInvalid)
			return
		}
		if len(q) == 0 {
			h.writeWindowsUpdateJobs(w, r, device)
			return
		}
		if len(q) != 1 {
			windowsUpdateJobError(w, windowsupdatejob.ErrInvalid)
			return
		}
		if ids, exists := q["jobId"]; exists && len(ids) == 1 && enrollmentcrypto.ValidID(ids[0], "update_") {
			h.writeWindowsUpdateJobs(w, r, device, ids[0])
			return
		}
		if history, exists := q["history"]; exists && len(history) == 1 && history[0] == "1" {
			h.writeWindowsUpdateHistory(w, r, device)
			return
		}
		windowsUpdateJobError(w, windowsupdatejob.ErrInvalid)
		return
	}
	if r.URL.RawQuery != "" {
		windowsUpdateJobError(w, windowsupdatejob.ErrInvalid)
		return
	}
	manager := h.windowsUpdateManager(device)
	actor, release, ok := h.beginWindowsUpdateMutation(w, r, op)
	if !ok {
		return
	}
	// No session lease spans client-controlled body reads.
	release()
	if manager == nil || h.insecureHTTPTest {
		windowsUpdateJobError(w, windowsupdatejob.ErrUnavailable)
		return
	}
	var mutate func() error
	var selectedID string
	if op == "request" || op == "request-download" {
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
			if op == "request-download" {
				return manager.RequestDownload(r.Context(), device, actor, in.RequestID, windowsupdatejob.Selection{UpdateID: in.UpdateID, Revision: in.Revision})
			}
			return manager.Request(r.Context(), device, actor, in.RequestID, windowsupdatejob.Selection{UpdateID: in.UpdateID, Revision: in.Revision})
		}
	} else if op == "retire" || op == "retire-download" {
		var in struct {
			JobID          string `json:"jobId"`
			Occurrence     uint64 `json:"occurrence,string"`
			EnvelopeDigest string `json:"envelopeDigest"`
			ResultDigest   string `json:"resultDigest"`
			Acknowledged   bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 1024, []string{"jobId", "occurrence", "envelopeDigest", "resultDigest", "acknowledged"}, &in) {
			return
		}
		selectedID = in.JobID
		mutate = func() error {
			if op == "retire-download" {
				return manager.RetireDownload(r.Context(), device, actor, in.JobID, in.Occurrence, in.EnvelopeDigest, in.ResultDigest, in.Acknowledged)
			}
			return manager.Retire(r.Context(), device, actor, in.JobID, in.Occurrence, in.EnvelopeDigest, in.ResultDigest, in.Acknowledged)
		}
	} else if op == "preview" || op == "preview-download" {
		var in struct {
			RequestID string `json:"requestId"`
		}
		if !readObject(w, r, 512, []string{"requestId"}, &in) {
			return
		}
		selectedID = in.RequestID
		mutate = func() error {
			if op == "preview-download" {
				return manager.ReviewDownload(r.Context(), device, actor, in.RequestID)
			}
			return manager.Review(r.Context(), device, actor, in.RequestID)
		}
	} else if op == "schedule" {
		var in struct {
			PreviewID     string `json:"previewId"`
			PreviewDigest string `json:"previewDigest"`
			StartAt       int64  `json:"startAt"`
			EndAt         int64  `json:"endAt"`
			Acknowledged  bool   `json:"acknowledged"`
		}
		if !readObject(w, r, 1024, []string{"previewId", "previewDigest", "startAt", "endAt", "acknowledged"}, &in) {
			return
		}
		selectedID = in.PreviewID
		mutate = func() error {
			return manager.Schedule(r.Context(), device, actor, in.PreviewID, in.PreviewDigest, in.StartAt, in.EndAt, in.Acknowledged)
		}
	} else if op == "cancel-schedule" {
		var in struct {
			ScheduleID     string `json:"scheduleId"`
			ScheduleDigest string `json:"scheduleDigest"`
		}
		if !readObject(w, r, 512, []string{"scheduleId", "scheduleDigest"}, &in) {
			return
		}
		selectedID = in.ScheduleID
		mutate = func() error {
			return manager.CancelSchedule(r.Context(), device, actor, in.ScheduleID, in.ScheduleDigest)
		}
	} else if op == "revoke-scheduling" {
		var in struct {
			Acknowledged bool `json:"acknowledged"`
		}
		if !readObject(w, r, 128, []string{"acknowledged"}, &in) {
			return
		}
		mutate = func() error { return manager.RevokeScheduling(r.Context(), device, actor, in.Acknowledged) }
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
			if op == "approve-download" {
				return manager.ApproveDownload(r.Context(), device, actor, in.PreviewID, in.PreviewDigest, in.Acknowledged)
			}
			return manager.Approve(r.Context(), device, actor, in.PreviewID, in.PreviewDigest, in.Acknowledged)
		}
	}
	currentActor, release, ok := h.beginWindowsUpdateMutation(w, r, op)
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
	if selectedID == "" {
		h.writeWindowsUpdateJobs(w, r, device)
	} else {
		h.writeWindowsUpdateJobs(w, r, device, selectedID)
	}
}

// Supply the live clock and session guard through the manager to the same
// enrollment commit fence. A timestamp sampled before SQLite waits is not enough.
func (h *operatorHandler) windowsUpdateJobContext(r *http.Request, mutation bool) context.Context {
	_, op, _ := windowsUpdateJobRoute(r)
	ctx := enrollmentstore.WithOverviewClock(r.Context(), h.auth.Now)
	owner, ok := operatorContext(r)
	return windowsupdatejob.WithFinalCheck(ctx, func() error {
		if !ok || !h.auth.Now().Before(owner.session.ExpiresAt) || owner.session.Lifetime().Err() != nil || owner.active == nil || !owner.active() {
			return windowsupdatejob.ErrAuthority
		}
		if mutation && (!owner.session.Named() || !h.auth.ActorHasCapability(owner.session.ActorID(), windowsUpdateCapability(op)) || windowsUpdateScheduleOperation(op) && !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsUpdateSchedule)) {
			return windowsupdatejob.ErrAuthority
		}
		return nil
	})
}
func (h *operatorHandler) writeWindowsUpdateJobs(w http.ResponseWriter, r *http.Request, device string, ids ...string) {
	v := windowsupdatejob.View{Version: windowsupdatejob.Version, DeviceID: device, ServerNow: h.auth.Now().UTC().Unix(), Reason: "executor_not_configured"}
	owner, ok := operatorContext(r)
	can, canDownload := false, false
	if ok && owner.session.Named() {
		for _, c := range owner.session.Capabilities() {
			if c == operatorauth.WindowsUpdateInstall {
				can = true
			}
			if c == operatorauth.WindowsUpdateDownload {
				canDownload = true
			}
		}
	}
	manager := h.windowsUpdateManager(device)
	if manager == nil {
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
		v, e = manager.View(r.Context(), device, owner.session.ActorID(), ids...)
		if e != nil {
			windowsUpdateJobError(w, e)
			return
		}
	}
	if !can || !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsUpdateSchedule) {
		v.SchedulingAvailable = false
	}
	v.DownloadAvailable = v.DownloadAvailable && canDownload
	if !can {
		v.Available = false
	}
	if !can && !canDownload {
		v.Reason = "operator_capability_required"
	}
	if v.Job != nil && (v.Job.Purpose == "download" && !canDownload || v.Job.Purpose != "download" && !can) {
		v.Job.Preview = nil
		if v.Job.Retirement != nil {
			v.Job.Retirement.State = "blocked"
		}
	}
	if h.insecureHTTPTest {
		v.DownloadAvailable = false
		v.SchedulingAvailable = false
		v.Available = false
		v.Reason = "tls_required"
		if v.Job != nil {
			v.Job.Preview = nil
			if v.Job.Retirement != nil {
				v.Job.Retirement.State = "blocked"
			}
		}
	}
	if operatorStillActive(w, r) {
		write(w, 200, v)
	}
}
func (h *operatorHandler) writeWindowsUpdateHistory(w http.ResponseWriter, r *http.Request, device string) {
	m := h.windowsUpdateManager(device)
	if m == nil || h.insecureHTTPTest {
		windowsUpdateJobError(w, windowsupdatejob.ErrUnavailable)
		return
	}
	v, e := m.History(r.Context(), device)
	if e != nil {
		windowsUpdateJobError(w, e)
		return
	}
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() || (!h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsUpdateInstall) && !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsUpdateDownload)) {
		v.Available = false
		v.Reason = "operator_capability_required"
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
		fail(w, 409, "windows_update_job_unavailable", "The update job is unavailable or its result is unconfirmed. Read saved status; do not retry the operation.")
	}
}
