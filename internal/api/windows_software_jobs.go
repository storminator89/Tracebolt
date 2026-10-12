package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowssoftwarejob"
)

func windowsSoftwareQueryAllowed(u *url.URL) bool {
	if u == nil {
		return false
	}
	_, op, ok := windowsSoftwareJobRoute(&http.Request{URL: u})
	if !ok || op != "" {
		return false
	}
	if u.RawQuery == "history=1" {
		return true
	}
	return strings.HasPrefix(u.RawQuery, "jobId=") && enrollmentcrypto.ValidID(strings.TrimPrefix(u.RawQuery, "jobId="), "software_")
}
func windowsSoftwareJobRoute(r *http.Request) (string, string, bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 || p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "windows-software-jobs" {
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

// One short install-capability lease also fences the separately required live
// scheduling capability. Never nest session leases or hold one during body reads.
func (h *operatorHandler) beginWindowsSoftwareMutation(w http.ResponseWriter, r *http.Request, op string) (string, func(), bool) {
	actor, release, ok := h.app.beginOperatorCapability(w, r, operatorauth.WindowsSoftwareInstall)
	if !ok {
		return "", nil, false
	}

	return actor, release, true
}
func (h *operatorHandler) windowsSoftwareManager(device string) *windowssoftwarejob.Manager {
	if h.windowsSoftwareRegistry != nil {
		return h.windowsSoftwareRegistry.Manager(device)
	}
	if h.windowsSoftwareJobs != nil && h.windowsSoftwareJobs.Binding().DeviceID == device {
		return h.windowsSoftwareJobs
	}
	return nil
}
func (h *operatorHandler) windowsSoftwareJobsAPI(w http.ResponseWriter, r *http.Request) {
	device, op, ok := windowsSoftwareJobRoute(r)
	if !ok {
		fail(w, 404, "not_found", "Prepared MSI job unavailable.")
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	r = r.WithContext(h.windowsSoftwareJobContext(r, op != ""))
	if op == "" {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			windowsSoftwareJobError(w, windowssoftwarejob.ErrInvalid)
			return
		}
		if len(q) == 0 {
			h.writeWindowsSoftwareJobs(w, r, device)
			return
		}
		if len(q) != 1 {
			windowsSoftwareJobError(w, windowssoftwarejob.ErrInvalid)
			return
		}
		if ids, exists := q["jobId"]; exists && len(ids) == 1 && enrollmentcrypto.ValidID(ids[0], "software_") {
			h.writeWindowsSoftwareJobs(w, r, device, ids[0])
			return
		}
		if history, exists := q["history"]; exists && len(history) == 1 && history[0] == "1" {
			h.writeWindowsSoftwareHistory(w, r, device)
			return
		}
		windowsSoftwareJobError(w, windowssoftwarejob.ErrInvalid)
		return
	}
	if r.URL.RawQuery != "" {
		windowsSoftwareJobError(w, windowssoftwarejob.ErrInvalid)
		return
	}
	manager := h.windowsSoftwareManager(device)
	actor, release, ok := h.beginWindowsSoftwareMutation(w, r, op)
	if !ok {
		return
	}
	// No session lease spans client-controlled body reads.
	release()
	if manager == nil || h.insecureHTTPTest {
		windowsSoftwareJobError(w, windowssoftwarejob.ErrUnavailable)
		return
	}
	var mutate func() error
	var selectedID string
	if op == "request" {
		var in struct {
			RequestID string          `json:"requestId"`
			Package   json.RawMessage `json:"package"`
		}
		if !readObject(w, r, 2048, []string{"requestId", "package"}, &in) {
			return
		}
		selection, valid := decodeSoftwarePackageSelection(in.Package)
		if !valid {
			windowsSoftwareJobError(w, windowssoftwarejob.ErrInvalid)
			return
		}
		selectedID = in.RequestID
		mutate = func() error { return manager.Request(r.Context(), device, actor, in.RequestID, selection) }
	} else if op == "preview" {
		var in struct {
			RequestID string `json:"requestId"`
		}
		if !readObject(w, r, 512, []string{"requestId"}, &in) {
			return
		}
		selectedID = in.RequestID
		mutate = func() error { return manager.Review(r.Context(), device, actor, in.RequestID) }
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
			return manager.Approve(r.Context(), device, actor, in.PreviewID, in.PreviewDigest, in.Acknowledged)
		}
	}
	currentActor, release, ok := h.beginWindowsSoftwareMutation(w, r, op)
	if !ok {
		return
	}
	defer release()
	if currentActor != actor {
		windowsSoftwareJobError(w, windowssoftwarejob.ErrAuthority)
		return
	}
	e := mutate()
	release()
	if e != nil {
		windowsSoftwareJobError(w, e)
		return
	}
	if selectedID == "" {
		h.writeWindowsSoftwareJobs(w, r, device)
	} else {
		h.writeWindowsSoftwareJobs(w, r, device, selectedID)
	}
}

// Supply the live clock and session guard through the manager to the same
// enrollment commit fence. A timestamp sampled before SQLite waits is not enough.
func (h *operatorHandler) windowsSoftwareJobContext(r *http.Request, mutation bool) context.Context {
	ctx := enrollmentstore.WithOverviewClock(r.Context(), h.auth.Now)
	owner, ok := operatorContext(r)
	return windowssoftwarejob.WithFinalCheck(ctx, func() error {
		if !ok || !h.auth.Now().Before(owner.session.ExpiresAt) || owner.session.Lifetime().Err() != nil || owner.active == nil || !owner.active() {
			return windowssoftwarejob.ErrAuthority
		}
		if mutation && (!owner.session.Named() || !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsSoftwareInstall)) {
			return windowssoftwarejob.ErrAuthority
		}
		return nil
	})
}
func (h *operatorHandler) writeWindowsSoftwareJobs(w http.ResponseWriter, r *http.Request, device string, ids ...string) {
	v := windowssoftwarejob.View{Version: windowssoftwarejob.Version, DeviceID: device, ServerNow: h.auth.Now().UTC().Unix(), Reason: "executor_not_configured"}
	owner, ok := operatorContext(r)
	can := false
	if ok && owner.session.Named() {
		for _, c := range owner.session.Capabilities() {
			if c == operatorauth.WindowsSoftwareInstall {
				can = true
			}
		}
	}
	manager := h.windowsSoftwareManager(device)
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
			windowsSoftwareJobError(w, e)
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
func (h *operatorHandler) writeWindowsSoftwareHistory(w http.ResponseWriter, r *http.Request, device string) {
	m := h.windowsSoftwareManager(device)
	if m == nil || h.insecureHTTPTest {
		windowsSoftwareJobError(w, windowssoftwarejob.ErrUnavailable)
		return
	}
	v, e := m.History(r.Context(), device)
	if e != nil {
		windowsSoftwareJobError(w, e)
		return
	}
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() || !h.auth.ActorHasCapability(owner.session.ActorID(), operatorauth.WindowsSoftwareInstall) {
		v.Available = false
		v.Reason = "operator_capability_required"
	}
	if operatorStillActive(w, r) {
		write(w, 200, v)
	}
}
func windowsSoftwareJobError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, windowssoftwarejob.ErrInvalid):
		fail(w, 400, "windows_software_job_invalid", "The exact prepared MSI request is invalid.")
	case errors.Is(e, windowssoftwarejob.ErrAuthority):
		fail(w, 403, "windows_software_job_authority", "Current identity or local software authority is unavailable.")
	case errors.Is(e, windowssoftwarejob.ErrExpired):
		fail(w, 409, "windows_software_job_expired", "The original package review expired.")
	case errors.Is(e, windowssoftwarejob.ErrConflict), errors.Is(e, windowssoftwarejob.ErrConsumed):
		fail(w, 409, "windows_software_job_conflict", "Read saved status before submitting another request.")
	default:
		fail(w, 409, "windows_software_job_unavailable", "The prepared MSI job is unavailable or its result is unconfirmed. Read saved status; do not retry installation.")
	}
}

// Reject alternate interpretations of the exact reviewed closed scalar shape.
func decodeSoftwarePackageSelection(raw []byte) (windowssoftwarejob.Selection, bool) {
	var selection windowssoftwarejob.Selection
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return selection, false
	}
	allowed := map[string]bool{"sha256": true, "size": true, "productCode": true, "packageCode": true, "version": true, "architecture": true, "name": true, "termsReviewDigest": true, "reviewReference": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return selection, false
	}
	seen := map[string]bool{}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		if e != nil || !ok || !allowed[key] || seen[key] {
			return selection, false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return selection, false
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return selection, false
	}
	if _, e = d.Token(); e != io.EOF {
		return selection, false
	}
	if json.Unmarshal(raw, &selection) != nil || !windowssoftwarejob.ValidSelection(selection) {
		return selection, false
	}
	return selection, true
}
