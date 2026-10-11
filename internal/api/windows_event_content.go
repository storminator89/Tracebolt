package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type windowsEventCapabilityView struct {
	Enabled    bool      `json:"enabled"`
	GrantID    string    `json:"grantId"`
	ReportedAt time.Time `json:"reportedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}
type windowsEventView struct {
	SchemaVersion    string                               `json:"schemaVersion"`
	DeviceID         string                               `json:"deviceId"`
	ServerNow        time.Time                            `json:"serverNow"`
	Configured       bool                                 `json:"configured"`
	ExpectedFloor    string                               `json:"expectedFloor"`
	LocalStatus      string                               `json:"localStatus"`
	EndpointStatus   string                               `json:"endpointStatus,omitempty"`
	ContentStatus    string                               `json:"contentStatus"`
	Capability       *windowsEventCapabilityView          `json:"capability,omitempty"`
	Headers          *enrollmentstore.WindowsEventHeaders `json:"headers,omitempty"`
	Request          *windowseventwire.RecordDTO          `json:"request"`
	SessionBinding   string                               `json:"sessionBinding"`
	SessionExpiresAt time.Time                            `json:"sessionExpiresAt"`
}

func windowsEventOwner(r *http.Request) (windowseventcache.Owner, bool) {
	o, ok := operatorContext(r)
	if !ok || o.session.Named() {
		return windowseventcache.Owner{}, false
	}
	return windowseventcache.Owner{ID: o.session.ID, ExpiresAt: o.session.ExpiresAt, Lifetime: o.session.Lifetime(), Active: o.active}, true
}
func windowsEventSessionBinding(id string) string {
	s := sha256.Sum256([]byte("windows-event-content-session-v1:" + id))
	return hex.EncodeToString(s[:])
}
func (h *operatorHandler) windowsEventContent(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "windows-event-content" {
		fail(w, 404, "not_found", "Selected event content is unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
	}
	if action != "" && action != "create" && action != "cancel" && action != "query" {
		fail(w, 404, "not_found", "Selected event action is unavailable.")
		return
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	owner, ok := windowsEventOwner(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "Selected event content requires an administrator session.")
		return
	}
	service := h.windowsEnrollment
	if service == nil || service.enrollment == nil {
		fail(w, 409, "windows_event_content_not_configured", "Selected event content requires the separately configured Windows authority and local content grant.")
		return
	}
	if action == "" {
		service.writeWindowsEventView(w, r, parts[3], owner)
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	defer release()
	switch action {
	case "create":
		var in struct {
			ExpectedFloor                string            `json:"expectedFloor"`
			ExpectedHeaderGenerationID   string            `json:"expectedHeaderGenerationId"`
			ExpectedHeaderSnapshotDigest string            `json:"expectedHeaderSnapshotDigest"`
			Selections                   []json.RawMessage `json:"selections"`
			AcknowledgeContent           bool              `json:"acknowledgeContent"`
			AcknowledgePlaintext         bool              `json:"acknowledgePlaintext"`
		}
		if !readObject(w, r, 8192, []string{"expectedFloor", "expectedHeaderGenerationId", "expectedHeaderSnapshotDigest", "selections", "acknowledgeContent", "acknowledgePlaintext"}, &in) {
			return
		}
		floor, err := strconv.ParseUint(in.ExpectedFloor, 10, 64)
		if err != nil || strconv.FormatUint(floor, 10) != in.ExpectedFloor || len(in.Selections) < 1 || len(in.Selections) > 16 || !in.AcknowledgeContent || h.insecureHTTPTest && !in.AcknowledgePlaintext {
			fail(w, 400, "invalid_windows_event_request", "Select 1–16 displayed events and acknowledge the content privacy and applicable plaintext warning.")
			return
		}
		selected := make([]windowseventrequest.Selection, len(in.Selections))
		for i, raw := range in.Selections {
			var row struct {
				Channel  string `json:"channel"`
				RecordID string `json:"recordId"`
			}
			if !journalObject(raw, []string{"channel", "recordId"}, &row) {
				fail(w, 400, "invalid_windows_event_request", "An exact displayed event selection is required.")
				return
			}
			id, e := strconv.ParseUint(row.RecordID, 10, 64)
			if e != nil || id == 0 || strconv.FormatUint(id, 10) != row.RecordID {
				fail(w, 400, "invalid_windows_event_request", "The record identity is invalid.")
				return
			}
			selected[i] = windowseventrequest.Selection{Channel: row.Channel, RecordID: row.RecordID}
		}
		_, err = service.enrollment.CreateWindowsEventRequest(r.Context(), parts[3], owner, floor, in.ExpectedHeaderGenerationID, in.ExpectedHeaderSnapshotDigest, selected, service.enrollment.Now().UTC())
		release()
		if err != nil {
			windowsEventOperatorError(w, err)
			return
		}
		service.writeWindowsEventView(w, r, parts[3], owner)
	case "cancel", "query":
		var in struct {
			Identity json.RawMessage `json:"identity"`
		}
		if !readObject(w, r, 4096, []string{"identity"}, &in) {
			return
		}
		var id windowseventrequest.Identity
		if !journalObject(in.Identity, []string{"id", "sequence", "queryDigest"}, &id) || !windowseventwire.ValidIdentity(id) {
			fail(w, 400, "invalid_windows_event_request", "The request identity is invalid.")
			return
		}
		var seq struct {
			Sequence string `json:"sequence"`
		}
		if json.Unmarshal(in.Identity, &seq) != nil || strconv.FormatUint(id.Sequence, 10) != seq.Sequence {
			fail(w, 400, "invalid_windows_event_request", "The request sequence is invalid.")
			return
		}
		if action == "cancel" {
			err := service.enrollment.CancelWindowsEventRequest(r.Context(), parts[3], owner, id, service.enrollment.Now().UTC())
			release()
			if err != nil {
				windowsEventOperatorError(w, err)
				return
			}
			service.writeWindowsEventView(w, r, parts[3], owner)
			return
		}
		page, err := service.enrollment.WindowsEventContentQuery(r.Context(), parts[3], owner, id, service.enrollment.Now().UTC())
		release()
		if err != nil {
			windowsEventOperatorError(w, err)
			return
		}
		if !operatorStillActive(w, r) || !h.app.authorizeJSONMutation(w, r) {
			return
		}
		raw, err := json.Marshal(page)
		if err != nil || len(raw) > windowseventcache.MaxEntryBytes {
			clear(raw)
			windowsEventOperatorError(w, windowseventcache.ErrUnavailable)
			return
		}
		defer clear(raw)
		current, status, err := service.enrollment.WindowsEventContentStatus(r.Context(), parts[3], owner, service.enrollment.Now().UTC())
		if err != nil {
			windowsEventOperatorError(w, err)
			return
		}
		finalNow := service.enrollment.Now().UTC()
		if status != "available" || current.Request == nil || current.Request.Receipt == nil || *current.Request.Receipt != page.Receipt || current.Request.Description.Identity != page.Identity || finalNow.Before(current.ObservedAt) || !finalNow.Before(page.ExpiresAt) || !finalNow.Before(current.AuthorityUntil) || current.Capability == nil || windowseventwire.CapabilityFresh(*current.Capability, finalNow) != nil {
			windowsEventOperatorError(w, windowseventcache.ErrUnavailable)
			return
		}
		if !operatorStillActive(w, r) || !h.app.authorizeJSONMutation(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}
}
func (h *operatorHandler) writeWindowsEventView(w http.ResponseWriter, r *http.Request, device string, owner windowseventcache.Owner) {
	now := h.enrollment.Now().UTC()
	s, content, err := h.enrollment.WindowsEventContentStatus(r.Context(), device, owner, now)
	if err != nil {
		windowsEventOperatorError(w, err)
		return
	}
	now = s.ObservedAt
	v := windowsEventView{SchemaVersion: "tracebolt.windows-event-content-view.v1", DeviceID: device, ServerNow: now, Configured: true, ExpectedFloor: s.ExpectedFloor, LocalStatus: s.LocalStatus, ContentStatus: content, EndpointStatus: s.EndpointStatus, Headers: s.Headers, SessionBinding: windowsEventSessionBinding(owner.ID), SessionExpiresAt: owner.ExpiresAt}
	if s.Capability != nil {
		c := s.Capability
		v.Capability = &windowsEventCapabilityView{c.Consent.Enabled, c.Consent.GrantID, c.CollectedAt, c.CollectedAt.Add(windowseventwire.CapabilityMaxAge)}
	}
	if s.Request != nil {
		record, e := windowseventwire.RecordForBrowser(*s.Request)
		if e != nil {
			windowsEventOperatorError(w, e)
			return
		}
		v.Request = &record
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 64<<10 {
		windowsEventOperatorError(w, windowseventcache.ErrUnavailable)
		return
	}
	defer clear(raw)
	after := h.enrollment.Now().UTC()
	if after.Before(now) || !after.Before(owner.ExpiresAt) {
		windowsEventOperatorError(w, windowseventcache.ErrSession)
		return
	}
	current, status, err := h.enrollment.WindowsEventContentStatus(r.Context(), device, owner, after)
	if err != nil {
		windowsEventOperatorError(w, err)
		return
	}
	if current.ExpectedFloor != s.ExpectedFloor || status != content || current.LocalStatus != s.LocalStatus || current.Request != nil && s.Request != nil && current.Request.State != s.Request.State {
		windowsEventOperatorError(w, windowseventrequest.ErrConflict)
		return
	}
	finalNow := h.enrollment.Now().UTC()
	if finalNow.Before(current.ObservedAt) || !finalNow.Before(current.AuthorityUntil) || v.LocalStatus == "enabled" && (current.Capability == nil || windowseventwire.CapabilityFresh(*current.Capability, finalNow) != nil) || v.Headers != nil && !finalNow.Before(v.Headers.ExpiresAt) {
		windowsEventOperatorError(w, windowseventcache.ErrUnavailable)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
func windowsEventOperatorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, windowseventcache.ErrSession):
		fail(w, 401, "authentication_required", "The requesting administrator session is no longer active.")
	case errors.Is(err, windowseventrequest.ErrInvalid), errors.Is(err, windowseventwire.ErrContract):
		fail(w, 400, "invalid_windows_event_request", "The exact selected-event request is invalid.")
	case errors.Is(err, windowseventrequest.ErrConflict), errors.Is(err, windowseventrequest.ErrConsumed):
		fail(w, 409, "windows_event_conflict", "The selected-event request changed. Refresh before continuing.")
	case errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "windows_event_not_found", "Selected event content is unavailable.")
	case errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy), errors.Is(err, enrollmentstore.ErrWindowsEventCapacity):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "windows_event_busy", "The selected-event view is busy. Retry shortly.")
	case errors.Is(err, windowseventcache.ErrUnavailable), errors.Is(err, enrollmentstore.ErrWindowsEventUnavailable), errors.Is(err, windowseventrequest.ErrDisabled), errors.Is(err, windowseventrequest.ErrExpired), errors.Is(err, windowseventrequest.ErrCanceled):
		fail(w, 409, "windows_event_unavailable", "Selected event content is unavailable, disabled, canceled or expired. No automatic recollection occurs.")
	default:
		fail(w, 503, "windows_event_unavailable", "Selected event content authority is unavailable.")
	}
}
