package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type windowsHistoryCapabilityView struct {
	Enabled    bool      `json:"enabled"`
	GrantID    string    `json:"grantId"`
	ReportedAt time.Time `json:"reportedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}
type windowsHistoryView struct {
	SchemaVersion    string                                 `json:"schemaVersion"`
	DeviceID         string                                 `json:"deviceId"`
	ServerNow        time.Time                              `json:"serverNow"`
	Configured       bool                                   `json:"configured"`
	ExpectedFloor    string                                 `json:"expectedFloor"`
	LocalStatus      string                                 `json:"localStatus"`
	EndpointStatus   string                                 `json:"endpointStatus,omitempty"`
	ContentStatus    string                                 `json:"contentStatus"`
	Capability       *windowsHistoryCapabilityView          `json:"capability,omitempty"`
	Headers          *enrollmentstore.WindowsHistoryHeaders `json:"headers,omitempty"`
	Request          *windowshistorywire.RecordDTO          `json:"request"`
	SessionBinding   string                                 `json:"sessionBinding"`
	SessionExpiresAt time.Time                              `json:"sessionExpiresAt"`
}

func windowsHistoryOwner(r *http.Request) (windowshistorycache.Owner, bool) {
	o, ok := operatorContext(r)
	if !ok || o.session.Named() {
		return windowshistorycache.Owner{}, false
	}
	return windowshistorycache.Owner{ID: o.session.ID, ExpiresAt: o.session.ExpiresAt, Lifetime: o.session.Lifetime(), Active: o.active}, true
}
func windowsHistorySessionBinding(id string) string {
	s := sha256.Sum256([]byte("windows-event-history-session-v1:" + id))
	return hex.EncodeToString(s[:])
}
func (h *operatorHandler) windowsHistory(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "windows-event-history" {
		fail(w, 404, "not_found", "Selected event content is unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
	}
	if action != "" && action != "create" && action != "messages" && action != "cancel" && action != "query" {
		fail(w, 404, "not_found", "Selected event action is unavailable.")
		return
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	owner, ok := windowsHistoryOwner(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "Selected event content requires an administrator session.")
		return
	}
	service := h.windowsEnrollment
	if service == nil || service.enrollment == nil {
		fail(w, 409, "windows_history_not_configured", "Selected event content requires the separately configured Windows authority and local content grant.")
		return
	}
	if action == "" {
		service.writeWindowsHistoryView(w, r, parts[3], owner)
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
			ExpectedFloor        string          `json:"expectedFloor"`
			Search               json.RawMessage `json:"search"`
			AcknowledgeHistory   bool            `json:"acknowledgeHistory"`
			AcknowledgePlaintext bool            `json:"acknowledgePlaintext"`
		}
		if !readObject(w, r, 4096, []string{"expectedFloor", "search", "acknowledgeHistory", "acknowledgePlaintext"}, &in) {
			return
		}
		floor, err := strconv.ParseUint(in.ExpectedFloor, 10, 64)
		var search windowseventhistory.Search
		if err != nil || strconv.FormatUint(floor, 10) != in.ExpectedFloor || !in.AcknowledgeHistory || h.insecureHTTPTest && !in.AcknowledgePlaintext || !windowsHistorySearchObject(in.Search, &search) {
			fail(w, 400, "invalid_windows_history_request", "Choose one Application/System channel and a UTC window, and acknowledge the history privacy warning.")
			return
		}
		_, err = service.enrollment.CreateWindowsHistorySearch(r.Context(), parts[3], owner, floor, search, service.enrollment.Now().UTC())
		release()
		if err != nil {
			windowsHistoryOperatorError(w, err)
			return
		}
		service.writeWindowsHistoryView(w, r, parts[3], owner)
	case "messages":
		var in struct {
			ExpectedFloor        string            `json:"expectedFloor"`
			Receipt              json.RawMessage   `json:"receipt"`
			Selections           []json.RawMessage `json:"selections"`
			AcknowledgeContent   bool              `json:"acknowledgeContent"`
			AcknowledgePlaintext bool              `json:"acknowledgePlaintext"`
		}
		if !readObject(w, r, 8192, []string{"expectedFloor", "receipt", "selections", "acknowledgeContent", "acknowledgePlaintext"}, &in) {
			return
		}
		floor, err := strconv.ParseUint(in.ExpectedFloor, 10, 64)
		var receipt windowshistoryrequest.Receipt
		if err != nil || strconv.FormatUint(floor, 10) != in.ExpectedFloor || len(in.Selections) < 1 || len(in.Selections) > 16 || !in.AcknowledgeContent || h.insecureHTTPTest && !in.AcknowledgePlaintext || !journalObject(in.Receipt, []string{"identity", "policyDigest", "resultDigest", "acceptedAt", "expiresAt"}, &receipt) {
			fail(w, 400, "invalid_windows_history_request", "Select 1–16 accepted search rows and acknowledge the message privacy warning.")
			return
		}
		selected := make([]windowshistoryrequest.Selection, len(in.Selections))
		for i, raw := range in.Selections {
			var row struct {
				Channel  string `json:"channel"`
				RecordID string `json:"recordId"`
			}
			if !journalObject(raw, []string{"channel", "recordId"}, &row) {
				fail(w, 400, "invalid_windows_history_request", "An exact accepted search row is required.")
				return
			}
			id, e := strconv.ParseUint(row.RecordID, 10, 64)
			if e != nil || id == 0 || strconv.FormatUint(id, 10) != row.RecordID {
				fail(w, 400, "invalid_windows_history_request", "Invalid record identity.")
				return
			}
			selected[i] = windowshistoryrequest.Selection{Channel: row.Channel, RecordID: row.RecordID}
		}
		_, err = service.enrollment.CreateWindowsHistoryMessages(r.Context(), parts[3], owner, floor, receipt, selected, service.enrollment.Now().UTC())
		release()
		if err != nil {
			windowsHistoryOperatorError(w, err)
			return
		}
		service.writeWindowsHistoryView(w, r, parts[3], owner)
	case "cancel", "query":
		var in struct {
			Identity json.RawMessage `json:"identity"`
		}
		if !readObject(w, r, 4096, []string{"identity"}, &in) {
			return
		}
		var id windowshistoryrequest.Identity
		if !journalObject(in.Identity, []string{"id", "sequence", "queryDigest"}, &id) || !windowshistorywire.ValidIdentity(id) {
			fail(w, 400, "invalid_windows_history_request", "The request identity is invalid.")
			return
		}
		var seq struct {
			Sequence string `json:"sequence"`
		}
		if json.Unmarshal(in.Identity, &seq) != nil || strconv.FormatUint(id.Sequence, 10) != seq.Sequence {
			fail(w, 400, "invalid_windows_history_request", "The request sequence is invalid.")
			return
		}
		if action == "cancel" {
			err := service.enrollment.CancelWindowsHistoryRequest(r.Context(), parts[3], owner, id, service.enrollment.Now().UTC())
			release()
			if err != nil {
				windowsHistoryOperatorError(w, err)
				return
			}
			service.writeWindowsHistoryView(w, r, parts[3], owner)
			return
		}
		page, err := service.enrollment.WindowsHistoryQuery(r.Context(), parts[3], owner, id, service.enrollment.Now().UTC())
		release()
		if err != nil {
			windowsHistoryOperatorError(w, err)
			return
		}
		if !operatorStillActive(w, r) || !h.app.authorizeJSONMutation(w, r) {
			return
		}
		raw, err := json.Marshal(page)
		if err != nil || len(raw) > windowshistorycache.MaxEntryBytes {
			clear(raw)
			windowsHistoryOperatorError(w, windowshistorycache.ErrUnavailable)
			return
		}
		defer clear(raw)
		current, status, err := service.enrollment.WindowsHistoryStatus(r.Context(), parts[3], owner, service.enrollment.Now().UTC())
		if err != nil {
			windowsHistoryOperatorError(w, err)
			return
		}
		finalNow := service.enrollment.Now().UTC()
		if status != "available" || current.Request == nil || current.Request.Receipt == nil || *current.Request.Receipt != page.Receipt || current.Request.Description.Identity != page.Identity || finalNow.Before(current.ObservedAt) || !finalNow.Before(page.ExpiresAt) || !finalNow.Before(current.AuthorityUntil) || current.Capability == nil || windowshistorywire.CapabilityFresh(*current.Capability, finalNow) != nil {
			windowsHistoryOperatorError(w, windowshistorycache.ErrUnavailable)
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
func (h *operatorHandler) writeWindowsHistoryView(w http.ResponseWriter, r *http.Request, device string, owner windowshistorycache.Owner) {
	now := h.enrollment.Now().UTC()
	s, content, err := h.enrollment.WindowsHistoryStatus(r.Context(), device, owner, now)
	if err != nil {
		windowsHistoryOperatorError(w, err)
		return
	}
	now = s.ObservedAt
	v := windowsHistoryView{SchemaVersion: "tracebolt.windows-event-history-view.v1", DeviceID: device, ServerNow: now, Configured: true, ExpectedFloor: s.ExpectedFloor, LocalStatus: s.LocalStatus, ContentStatus: content, EndpointStatus: s.EndpointStatus, Headers: s.Headers, SessionBinding: windowsHistorySessionBinding(owner.ID), SessionExpiresAt: owner.ExpiresAt}
	if s.Capability != nil {
		c := s.Capability
		v.Capability = &windowsHistoryCapabilityView{c.Consent.Enabled, c.Consent.GrantID, c.CollectedAt, c.CollectedAt.Add(windowshistorywire.CapabilityMaxAge)}
	}
	if s.Request != nil {
		record, e := windowshistorywire.RecordForBrowser(*s.Request)
		if e != nil {
			windowsHistoryOperatorError(w, e)
			return
		}
		v.Request = &record
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 64<<10 {
		windowsHistoryOperatorError(w, windowshistorycache.ErrUnavailable)
		return
	}
	defer clear(raw)
	after := h.enrollment.Now().UTC()
	if after.Before(now) || !after.Before(owner.ExpiresAt) {
		windowsHistoryOperatorError(w, windowshistorycache.ErrSession)
		return
	}
	current, status, err := h.enrollment.WindowsHistoryStatus(r.Context(), device, owner, after)
	if err != nil {
		windowsHistoryOperatorError(w, err)
		return
	}
	if current.ExpectedFloor != s.ExpectedFloor || status != content || current.LocalStatus != s.LocalStatus || current.Request != nil && s.Request != nil && current.Request.State != s.Request.State {
		windowsHistoryOperatorError(w, windowshistoryrequest.ErrConflict)
		return
	}
	finalNow := h.enrollment.Now().UTC()
	if finalNow.Before(current.ObservedAt) || !finalNow.Before(current.AuthorityUntil) || v.LocalStatus == "enabled" && (current.Capability == nil || windowshistorywire.CapabilityFresh(*current.Capability, finalNow) != nil) || v.Headers != nil && !finalNow.Before(v.Headers.ExpiresAt) {
		windowsHistoryOperatorError(w, windowshistorycache.ErrUnavailable)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
func windowsHistoryOperatorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, windowshistorycache.ErrSession):
		fail(w, 401, "authentication_required", "The requesting administrator session is no longer active.")
	case errors.Is(err, windowshistoryrequest.ErrInvalid), errors.Is(err, windowshistorywire.ErrContract):
		fail(w, 400, "invalid_windows_history_request", "The exact selected-event request is invalid.")
	case errors.Is(err, windowshistoryrequest.ErrConflict), errors.Is(err, windowshistoryrequest.ErrConsumed):
		fail(w, 409, "windows_history_conflict", "The selected-event request changed. Refresh before continuing.")
	case errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "windows_history_not_found", "Selected event content is unavailable.")
	case errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy), errors.Is(err, enrollmentstore.ErrWindowsHistoryCapacity):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "windows_history_busy", "The selected-event view is busy. Retry shortly.")
	case errors.Is(err, windowshistorycache.ErrUnavailable), errors.Is(err, enrollmentstore.ErrWindowsHistoryUnavailable), errors.Is(err, windowshistoryrequest.ErrDisabled), errors.Is(err, windowshistoryrequest.ErrExpired), errors.Is(err, windowshistoryrequest.ErrCanceled):
		fail(w, 409, "windows_history_unavailable", "Selected event content is unavailable, disabled, canceled or expired. No automatic recollection occurs.")
	default:
		fail(w, 503, "windows_history_unavailable", "Selected event content authority is unavailable.")
	}
}

func windowsHistorySearchObject(raw []byte, out *windowseventhistory.Search) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	keys := []string{"channel", "start", "end"}
	for _, optional := range []string{"level", "eventId"} {
		if _, ok := fields[optional]; ok {
			keys = append(keys, optional)
		}
	}
	return journalObject(raw, keys, out)
}
