package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"
)

func (h *operatorHandler) applicationIncidentsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_request", "Local incidents do not accept query parameters.")
		return
	}
	if h.applicationCheckSettings == nil {
		fail(w, 503, "application_incidents_unavailable", "Local application incidents are unavailable.")
		return
	}
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authenticated operator is required.")
		return
	}
	can := !op.session.Named()
	for _, c := range op.session.Capabilities() {
		if c == operatorauth.ManageApplicationChecks {
			can = true
		}
	}
	var command applicationcheck.IncidentCommand
	var release func()
	if r.Method == "POST" {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		var valid bool
		command, valid = readApplicationIncidentCommand(w, r)
		if !valid {
			return
		}
		_, release, valid = h.beginApplicationCheckAdministration(w, r)
		if !valid {
			return
		}
		defer release()
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		fail(w, 400, "invalid_request", "Local incident reads do not accept a body.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(7*time.Second)) != nil {
		fail(w, 503, "application_incidents_unavailable", "Local application incidents are unavailable.")
		return
	}
	leased := h.applicationCheckSettings.WithIncidentSource(func(source applicationcheck.IncidentSource) {
		var view applicationcheck.IncidentView
		var err error
		if r.Method == "POST" {
			view, err = h.app.store.ChangeApplicationIncidents(ctx, source, command, func() bool { return ctx.Err() == nil && op.active != nil && op.active() }, can)
		} else {
			view, err = h.app.store.ApplicationIncidents(ctx, source, can)
		}
		if errors.Is(err, store.ErrApplicationIncidentSession) {
			fail(w, 401, "authentication_required", "Operator session ended.")
			return
		}
		if errors.Is(err, applicationcheck.ErrIncidentInvalid) {
			fail(w, 409, "application_incidents_changed", "Local incident state or source changed. Read saved state before another review.")
			return
		}
		if err != nil {
			fail(w, 503, "application_incidents_unavailable", "Local incident storage is unavailable; a write outcome may be uncertain. Do not repeat it.")
			return
		}
		raw, e := json.Marshal(view)
		if e != nil || len(raw) > applicationcheck.IncidentMaxBytes {
			fail(w, 503, "application_incidents_unavailable", "Local application incidents are unavailable.")
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
	})
	if !leased {
		fail(w, 503, "application_incidents_busy", "Application checks are changing or unavailable. Read saved state later.")
	}
}

func readApplicationIncidentCommand(w http.ResponseWriter, r *http.Request) (applicationcheck.IncidentCommand, bool) {
	var c applicationcheck.IncidentCommand
	bad := func() (applicationcheck.IncidentCommand, bool) {
		fail(w, 400, "invalid_application_incident", "Use exactly the reviewed local incident command fields.")
		return c, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return c, false
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return bad()
	}
	fields := map[string]json.RawMessage{"requestId": nil, "expectedRevision": nil, "operation": nil, "sourceToken": nil, "targetIds": nil, "consecutiveFailures": nil, "incidentId": nil, "retentionAcknowledged": nil}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	count := 0
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return bad()
		}
		old, ok := fields[key]
		if !ok || old != nil {
			return bad()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return bad()
		}
		if key != "incidentId" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return bad()
		}
		fields[key] = value
		count++
	}
	if _, err = d.Token(); err != nil || count != len(fields) {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	if json.Unmarshal(raw, &c) != nil {
		return bad()
	}
	var rev string
	if json.Unmarshal(fields["expectedRevision"], &rev) != nil || rev != strconv.FormatUint(c.ExpectedRevision, 10) {
		return bad()
	}
	if !operatorStillActive(w, r) {
		return c, false
	}
	return c, true
}
