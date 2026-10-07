package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/operatorauth"
	"net/http"
	"strings"
	"unicode/utf8"
)

const applicationCheckSettingsBodyLimit = 32768

// The settings DTO contains destinations, unlike the redacted status DTO. Both
// reads and writes require the specific administrator authority before access.
func (h *operatorHandler) applicationCheckSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_request", "Application check settings do not accept query parameters.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(w, 400, "invalid_request", "Application check settings reads do not accept a body.")
			return
		}
		h.writeApplicationCheckSettings(w, r)
	case http.MethodPost:
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		in, ok := readApplicationCheckSettingsChange(w, r)
		if !ok {
			return
		}
		defer func() {
			for _, target := range in.Targets {
				clear(target)
			}
		}()
		actor, release, ok := h.beginApplicationCheckAdministration(w, r)
		if !ok {
			return
		}
		defer release()
		// Keep admission through persistence and cancellation/join of an
		// already-admitted, five-second-bounded attempt. Change starts no
		// network I/O and rechecks cancellation before durable commit; logout
		// must not confirm while old-generation work remains admitted.
		err := h.applicationCheckSettings.Change(r.Context(), in, actor)
		release()
		if err != nil {
			applicationCheckSettingsError(w, err)
			return
		}
		h.writeApplicationCheckSettings(w, r)
	default:
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
	}
}

func (h *operatorHandler) beginApplicationCheckAdministration(w http.ResponseWriter, r *http.Request) (string, func(), bool) {
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authenticated application check administrator is required.")
		return "", nil, false
	}
	if !operatorStillActive(w, r) {
		return "", nil, false
	}
	if op.session.Named() {
		if r.Method == http.MethodPost {
			return h.app.beginOperatorCapability(w, r, operatorauth.ManageApplicationChecks)
		}
		release, err := op.session.BeginCapability(r.Context(), operatorauth.ManageApplicationChecks)
		if err != nil {
			if errors.Is(err, operatorauth.ErrUnauthenticated) {
				fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
			} else {
				fail(w, 403, "operator_capability_required", "Application check administration permission is required.")
			}
			return "", nil, false
		}
		return op.session.ActorID(), release, true
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return "", nil, false
	}
	return "shared-administrator", release, true
}

func (h *operatorHandler) writeApplicationCheckSettings(w http.ResponseWriter, r *http.Request) {
	_, release, ok := h.beginApplicationCheckAdministration(w, r)
	if !ok {
		return
	}
	defer release()
	view := h.applicationCheckSettings.View()
	release()
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, view)
}

// Optional request fields are operation-specific. Presence matters, including
// false or empty values: unrelated fields must never silently add authority.
func readApplicationCheckSettingsChange(w http.ResponseWriter, r *http.Request) (applicationcheck.SettingsChange, bool) {
	var in applicationcheck.SettingsChange
	invalid := func() (applicationcheck.SettingsChange, bool) {
		fail(w, 400, "invalid_application_check_settings", "Use the exact typed fields for save, enable or disable.")
		return applicationcheck.SettingsChange{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, applicationCheckSettingsBodyLimit))
	defer clear(raw)
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return in, false
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return invalid()
	}
	allowed := map[string]bool{"expectedRevision": true, "operation": true, "intervalSeconds": true, "targets": true, "checksFromManagerAcknowledged": true, "destinationsAcknowledged": true, "plaintextAcknowledged": true}
	fields := map[string]json.RawMessage{}
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return invalid()
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || fields[key] != nil {
			return invalid()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid()
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return invalid()
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid()
	}
	if json.Unmarshal(fields["expectedRevision"], &in.ExpectedRevision) != nil || json.Unmarshal(fields["operation"], &in.Operation) != nil || strings.ContainsRune(in.ExpectedRevision, utf8.RuneError) {
		return invalid()
	}
	switch in.Operation {
	case "save":
		if len(fields) != 4 || json.Unmarshal(fields["intervalSeconds"], &in.IntervalSeconds) != nil || json.Unmarshal(fields["targets"], &in.Targets) != nil || in.IntervalSeconds < 60 || in.IntervalSeconds > 3600 || len(in.Targets) < 1 || len(in.Targets) > applicationcheck.MaxTargets {
			return invalid()
		}
	case "enable":
		if len(fields) < 4 || len(fields) > 5 || fields["intervalSeconds"] != nil || fields["targets"] != nil || json.Unmarshal(fields["checksFromManagerAcknowledged"], &in.ChecksFromManagerAcknowledged) != nil || json.Unmarshal(fields["destinationsAcknowledged"], &in.DestinationsAcknowledged) != nil {
			return invalid()
		}
		if fields["plaintextAcknowledged"] != nil && json.Unmarshal(fields["plaintextAcknowledged"], &in.PlaintextAcknowledged) != nil {
			return invalid()
		}
	case "disable":
		if len(fields) != 2 {
			return invalid()
		}
	default:
		return invalid()
	}
	return in, operatorStillActive(w, r)
}

func applicationCheckSettingsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, applicationcheck.ErrSettingsConflict):
		fail(w, 409, "application_check_settings_changed", "Application check settings changed. Refresh and review the current destinations before trying again.")
	case errors.Is(err, applicationcheck.ErrSettingsBusy):
		fail(w, 409, "application_check_settings_busy", "An application check settings change is in progress. Refresh before trying again.")
	case errors.Is(err, applicationcheck.ErrConfiguration):
		fail(w, 400, "invalid_application_check_settings", "Review the typed targets, interval and required acknowledgements.")
	default:
		fail(w, 503, "application_check_settings_unavailable", "Application check settings could not be changed. Refresh and review manager configuration before trying again.")
	}
}
