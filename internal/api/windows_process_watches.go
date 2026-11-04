package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	watch "localrmm/internal/windowsprocesswatch"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type windowsProcessWatchSource interface {
	WithWindowsProcessWatchAuthority(context.Context, string, []string, func(watch.Input, func(time.Time) error) error) error
	Now() time.Time
}

func (h *operatorHandler) windowsProcessWatchesAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 || len(parts) > 6 || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "windows-process-watches" || len(parts) == 6 && parts[5] != "policy" || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Process presence watches are unavailable.")
		return
	}
	mutation := len(parts) == 6
	if !mutation && r.Method != "GET" || mutation && r.Method != "POST" {
		method := "GET"
		if mutation {
			method = "POST"
		}
		w.Header().Set("Allow", method)
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.app.windowsCapacity == nil {
		fail(w, 404, "not_found", "Windows enrollment is not configured.")
		return
	}
	op, ok := operatorContext(r)
	if !ok || op.active == nil || !op.active() {
		fail(w, 401, "authentication_required", "Operator session is required.")
		return
	}
	var request watch.Request
	if mutation {
		if op.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to save selections.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readWindowsProcessWatchRequest(w, r, &request) {
			return
		}
		if _, e := watch.Names(request.Names); e != nil || request.ExpectedRevision >= 1<<53-1 || request.Enabled && (!request.Consent || len(request.Names) == 0 || request.Source == nil) || !request.Enabled && (request.Consent || len(request.Names) != 0 || request.Source != nil) {
			fail(w, 400, "invalid_windows_process_watch_policy", "Review up to eight exact names and explicitly confirm saved selection scope.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	source, ok := h.app.windowsCapacity.source.(windowsProcessWatchSource)
	if !ok {
		fail(w, 404, "not_found", "Process presence watches are unavailable.")
		return
	}
	id := parts[3]
	initial, e := h.app.store.WindowsProcessWatchState(r.Context(), id)
	if e != nil {
		fail(w, 503, "windows_process_watch_unavailable", "Saved selections are unavailable.")
		return
	}
	names := initial.Policy.Names
	if mutation {
		names = request.Names
	}
	var raw []byte
	var responseUntil, responseNow time.Time
	e = source.WithWindowsProcessWatchAuthority(r.Context(), id, names, func(in watch.Input, authority func(time.Time) error) error {
		guard := func(at time.Time) error {
			if !op.active() || r.Context().Err() != nil {
				return watch.ErrInvalid
			}
			if e := authority(at); e != nil {
				return e
			}
			if !op.active() {
				return watch.ErrInvalid
			}
			return nil
		}
		state, e := h.app.store.WindowsProcessWatchState(r.Context(), id)
		if e != nil {
			return e
		}
		// A concurrent policy cannot make a previously selected subset look complete.
		if state.Policy.Revision != initial.Policy.Revision {
			return watch.ErrInvalid
		}
		if mutation {
			state, e = h.app.store.ConfigureWindowsProcessWatch(r.Context(), in, request, source.Now, guard)
			if e != nil {
				return e
			}
		}
		at := source.Now().UTC()
		if e := guard(at); e != nil {
			return e
		}
		view, e := state.View(in, source.Now().UTC())
		if e != nil {
			return e
		}
		if op.session.ExpiresAt.Before(view.ExpiresAt) {
			view.ExpiresAt = op.session.ExpiresAt.UTC()
		}
		if !view.ServerNow.Before(view.ExpiresAt) {
			return watch.ErrInvalid
		}
		raw, e = json.Marshal(view)
		if e != nil || len(raw)+1 > watch.MaxBytes {
			return watch.ErrInvalid
		}
		responseUntil = view.ExpiresAt
		responseNow = view.ServerNow
		return guard(source.Now().UTC())
	})
	if e != nil {
		clear(raw)
		if errors.Is(e, watch.ErrInvalid) || errors.Is(e, enrollmentstate.ErrProof) {
			fail(w, 409, "windows_process_watch_conflict", "Selection, source or access changed. Reload to reconcile; do not automatically repeat a save.")
			return
		}
		fail(w, 503, "windows_process_watch_unavailable", "The result could not be confirmed. Reload before saving again.")
		return
	}
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	finished := source.Now().UTC()
	if finished.Before(responseNow) || !finished.Before(responseUntil) {
		fail(w, 409, "windows_process_watch_conflict", "The view expired. Reload to verify.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

// The reviewed complete source is explicitly null only for disable. All other
// fields are required, non-null and typed; duplicate/unknown fields are rejected.
func readWindowsProcessWatchRequest(w http.ResponseWriter, r *http.Request, out *watch.Request) bool {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, watch.MaxBytes))
	invalid := func() bool {
		fail(w, 400, "invalid_json", "Exactly the expected typed fields are required.")
		return false
	}
	if e != nil || !utf8.Valid(raw) || !json.Valid(raw) {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, e := decoder.Token()
	if e != nil || token != json.Delim('{') {
		return invalid()
	}
	fields := map[string]bool{"enabled": true, "names": true, "expectedRevision": true, "consent": true, "source": true}
	seen := map[string]bool{}
	for decoder.More() {
		token, e = decoder.Token()
		key, ok := token.(string)
		if e != nil || !ok || !fields[key] || seen[key] {
			return invalid()
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || key != "source" && bytes.Equal(value, []byte("null")) {
			return invalid()
		}
	}
	if _, e = decoder.Token(); e != nil || len(seen) != len(fields) {
		return invalid()
	}
	if _, e = decoder.Token(); e != io.EOF {
		return invalid()
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if typed.Decode(out) != nil {
		return invalid()
	}
	return operatorStillActive(w, r)
}
