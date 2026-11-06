package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowscontact"
)

type windowsContactPolicyAuthoritySource interface {
	WithWindowsMonitoringAuthority(context.Context, []windowscontact.Input, func(func(time.Time) error) error) error
}

func (h *operatorHandler) configureWindowsContactPolicy(r *http.Request, in windowscontact.Input, request windowscontact.PolicyRequest, started time.Time) (windowscontact.State, error) {
	m := h.app.windowsContact
	lease, ok := m.source.(windowsContactPolicyAuthoritySource)
	if !ok {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	var state windowscontact.State
	err := lease.WithWindowsMonitoringAuthority(r.Context(), []windowscontact.Input{in}, func(authority func(time.Time) error) error {
		guard := func(minimum time.Time) error {
			op, ok := operatorContext(r)
			at := m.source.Now().UTC()
			if !ok || op.active == nil || !op.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(minimum) || !at.Before(in.AuthorityUntil) {
				return windowscontact.ErrInvalid
			}
			if err := authority(at); err != nil {
				return err
			}
			end := m.source.Now().UTC()
			if !op.active() || r.Context().Err() != nil || end.Before(at) || !contactReadTime(started, end) || !end.Before(in.AuthorityUntil) {
				return windowscontact.ErrInvalid
			}
			return nil
		}
		var err error
		state, err = m.store.ConfigureWindowsContact(r.Context(), in, request, m.epoch, m.source.Now, guard)
		return err
	})
	return state, err
}

func readWindowsContactPolicyRequest(w http.ResponseWriter, r *http.Request, out *windowscontact.PolicyRequest) bool {
	bad := func() bool {
		fail(w, 400, "invalid_contact_policy", "Review one supported grace period and explicitly confirm it.")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || !utf8.Valid(raw) || !json.Valid(raw) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	fields := map[string]bool{"expectedRevision": true, "requestId": true, "graceSeconds": true, "acknowledged": true}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !fields[key] || seen[key] {
			return bad()
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return bad()
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != len(fields) {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || !out.Acknowledged || out.ExpectedRevision >= windowscontact.MaxCounter || !windowscontact.ValidEpoch(out.RequestID) || out.GraceSeconds != 120 && out.GraceSeconds != 300 && out.GraceSeconds != 900 && out.GraceSeconds != 3600 {
		return bad()
	}
	return operatorStillActive(w, r)
}
