package api

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowseventwatch"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Only existing manager reads and an exact accepted-frame authority lease are
// used. The historically named notification lease performs no notification or
// external transmission; no content/history/capture API is admitted here.
type windowsEventWatchSource interface {
	Now() time.Time
	WindowsContactInputs(context.Context, time.Time) ([]windowscontact.Input, error)
	WindowsInventoryView(context.Context, string, time.Time) (enrollmentstore.WindowsInventoryView, error)
	WithWindowsNotificationAuthority(context.Context, windowscontact.Input, func(func(time.Time) error) error) error
}
type windowsEventWatchMonitor struct {
	mu     sync.Mutex
	store  *store.Store
	source windowsEventWatchSource
	next   int // Fair continuation after an earlier device consumes the pass deadline.
}

func (m *windowsEventWatchMonitor) withInput(ctx context.Context, id string, fn func(windowseventwatch.Input, func(time.Time) error) error) error {
	started := m.source.Now().UTC()
	inputs, e := m.source.WindowsContactInputs(ctx, started)
	if e != nil {
		return e
	}
	byID, e := windowsContactAuthority(inputs, started)
	if e != nil {
		return e
	}
	source, ok := byID[id]
	if !ok || !source.Authorized {
		return enrollmentstate.ErrNotFound
	}
	view, e := m.source.WindowsInventoryView(ctx, id, m.source.Now().UTC())
	if e != nil {
		return e
	}
	if view.DeviceID != id || view.Status == "revoked" || view.Sequence == nil && source.Sequence != 0 || view.Sequence != nil && (*view.Sequence != source.Sequence || view.ReceivedAt == nil || !view.ReceivedAt.Equal(source.ReceivedAt)) {
		return ErrEventWatchSource
	}
	in := windowseventwatch.Input{Source: source, Events: view.Events}
	if in.Events != nil && (view.Snapshot == nil || in.Events.GenerationID != view.Snapshot.GenerationID || !in.Events.CollectedAt.Equal(view.Snapshot.CollectedAt)) {
		return ErrEventWatchSource
	}
	return m.source.WithWindowsNotificationAuthority(ctx, source, func(sourceGuard func(time.Time) error) error {
		guard := func(at time.Time) error {
			if at.Before(started) || at.Sub(started) > 5*time.Second || in.Events != nil && !at.Before(in.Events.CollectedAt.Add(24*time.Hour)) {
				return ErrEventWatchSource
			}
			return sourceGuard(at)
		}
		if e := guard(m.source.Now().UTC()); e != nil {
			return e
		}
		return fn(in, guard)
	})
}

var ErrEventWatchSource = errors.New("windows_event_watch_source_changed")

func (m *windowsEventWatchMonitor) evaluate(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	records, e := m.store.WindowsEventWatchRecords(ctx)
	if e != nil {
		return e
	}
	var failures []error
	for _, record := range records {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e = m.store.PruneWindowsEventWatch(ctx, record.DeviceID, m.source.Now); e != nil {
			return e
		}
	}
	enabled := make([]store.WindowsEventWatchRecord, 0, len(records))
	for _, record := range records {
		if record.State.Policy.Enabled {
			enabled = append(enabled, record)
		}
	}
	if len(enabled) == 0 {
		m.next = 0
		return nil
	}
	start := m.next % len(enabled)
	for n := 0; n < len(enabled); n++ {
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
		index := (start + n) % len(enabled)
		record := enabled[index]
		// Advance before the bounded read so an expired pass resumes after the
		// slow device on the next tick, rather than starving later devices.
		m.next = (index + 1) % len(enabled)
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = m.withInput(step, record.DeviceID, func(in windowseventwatch.Input, guard func(time.Time) error) error {
			_, e := m.store.UpdateWindowsEventWatch(step, in, nil, true, m.source.Now, guard)
			return e
		})
		cancel()
		if e != nil {
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}

type windowsEventWatchSourceView struct {
	Token       string                       `json:"token"`
	Available   bool                         `json:"available"`
	CollectedAt *time.Time                   `json:"collectedAt"`
	ReceivedAt  *time.Time                   `json:"receivedAt"`
	Reason      string                       `json:"reason"`
	Choices     []windowseventwatch.Selector `json:"choices"`
}
type windowsEventWatchPolicyView struct {
	Enabled               bool                         `json:"enabled"`
	Selectors             []windowseventwatch.Selector `json:"selectors"`
	EnabledAt             *time.Time                   `json:"enabledAt"`
	RetentionAcknowledged bool                         `json:"retentionAcknowledged"`
}
type windowsEventWatchesView struct {
	SchemaVersion string                          `json:"schemaVersion"`
	DeviceID      string                          `json:"deviceId"`
	ServerNow     time.Time                       `json:"serverNow"`
	ValidUntil    time.Time                       `json:"validUntil"`
	Revision      uint64                          `json:"revision"`
	CanManage     bool                            `json:"canManage"`
	Source        windowsEventWatchSourceView     `json:"source"`
	Policy        windowsEventWatchPolicyView     `json:"policy"`
	Status        string                          `json:"status"`
	Incidents     []windowseventwatch.Incident    `json:"incidents"`
	RetentionDays int                             `json:"retentionDays"`
	MaxSelectors  int                             `json:"maxSelectors"`
	MaxIncidents  int                             `json:"maxIncidents"`
	LastRequest   *store.WindowsEventWatchRequest `json:"lastRequest"`
}

func eventWatchView(record store.WindowsEventWatchRecord, in windowseventwatch.Input, now time.Time, can bool) (windowsEventWatchesView, error) {
	// A read started before raw-view expiry must not extend that grant-backed
	// visibility through a delayed response or the next browser lease.
	if in.Events != nil && (now.Before(in.Events.CollectedAt) || now.Sub(in.Events.CollectedAt) >= 24*time.Hour) {
		in.Events = nil
	}
	if !in.Source.Authorized || !now.Before(in.Source.AuthorityUntil) {
		return windowsEventWatchesView{}, ErrEventWatchSource
	}
	pub := record.State.Public(in, now)
	v := windowsEventWatchesView{SchemaVersion: "tracebolt.windows-event-watches.v1", DeviceID: record.DeviceID, ServerNow: now, ValidUntil: now.Add(30 * time.Second), Revision: record.Revision, CanManage: can, Status: pub.Status, Incidents: pub.Incidents, RetentionDays: 7, MaxSelectors: windowseventwatch.MaxSelectors, MaxIncidents: windowseventwatch.MaxIncidents, LastRequest: record.LastRequest}
	v.Source = windowsEventWatchSourceView{Token: windowseventwatch.SourceToken(in), Reason: "unavailable", Choices: []windowseventwatch.Selector{}}
	v.Policy = windowsEventWatchPolicyView{Enabled: pub.Policy.Enabled, Selectors: pub.Policy.Selectors, RetentionAcknowledged: pub.Policy.RetentionAcknowledged}
	if !pub.Policy.EnabledAt.IsZero() {
		at := pub.Policy.EnabledAt
		v.Policy.EnabledAt = &at
	}
	if in.Source.AuthorityUntil.Before(v.ValidUntil) {
		v.ValidUntil = in.Source.AuthorityUntil
	}
	// A replaced original identity or local grant cannot acquire old private
	// settings/history, nor replace an old ledger through the policy API.
	if record.State.DeviceID != "" && !record.State.SourceMatches(in) {
		v.CanManage = false
		v.LastRequest = nil
		v.Policy = windowsEventWatchPolicyView{Selectors: []windowseventwatch.Selector{}}
		v.Incidents = []windowseventwatch.Incident{}
		v.Status = "unknown"
	}
	if windowseventwatch.Fresh(in, now) {
		v.Source.Available = true
		v.Source.Reason = "none"
		captured, received := in.Events.CollectedAt, in.Source.ReceivedAt
		v.Source.CollectedAt = &captured
		v.Source.ReceivedAt = &received
		for _, end := range []time.Time{captured.Add(windowseventwatch.MaxAge), received.Add(windowseventwatch.MaxAge)} {
			if end.Before(v.ValidUntil) {
				v.ValidUntil = end
			}
		}
		seen := map[windowseventwatch.Selector]bool{}
		for _, channel := range in.Events.Channels {
			for _, row := range channel.Rows {
				sel := windowseventwatch.Selector{Channel: channel.Channel, Provider: row.Provider, EventID: row.EventID, Level: row.Level}
				if !seen[sel] {
					seen[sel] = true
					v.Source.Choices = append(v.Source.Choices, sel)
				}
			}
		}
	} else if in.Events != nil {
		v.Source.Reason = "stale"
		if expiry := in.Events.CollectedAt.Add(24 * time.Hour); expiry.Before(v.ValidUntil) {
			v.ValidUntil = expiry
		}
	}
	for _, incident := range v.Incidents {
		if expiry := incident.LastReceivedAt.Add(windowseventwatch.Retention); expiry.Before(v.ValidUntil) {
			v.ValidUntil = expiry
		}
	}
	if v.Status != "disabled" && v.Status != "unknown" && record.State.EvaluatedAt != nil {
		if expiry := record.State.EvaluatedAt.Add(windowseventwatch.MaxAge); expiry.Before(v.ValidUntil) {
			v.ValidUntil = expiry
		}
	}
	if !now.Before(v.ValidUntil) {
		return v, ErrEventWatchSource
	}
	return v, nil
}
func (h *operatorHandler) windowsEventWatchesAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || parts[4] != "windows-event-watches" || !enrollmentcrypto.ValidID(parts[3], "agent_") {
		fail(w, 404, "not_found", "Event watches are unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
		if action != "policy" && action != "review" {
			fail(w, 404, "not_found", "Event watch action unavailable.")
			return
		}
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_request", "Event watches do not accept query parameters.")
		return
	}
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "Authenticated operator required.")
		return
	}
	m := h.app.windowsEventWatches
	if m == nil {
		fail(w, 409, "event_watches_unavailable", "Existing Windows periodic-header observations are required.")
		return
	}
	can := !op.session.Named()
	var command *store.WindowsEventWatchCommand
	if action != "" {
		if !can {
			fail(w, 403, "operator_capability_required", "Shared administration is required.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		var valid bool
		command, valid = readEventWatchCommand(w, r, action)
		if !valid {
			return
		}
		release, valid := beginOperatorMutation(w, r)
		if !valid {
			return
		}
		defer release()
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		fail(w, 400, "invalid_request", "Event watch reads do not accept a body.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(7*time.Second)) != nil {
		fail(w, 503, "event_watches_unavailable", "Event watches unavailable.")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var v windowsEventWatchesView
	var raw []byte
	e := m.withInput(ctx, parts[3], func(in windowseventwatch.Input, sourceGuard func(time.Time) error) error {
		guard := func(at time.Time) error {
			if ctx.Err() != nil || op.active == nil || !op.active() {
				return store.ErrWindowsEventWatchSession
			}
			return sourceGuard(at)
		}
		record, e := m.store.UpdateWindowsEventWatch(ctx, in, command, false, m.source.Now, guard)
		if e != nil {
			return e
		}
		now := m.source.Now().UTC()
		v, e = eventWatchView(record, in, now, can)
		if e != nil {
			return e
		}
		raw, e = json.Marshal(v)
		if e != nil || len(raw) > windowseventwatch.MaxStateBytes {
			return store.ErrWindowsEventWatchUnavailable
		}
		return guard(now)
	})
	if e != nil {
		eventWatchError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	now := m.source.Now().UTC()
	if now.Before(v.ServerNow) || !now.Before(v.ValidUntil) {
		eventWatchError(w, ErrEventWatchSource)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func readEventWatchCommand(w http.ResponseWriter, r *http.Request, action string) (*store.WindowsEventWatchCommand, bool) {
	var body struct {
		RequestID             string                       `json:"requestId"`
		ExpectedRevision      uint64                       `json:"expectedRevision"`
		SourceToken           string                       `json:"sourceToken"`
		Enabled               bool                         `json:"enabled"`
		Selectors             []windowseventwatch.Selector `json:"selectors"`
		RetentionAcknowledged bool                         `json:"retentionAcknowledged"`
		IncidentID            string                       `json:"incidentId"`
	}
	fields := []string{"requestId", "expectedRevision", "sourceToken"}
	if action == "policy" {
		fields = append(fields, "enabled", "selectors", "retentionAcknowledged")
	} else {
		fields = append(fields, "incidentId")
	}
	if !readObject(w, r, 8192, fields, &body) {
		return nil, false
	}
	if !enrollmentcrypto.ValidID(body.RequestID, "eventrequest_") || !enrollmentcrypto.ValidID(body.SourceToken, "eventsource_") || body.ExpectedRevision > windowseventwatch.MaxCounter {
		fail(w, 400, "invalid_event_watch", "Use the exact reviewed event watch command.")
		return nil, false
	}
	return &store.WindowsEventWatchCommand{RequestID: body.RequestID, ExpectedRevision: body.ExpectedRevision, SourceToken: body.SourceToken, Operation: action, Enabled: body.Enabled, Selectors: body.Selectors, RetentionAcknowledged: body.RetentionAcknowledged, IncidentID: body.IncidentID}, true
}
func eventWatchError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrWindowsEventWatchSession):
		fail(w, 401, "authentication_required", "Operator session ended.")
	case errors.Is(e, enrollmentstate.ErrNotFound), errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentstate.ErrExpired):
		fail(w, 404, "not_found", "Event watches unavailable for this identity.")
	case errors.Is(e, windowseventwatch.ErrInvalid):
		fail(w, 400, "invalid_event_watch", "Invalid event watch command.")
	case errors.Is(e, store.ErrWindowsEventWatchConflict), errors.Is(e, ErrEventWatchSource):
		fail(w, 409, "event_watches_changed", "State or source changed. Refresh before another review.")
	case errors.Is(e, enrollmentstore.ErrBusy), errors.Is(e, enrollmentstore.ErrOperationalBusy):
		fail(w, 429, "event_watches_busy", "Stored observations are busy. Refresh before another review.")
	default:
		fail(w, 503, "event_watches_unavailable", "Event watches unavailable; any write may be uncertain. Read saved state without replaying it.")
	}
}
