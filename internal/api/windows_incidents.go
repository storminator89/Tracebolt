package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
)

type windowsIncidentAuthoritySource interface {
	WithWindowsIncidentAuthority(context.Context, windowscontact.Input, func(func(time.Time) error) error) error
}

type windowsInboxQuery struct {
	Scope  string `json:"scope"`
	Ack    string `json:"ack"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}
type windowsInboxItem struct {
	Key                 string     `json:"key"`
	DeviceID            string     `json:"deviceId"`
	Domain              string     `json:"domain"`
	IncidentID          string     `json:"incidentId"`
	ServiceName         string     `json:"serviceName"`
	OpenedAt            time.Time  `json:"openedAt"`
	LastConfirmedAt     time.Time  `json:"lastConfirmedAt"`
	CollectedAt         *time.Time `json:"collectedAt"`
	ReceivedAt          time.Time  `json:"receivedAt"`
	ResolvedAt          *time.Time `json:"resolvedAt"`
	RecoveryCollectedAt *time.Time `json:"recoveryCollectedAt"`
	RecoveryReceivedAt  *time.Time `json:"recoveryReceivedAt"`
	ClosedReason        string     `json:"closedReason"`
	Status              string     `json:"status"`
	StatusValidUntil    *time.Time `json:"statusValidUntil"`
	EvaluatedAt         *time.Time `json:"evaluatedAt"`
	AcknowledgedAt      *time.Time `json:"acknowledgedAt"`
}
type windowsInboxCounts struct {
	Active         int `json:"active"`
	Resolved       int `json:"resolved"`
	Acknowledged   int `json:"acknowledged"`
	Unacknowledged int `json:"unacknowledged"`
	Total          int `json:"total"`
}
type windowsInboxCoverage struct {
	Devices            int `json:"devices"`
	UnavailableDevices int `json:"unavailableDevices"`
	UnknownChecks      int `json:"unknownChecks"`
	DisabledChecks     int `json:"disabledChecks"`
}
type windowsInboxView struct {
	SchemaVersion      string    `json:"schemaVersion"`
	ServerNow          time.Time `json:"serverNow"`
	AuthorityExpiresAt time.Time `json:"authorityExpiresAt"`
	windowsInboxQuery
	Total      int                  `json:"total"`
	NextOffset *int                 `json:"nextOffset"`
	Counts     windowsInboxCounts   `json:"counts"`
	Coverage   windowsInboxCoverage `json:"coverage"`
	Items      []windowsInboxItem   `json:"items"`
}

func parseWindowsInboxQuery(u *url.URL) (windowsInboxQuery, bool) {
	q := windowsInboxQuery{Scope: "active", Ack: "all", Limit: 25}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil || u.ForceQuery {
		return q, false
	}
	for k, v := range values {
		if len(v) != 1 {
			return q, false
		}
		switch k {
		case "scope":
			q.Scope = v[0]
		case "ack":
			q.Ack = v[0]
		case "offset", "limit":
			n, e := strconv.Atoi(v[0])
			if e != nil || strconv.Itoa(n) != v[0] {
				return q, false
			}
			if k == "offset" {
				q.Offset = n
			} else {
				q.Limit = n
			}
		default:
			return q, false
		}
	}
	return q, (q.Scope == "active" || q.Scope == "recent" || q.Scope == "resolved" || q.Scope == "all") && (q.Ack == "all" || q.Ack == "acknowledged" || q.Ack == "unacknowledged") && q.Offset >= 0 && q.Offset <= store.MaxWindowsInboxIncidents && q.Limit >= 1 && q.Limit <= 50
}
func windowsInboxQueryAllowed(u *url.URL) bool {
	if u.Path != "/api/fleet/windows-incidents" {
		return false
	}
	_, ok := parseWindowsInboxQuery(u)
	return ok
}

// A historical incident sample is not current evidence. Bind this deadline to
// the qualified v1 view's current evaluator and source, never to HTTP receipt.
func windowsInboxStatusUntil(status string, evaluated, captured, received *time.Time, expires time.Time) *time.Time {
	if status == "unknown" || status == "disabled" || evaluated == nil {
		return nil
	}
	until := expires
	for _, at := range []*time.Time{evaluated, captured, received} {
		if at != nil {
			end := at.Add(120 * time.Second)
			if end.Before(until) {
				until = end
			}
		}
	}
	return inboxStamp(until)
}
func windowsInboxIdentity(in windowscapacity.Input, id, invitation, certificate string) bool {
	return in.Authorized && in.DeviceID == id && in.InvitationID == invitation && in.CertificateHash == certificate
}
func windowsInboxTarget(in windowscapacity.Input, domain, incident string, opened time.Time) store.WindowsIncidentTarget {
	return store.WindowsIncidentTarget{DeviceID: in.DeviceID, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, Domain: domain, IncidentID: incident, OpenedAt: opened}
}
func inboxStamp(t time.Time) *time.Time { v := t; return &v }

// projectWindowsInbox never evaluates evidence or edits a source ledger. Current
// confidence comes from its original, independently qualified v1 view only.
func projectWindowsInbox(snapshot store.WindowsIncidentSnapshot, authority map[string]windowscapacity.Input, now time.Time, contactEpoch, capacityEpoch string, q windowsInboxQuery) (windowsInboxView, error) {
	view := windowsInboxView{SchemaVersion: "tracebolt.windows-incident-inbox.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), windowsInboxQuery: q, Items: []windowsInboxItem{}}
	all := []windowsInboxItem{}
	unavailable := map[string]bool{}
	countStatus := func(status string) {
		if status == "unknown" {
			view.Coverage.UnknownChecks++
		}
		if status == "disabled" {
			view.Coverage.DisabledChecks++
		}
	}
	add := func(in windowscapacity.Input, item windowsInboxItem) error {
		if item.OpenedAt.After(now) || item.LastConfirmedAt.After(now) || item.ResolvedAt != nil && item.ResolvedAt.After(now) {
			return store.ErrWindowsIncident
		}
		item.Key = windowsInboxTarget(in, item.Domain, item.IncidentID, item.OpenedAt).Key()
		item.DeviceID = in.DeviceID
		if ack, ok := snapshot.Acknowledgements[item.Key]; ok {
			if ack.AcknowledgedAt.After(now) {
				return store.ErrWindowsIncident
			}
			item.AcknowledgedAt = inboxStamp(ack.AcknowledgedAt)
		}
		all = append(all, item)
		return nil
	}
	// Retained but unavailable identities are counted without exposing their rows.
	for _, target := range snapshot.Targets() {
		in, ok := authority[target.DeviceID]
		if !ok || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) {
			unavailable[target.DeviceID] = true
		}
	}
	for id, in := range authority {
		if !in.Authorized {
			unavailable[id] = true
			continue
		}
		view.Coverage.Devices++
		if in.AuthorityUntil.Before(view.AuthorityExpiresAt) {
			view.AuthorityExpiresAt = in.AuthorityUntil
		}
		cs, ok := snapshot.Contacts[id]
		if !ok {
			cs = windowscontact.New()
		}
		if cs.DeviceID != "" && !windowsInboxIdentity(in, id, cs.InvitationID, cs.CertificateHash) {
			unavailable[id] = true
			countStatus("unknown")
		} else {
			cv := cs.View(in.Input, now, contactEpoch)
			var recentReceipt *time.Time
			if cv.Status == "recent" {
				recentReceipt = cv.LastAcceptedAt
			}
			validUntil := windowsInboxStatusUntil(cv.Status, cv.EvaluatedAt, nil, recentReceipt, in.AuthorityUntil)
			countStatus(cv.Status)
			for _, i := range cv.Incidents {
				if err := add(in, windowsInboxItem{Domain: "contact", IncidentID: i.ID, OpenedAt: i.OpenedAt, LastConfirmedAt: i.LastConfirmedAt, ReceivedAt: i.LastAcceptedAt, ResolvedAt: i.ResolvedAt, RecoveryReceivedAt: i.RecoveryAcceptedAt, ClosedReason: i.ClosedReason, Status: cv.Status, StatusValidUntil: validUntil, EvaluatedAt: cv.EvaluatedAt}); err != nil {
					return view, err
				}
			}
		}
		for _, domain := range []string{"disk", "cpu", "memory"} {
			s := windowscapacity.New()
			if domain == "disk" {
				if st, ok := snapshot.Capacities[id]; ok {
					s = st
				}
			} else {
				for _, r := range snapshot.Resources {
					if r.Assessment.DeviceID == id && string(r.Metric) == domain {
						s = r.Assessment
						break
					}
				}
			}
			if s.DeviceID != "" && !windowsInboxIdentity(in, id, s.InvitationID, s.CertificateHash) {
				unavailable[id] = true
				countStatus("unknown")
				continue
			}
			selected := in
			if domain != "disk" {
				selected, _ = windowsresource.Select(in, windowsresource.Kind(domain))
			}
			pv := s.View(selected, now, capacityEpoch)
			countStatus(pv.Status)
			var captured, received *time.Time
			if pv.Observation != nil {
				captured = inboxStamp(pv.Observation.CollectedAt)
				received = inboxStamp(pv.Observation.ReceivedAt)
			}
			validUntil := windowsInboxStatusUntil(pv.Status, pv.EvaluatedAt, captured, received, in.AuthorityUntil)
			for _, i := range pv.Incidents {
				item := windowsInboxItem{Domain: domain, IncidentID: i.ID, OpenedAt: i.OpenedAt, LastConfirmedAt: i.LastConfirmedAt, CollectedAt: inboxStamp(i.LastHighObservation.CollectedAt), ReceivedAt: i.LastHighObservation.ReceivedAt, ResolvedAt: i.ResolvedAt, ClosedReason: i.ClosedReason, Status: pv.Status, StatusValidUntil: validUntil, EvaluatedAt: pv.EvaluatedAt}
				if i.RecoveryObservation != nil {
					item.RecoveryCollectedAt = inboxStamp(i.RecoveryObservation.CollectedAt)
					item.RecoveryReceivedAt = inboxStamp(i.RecoveryObservation.ReceivedAt)
				}
				if err := add(in, item); err != nil {
					return view, err
				}
			}
		}
		ss, ok := snapshot.Services[id]
		if !ok {
			ss = windowsservicehealth.New()
		}
		if ss.DeviceID != "" && !windowsInboxIdentity(in, id, ss.InvitationID, ss.CertificateHash) {
			unavailable[id] = true
			countStatus("unknown")
			continue
		}
		// Complete-source history has an explicit v2 Health contract. Do not
		// project it into preview-v1 notification/review authority or names.
		if ss.SchemaVersion == windowsservicehealth.CompleteStateSchema {
			continue
		}
		sv := ss.View(windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, now, capacityEpoch)
		if !sv.Policy.Enabled {
			countStatus("disabled")
		} else {
			for _, c := range sv.Checks {
				countStatus(c.Status)
			}
		}
		for _, i := range sv.Incidents {
			status := "unknown"
			var captured, received *time.Time
			if !sv.Policy.Enabled {
				status = "disabled"
			} else {
				for _, c := range sv.Checks {
					if c.Name == i.Name {
						status = c.Status
						if c.Observation != nil {
							captured = inboxStamp(c.Observation.CollectedAt)
							received = inboxStamp(c.Observation.ReceivedAt)
						}
						break
					}
				}
			}
			item := windowsInboxItem{Domain: "service", IncidentID: i.ID, ServiceName: i.Name, OpenedAt: i.OpenedAt, LastConfirmedAt: i.LastConfirmedAt, CollectedAt: inboxStamp(i.LastBadObservation.CollectedAt), ReceivedAt: i.LastBadObservation.ReceivedAt, ResolvedAt: i.ResolvedAt, ClosedReason: i.ClosedReason, Status: status, StatusValidUntil: windowsInboxStatusUntil(status, sv.EvaluatedAt, captured, received, in.AuthorityUntil), EvaluatedAt: sv.EvaluatedAt}
			if i.RecoveryObservation != nil {
				item.RecoveryCollectedAt = inboxStamp(i.RecoveryObservation.CollectedAt)
				item.RecoveryReceivedAt = inboxStamp(i.RecoveryObservation.ReceivedAt)
			}
			if err := add(in, item); err != nil {
				return view, err
			}
		}
	}
	view.Coverage.UnavailableDevices = len(unavailable)
	if len(all) > store.MaxWindowsInboxIncidents {
		return view, store.ErrWindowsIncident
	}
	for i := range all {
		until := all[i].StatusValidUntil
		if until != nil && until.After(view.AuthorityExpiresAt) {
			all[i].StatusValidUntil = inboxStamp(view.AuthorityExpiresAt)
			until = all[i].StatusValidUntil
		}
		if until != nil && !now.Before(*until) {
			all[i].Status = "unknown"
			all[i].StatusValidUntil = nil
		}
	}
	filtered := []windowsInboxItem{}
	recent := now.Add(-7 * 24 * time.Hour)
	for _, item := range all {
		view.Counts.Total++
		if item.ResolvedAt == nil {
			view.Counts.Active++
		} else {
			view.Counts.Resolved++
		}
		if item.AcknowledgedAt == nil {
			view.Counts.Unacknowledged++
		} else {
			view.Counts.Acknowledged++
		}
		if q.Scope == "active" && item.ResolvedAt != nil || q.Scope == "resolved" && item.ResolvedAt == nil || q.Scope == "recent" && item.OpenedAt.Before(recent) && (item.ResolvedAt == nil || item.ResolvedAt.Before(recent)) || q.Ack == "acknowledged" && item.AcknowledgedAt == nil || q.Ack == "unacknowledged" && item.AcknowledgedAt != nil {
			continue
		}
		filtered = append(filtered, item)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].OpenedAt.Equal(filtered[j].OpenedAt) {
			return filtered[i].Key < filtered[j].Key
		}
		return filtered[i].OpenedAt.After(filtered[j].OpenedAt)
	})
	view.Total = len(filtered)
	start := min(q.Offset, len(filtered))
	end := min(start+q.Limit, len(filtered))
	view.Items = append(view.Items, filtered[start:end]...)
	if end < len(filtered) {
		view.NextOffset = &end
	}
	return view, nil
}

// The fleet route is distinct from Linux investigations and every v1 per-device
// view. Only a shared administrator can deliberately mark an exact episode seen.
func (h *operatorHandler) windowsIncidentsAPI(w http.ResponseWriter, r *http.Request) {
	if _, ok := windowsServiceIncidentReviewKey(r); ok {
		h.windowsServiceIncidentReview(w, r)
		return
	}

	mutation := r.URL.Path == "/api/fleet/windows-incidents/acknowledge"
	if r.URL.Path != "/api/fleet/windows-incidents" && !mutation {
		fail(w, 404, "not_found", "Windows incidents are unavailable.")
		return
	}
	if !mutation && r.Method != "GET" || mutation && r.Method != "POST" {
		if mutation {
			w.Header().Set("Allow", "POST")
		} else {
			w.Header().Set("Allow", "GET")
		}
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	query, valid := parseWindowsInboxQuery(r.URL)
	if !valid || mutation && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		fail(w, 400, "invalid_windows_inbox_query", "Choose bounded incident filters and paging.")
		return
	}
	m := h.app.windowsCapacity
	c := h.app.windowsContact
	if m == nil {
		fail(w, 404, "not_found", "Windows incidents are not configured.")
		return
	}
	// Bound a cross-store authority lease even if operator SQLite is busy.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var intent struct {
		Key string `json:"key"`
	}
	if mutation {
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to acknowledge an incident.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readObject(w, r, 128, []string{"key"}, &intent) {
			return
		}
		if !enrollmentcrypto.ValidHash(intent.Key) {
			fail(w, 400, "invalid_windows_incident", "Choose the exact retained incident.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	// Match scheduler lock order; never take enrollment while holding SQLite.
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	inputs, err := m.source.WindowsCapacityInputs(r.Context(), started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, started)
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Windows incident authority is unavailable.")
		return
	}
	snapshot, err := m.store.WindowsIncidentSnapshot(r.Context())
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) {
			fail(w, 409, "windows_inbox_conflict", "The time reference changed. Refresh this inbox.")
			return false
		}
		current, e := m.source.WindowsCapacityInputs(r.Context(), at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(current, at)
		if e != nil || len(latest) != len(authority) {
			fail(w, 409, "windows_inbox_conflict", "Windows device authority changed. Refresh this inbox.")
			return false
		}
		for id, in := range authority {
			v, ok := latest[id]
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
				fail(w, 409, "windows_inbox_conflict", "Windows device authority changed. Refresh this inbox.")
				return false
			}
		}
		end := m.source.Now().UTC()
		if !contactReadTime(started, end) || end.Before(at) {
			fail(w, 409, "windows_inbox_conflict", "The time reference changed. Refresh this inbox.")
			return false
		}
		for _, in := range latest {
			if in.Authorized && !end.Before(in.AuthorityUntil) {
				fail(w, 409, "windows_inbox_conflict", "Windows device authority expired. Refresh this inbox.")
				return false
			}
		}
		authority = latest
		return operatorStillActive(w, r)
	}
	if mutation {
		target, ok := snapshot.Targets()[intent.Key]
		in, admitted := authority[target.DeviceID]
		if !ok || !admitted || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) {
			fail(w, 409, "windows_inbox_conflict", "The exact incident is no longer available. Refresh this inbox.")
			return
		}
		if !recheck() {
			return
		}
		lease, ok := m.source.(windowsIncidentAuthoritySource)
		if !ok {
			fail(w, 503, "windows_inbox_unavailable", "Current incident authority cannot be locked. Refresh before acknowledging.")
			return
		}
		var ack store.WindowsIncidentAcknowledgement
		e := lease.WithWindowsIncidentAuthority(r.Context(), in.Input, func(authorityGuard func(time.Time) error) error {
			var saveErr error
			ack, saveErr = m.store.AcknowledgeWindowsIncident(r.Context(), target, m.source.Now, func(sampled time.Time) error {
				at := m.source.Now().UTC()
				operator, ok := operatorContext(r)
				if !ok || operator.active == nil || !operator.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(sampled) || !at.Before(in.AuthorityUntil) {
					return store.ErrWindowsIncident
				}
				if err := authorityGuard(at); err != nil {
					return store.ErrWindowsIncident
				}
				return nil
			})
			return saveErr
		})
		if errors.Is(e, store.ErrWindowsIncident) {
			fail(w, 409, "windows_inbox_conflict", "Acknowledgement changed or expired. Refresh before trying again.")
			return
		}
		if e != nil {
			fail(w, 503, "windows_inbox_unavailable", "Acknowledgement could not be confirmed. Refresh before trying again.")
			return
		}
		if !recheck() {
			return
		}
		now := m.source.Now().UTC()
		h.writeWindowsInbox(w, r, started, now, in.AuthorityUntil, 1024, struct {
			SchemaVersion  string    `json:"schemaVersion"`
			ServerNow      time.Time `json:"serverNow"`
			Key            string    `json:"key"`
			AcknowledgedAt time.Time `json:"acknowledgedAt"`
		}{"tracebolt.windows-incident-ack.v1", now, intent.Key, ack.AcknowledgedAt})
		return
	}
	if !recheck() {
		return
	}
	contactEpoch := ""
	if c != nil && c.ready {
		contactEpoch = c.epoch
	}
	capacityEpoch := ""
	if m.ready {
		capacityEpoch = m.epoch
	}
	now := m.source.Now().UTC()
	view, err := projectWindowsInbox(snapshot, authority, now, contactEpoch, capacityEpoch, query)
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	h.writeWindowsInbox(w, r, started, now, view.AuthorityExpiresAt, 262144, view)
}
func (h *operatorHandler) writeWindowsInbox(w http.ResponseWriter, r *http.Request, started, now, expires time.Time, limit int, value any) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > limit {
		fail(w, 503, "windows_inbox_unavailable", "Windows incidents are unavailable.")
		return
	}
	defer clear(raw)
	end := h.app.windowsCapacity.source.Now().UTC()
	if !contactReadTime(started, end) || end.Before(now) || !end.Before(expires) {
		fail(w, 409, "windows_inbox_conflict", "Windows device authority or time reference changed. Refresh this inbox.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
