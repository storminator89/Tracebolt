package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
)

// V2 is a combined bounded inbox, not a second service ledger. Legacy rows keep
// their exact v1 target and acknowledgement. Complete rows carry explicit source
// provenance and never enter the v1 service-control/notification projection.
type windowsCompleteInboxItem struct {
	windowsInboxItem
	SourceKind     string                           `json:"sourceKind"`
	OpeningSource  *windowsservicehealth.Provenance `json:"openingSource"`
	LastBadSource  *windowsservicehealth.Provenance `json:"lastBadSource"`
	RecoverySource *windowsservicehealth.Provenance `json:"recoverySource"`
	CurrentSource  *windowsservicehealth.Provenance `json:"currentSource"`
}
type windowsCompleteInboxView struct {
	SchemaVersion      string    `json:"schemaVersion"`
	ServerNow          time.Time `json:"serverNow"`
	AuthorityExpiresAt time.Time `json:"authorityExpiresAt"`
	windowsInboxQuery
	Total      int                        `json:"total"`
	NextOffset *int                       `json:"nextOffset"`
	Counts     windowsInboxCounts         `json:"counts"`
	Coverage   windowsInboxCoverage       `json:"coverage"`
	Items      []windowsCompleteInboxItem `json:"items"`
}
type windowsCompleteIncidentAuthoritySource interface {
	WithWindowsCompleteIncidentAuthority(context.Context, windowsservicehealth.Input, func(func(time.Time) error) error) error
}

func windowsCompleteInboxQueryAllowed(u *url.URL) bool {
	if u.Path != "/api/fleet/windows-incidents/complete" {
		return false
	}
	_, ok := parseWindowsInboxQuery(u)
	return ok
}
func completeInboxCurrentSource(in windowscapacity.Input, now time.Time) *windowsservicehealth.Provenance {
	if in.Services.Complete == nil || !in.Services.Complete.Source.Fresh(now) {
		return nil
	}
	p := in.Services.Complete.Source
	return &p
}
func completeInboxStatusUntil(status string, evaluated *time.Time, source *windowsservicehealth.Provenance, expires time.Time) *time.Time {
	if status == "unknown" || status == "disabled" || evaluated == nil || source == nil {
		return nil
	}
	until := expires
	for _, end := range []time.Time{evaluated.Add(120 * time.Second), source.CapturedAt.Add(windowsservicehealth.CompleteMaxAge), source.ReceivedAt.Add(windowsservicehealth.CompleteMaxAge), source.ExpiresAt} {
		if end.Before(until) {
			until = end
		}
	}
	return inboxStamp(until)
}
func projectWindowsCompleteInbox(snapshot store.WindowsCompleteIncidentSnapshot, authority map[string]windowscapacity.Input, now time.Time, contactEpoch, capacityEpoch string, q windowsInboxQuery) (windowsCompleteInboxView, error) {
	// Internal full projection only; public page limit remains 50 and final bytes
	// remain 256 KiB. The five-family bound is not doubled for a tagged v2 ledger.
	legacy, err := projectWindowsInbox(snapshot.WindowsIncidentSnapshot, authority, now, contactEpoch, capacityEpoch, windowsInboxQuery{Scope: "all", Ack: "all", Limit: store.MaxWindowsInboxIncidents})
	view := windowsCompleteInboxView{SchemaVersion: "tracebolt.windows-incident-inbox.v2", ServerNow: now, AuthorityExpiresAt: legacy.AuthorityExpiresAt, windowsInboxQuery: q, Coverage: legacy.Coverage, Items: []windowsCompleteInboxItem{}}
	if err != nil {
		return view, err
	}
	all := make([]windowsCompleteInboxItem, 0, len(legacy.Items))
	for _, item := range legacy.Items {
		all = append(all, windowsCompleteInboxItem{windowsInboxItem: item, SourceKind: "assessment_v1"})
	}
	// Count each unavailable retained original identity once across both versions.
	unavailable := map[string]bool{}
	for id, in := range authority {
		if !in.Authorized {
			unavailable[id] = true
		}
	}
	markUnavailable := func(id, invitation, certificate string) {
		if id != "" {
			in, ok := authority[id]
			if !ok || !windowsInboxIdentity(in, id, invitation, certificate) {
				unavailable[id] = true
			}
		}
	}
	for id, s := range snapshot.Contacts {
		markUnavailable(id, s.InvitationID, s.CertificateHash)
	}
	for id, s := range snapshot.Capacities {
		markUnavailable(id, s.InvitationID, s.CertificateHash)
	}
	for _, s := range snapshot.Resources {
		markUnavailable(s.Assessment.DeviceID, s.Assessment.InvitationID, s.Assessment.CertificateHash)
	}
	for id, s := range snapshot.Services {
		markUnavailable(id, s.InvitationID, s.CertificateHash)
	}
	view.Coverage.UnavailableDevices = len(unavailable)
	for id, state := range snapshot.Services {
		if state.SchemaVersion != windowsservicehealth.CompleteStateSchema {
			continue
		}
		in, ok := authority[id]
		if !ok || !windowsInboxIdentity(in, id, state.InvitationID, state.CertificateHash) {
			continue
		}
		sv := state.View(windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: true, CurrentLeaf: in.CurrentLeaf}, now, capacityEpoch)
		if !sv.Policy.Enabled {
			view.Coverage.DisabledChecks++
		} else {
			for _, c := range sv.Checks {
				if c.Status == "unknown" {
					view.Coverage.UnknownChecks++
				}
			}
		}
		for _, incident := range sv.Incidents {
			status := "unknown"
			var current *windowsservicehealth.Provenance
			if !sv.Policy.Enabled {
				status = "disabled"
			} else {
				for _, c := range sv.Checks {
					if c.Name == incident.Name {
						status = c.Status
						if c.Observation != nil {
							current = c.Observation.Source
						}
						break
					}
				}
			}
			if incident.OpeningObservation.Source == nil || incident.LastBadObservation.Source == nil || incident.OpenedAt.After(now) || incident.LastConfirmedAt.After(now) || incident.ResolvedAt != nil && incident.ResolvedAt.After(now) {
				return view, store.ErrWindowsIncident
			}
			target := store.WindowsCompleteIncidentTarget{WindowsIncidentTarget: windowsInboxTarget(in, "service-complete", incident.ID, incident.OpenedAt), Source: incident.OpeningObservation.Source.Binding()}
			item := windowsCompleteInboxItem{windowsInboxItem: windowsInboxItem{Key: target.Key(), DeviceID: id, Domain: "service-complete", IncidentID: incident.ID, ServiceName: incident.Name, OpenedAt: incident.OpenedAt, LastConfirmedAt: incident.LastConfirmedAt, CollectedAt: inboxStamp(incident.LastBadObservation.CollectedAt), ReceivedAt: incident.LastBadObservation.ReceivedAt, ResolvedAt: incident.ResolvedAt, ClosedReason: incident.ClosedReason, Status: status, StatusValidUntil: completeInboxStatusUntil(status, sv.EvaluatedAt, current, in.AuthorityUntil), EvaluatedAt: sv.EvaluatedAt}, SourceKind: windowsservicehealth.CompleteSourceKind, OpeningSource: incident.OpeningObservation.Source, LastBadSource: incident.LastBadObservation.Source, CurrentSource: current}
			if incident.RecoveryObservation != nil {
				item.RecoveryCollectedAt = inboxStamp(incident.RecoveryObservation.CollectedAt)
				item.RecoveryReceivedAt = inboxStamp(incident.RecoveryObservation.ReceivedAt)
				item.RecoverySource = incident.RecoveryObservation.Source
			}
			if ack, exists := snapshot.CompleteAcknowledgements[item.Key]; exists {
				if ack.AcknowledgedAt.After(now) {
					return view, store.ErrWindowsIncident
				}
				item.AcknowledgedAt = inboxStamp(ack.AcknowledgedAt)
			}
			all = append(all, item)
		}
	}
	if len(all) > store.MaxWindowsInboxIncidents {
		return view, store.ErrWindowsIncident
	}
	filtered := []windowsCompleteInboxItem{}
	recent := now.Add(-7 * 24 * time.Hour)
	for _, item := range all {
		if item.StatusValidUntil != nil && item.StatusValidUntil.After(view.AuthorityExpiresAt) {
			item.StatusValidUntil = inboxStamp(view.AuthorityExpiresAt)
		}
		if item.StatusValidUntil != nil && !now.Before(*item.StatusValidUntil) {
			item.Status = "unknown"
			item.StatusValidUntil = nil
			item.CurrentSource = nil
		}
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

func (h *operatorHandler) windowsCompleteIncidentsAPI(w http.ResponseWriter, r *http.Request) {
	if _, ok := windowsCompleteServiceIncidentReviewKey(r); ok {
		h.windowsCompleteServiceIncidentReview(w, r)
		return
	}
	mutation := r.URL.Path == "/api/fleet/windows-incidents/complete/acknowledge"
	if r.URL.Path != "/api/fleet/windows-incidents/complete" && !mutation {
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
	m, c := h.app.windowsCapacity, h.app.windowsContact
	if m == nil {
		fail(w, 404, "not_found", "Windows incidents are not configured.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var intent struct {
		Key string `json:"key"`
	}
	if mutation {
		op, ok := operatorContext(r)
		if !ok || op.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to acknowledge an incident.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) || !readObject(w, r, 128, []string{"key"}, &intent) {
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
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	snapshot, err := m.store.WindowsCompleteIncidentSnapshot(r.Context())
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	selections := map[string][]string{}
	for id, s := range snapshot.Services {
		if s.SchemaVersion == windowsservicehealth.CompleteStateSchema {
			names := []string{}
			if s.Policy.Enabled {
				names = s.Policy.Services
			}
			selections[id] = names
		}
	}
	r = r.WithContext(windowsservicehealth.WithCompleteSelections(r.Context(), selections))
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
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || v.CurrentLeaf != in.CurrentLeaf || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
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
		if !recheck() {
			return
		}
		completeTarget, complete := snapshot.CompleteTargets()[intent.Key]
		legacyTarget, legacy := snapshot.Targets()[intent.Key]
		target := legacyTarget
		if complete {
			target = completeTarget.WindowsIncidentTarget
		}
		in, admitted := authority[target.DeviceID]
		if complete == legacy || !admitted || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) {
			fail(w, 409, "windows_inbox_conflict", "The exact incident is no longer available. Refresh this inbox.")
			return
		}
		var acknowledged time.Time
		var source *windowsservicehealth.Provenance
		if complete {
			source = completeInboxCurrentSource(in, m.source.Now().UTC())
		}
		save := func(authorityGuard func(time.Time) error) error {
			guard := func(sampled time.Time) error {
				at := m.source.Now().UTC()
				op, ok := operatorContext(r)
				if !ok || op.active == nil || !op.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(sampled) || !at.Before(in.AuthorityUntil) {
					return store.ErrWindowsIncident
				}
				if e := authorityGuard(at); e != nil {
					return store.ErrWindowsIncident
				}
				end := m.source.Now().UTC()
				if !contactReadTime(started, end) || end.Before(at) || !end.Before(in.AuthorityUntil) || source != nil && !source.Fresh(end) || !op.active() {
					return store.ErrWindowsIncident
				}
				return nil
			}
			if complete {
				ack, e := m.store.AcknowledgeWindowsCompleteIncident(r.Context(), completeTarget, m.source.Now, guard)
				acknowledged = ack.AcknowledgedAt
				return e
			}
			ack, e := m.store.AcknowledgeWindowsIncident(r.Context(), legacyTarget, m.source.Now, guard)
			acknowledged = ack.AcknowledgedAt
			return e
		}
		var e error
		if complete {
			lease, ok := m.source.(windowsCompleteIncidentAuthoritySource)
			if !ok {
				fail(w, 503, "windows_inbox_unavailable", "Current incident source cannot be locked.")
				return
			}
			e = lease.WithWindowsCompleteIncidentAuthority(r.Context(), windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: true, CurrentLeaf: in.CurrentLeaf, Selection: source}, save)
		} else {
			// V2 reads pin the actual pre-read leaf even for old row keys. The
			// identity-only path requires no full-service source or local grant.
			lease, ok := m.source.(windowsCompleteServiceAuthoritySource)
			if !ok {
				fail(w, 503, "windows_inbox_unavailable", "Current incident authority cannot be locked.")
				return
			}
			e = lease.WithWindowsCompleteServiceAuthority(r.Context(), windowsservicehealth.Input{Input: in.Input, Complete: true, CurrentLeaf: in.CurrentLeaf}, save)
		}
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
		// A post-commit source change makes the response uncertain, never a retry.
		if complete {
			current := completeInboxCurrentSource(authority[in.DeviceID], m.source.Now().UTC())
			if (current == nil) != (source == nil) || current != nil && *current != *source {
				fail(w, 409, "windows_inbox_conflict", "The source changed. Refresh acknowledgement state.")
				return
			}
		}
		now := m.source.Now().UTC()
		h.writeWindowsCompleteInbox(w, r, started, now, in.AuthorityUntil, 1024, struct {
			SchemaVersion  string    `json:"schemaVersion"`
			ServerNow      time.Time `json:"serverNow"`
			Key            string    `json:"key"`
			AcknowledgedAt time.Time `json:"acknowledgedAt"`
		}{"tracebolt.windows-incident-ack.v2", now, intent.Key, acknowledged})
		return
	}
	if !recheck() {
		return
	}
	contactEpoch, capacityEpoch := "", ""
	if c != nil && c.ready {
		contactEpoch = c.epoch
	}
	if m.ready {
		capacityEpoch = m.epoch
	}
	now := m.source.Now().UTC()
	view, err := projectWindowsCompleteInbox(snapshot, authority, now, contactEpoch, capacityEpoch, query)
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	h.writeWindowsCompleteInbox(w, r, started, now, view.AuthorityExpiresAt, 262144, view)
}
func (h *operatorHandler) writeWindowsCompleteInbox(w http.ResponseWriter, r *http.Request, started, now, expires time.Time, limit int, value any) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > limit {
		fail(w, 503, "windows_inbox_unavailable", "Windows incidents are unavailable.")
		return
	}
	clear(raw)
	h.writeWindowsInbox(w, r, started, now, expires, limit, value)
}
