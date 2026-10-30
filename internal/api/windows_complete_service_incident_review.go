package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
	"net/http"
	"strings"
	"time"
)

func windowsCompleteServiceIncidentReviewKey(r *http.Request) (string, bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 7 || parts[1] != "api" || parts[2] != "fleet" || parts[3] != "windows-incidents" || parts[4] != "complete" || parts[6] != "service-review" || !enrollmentcrypto.ValidHash(parts[5]) {
		return "", false
	}
	return parts[5], true
}

type windowsCompleteServiceReviewObservation struct {
	Name        string                          `json:"name"`
	DisplayName string                          `json:"displayName"`
	State       string                          `json:"state"`
	Source      windowsservicehealth.Provenance `json:"source"`
}
type windowsCompleteServiceIncidentReviewView struct {
	SchemaVersion      string                                   `json:"schemaVersion"`
	ServerNow          time.Time                                `json:"serverNow"`
	AuthorityExpiresAt time.Time                                `json:"authorityExpiresAt"`
	Incident           windowsCompleteInboxItem                 `json:"incident"`
	Observation        *windowsCompleteServiceReviewObservation `json:"observation"`
	Control            windowsServiceReviewControl              `json:"control"`
}

func projectWindowsCompleteServiceIncidentReview(snapshot store.WindowsCompleteIncidentSnapshot, in windowscapacity.Input, key string, now time.Time, contactEpoch, capacityEpoch string) (windowsCompleteServiceIncidentReviewView, error) {
	v := windowsCompleteServiceIncidentReviewView{SchemaVersion: "tracebolt.windows-service-incident-review.v2", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), Control: windowsServiceReviewControl{Status: "not_configured"}}
	target, ok := snapshot.CompleteTargets()[key]
	if !ok || target.Domain != "service-complete" || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) || !now.Before(in.AuthorityUntil) {
		return v, store.ErrWindowsIncident
	}
	if in.AuthorityUntil.Before(v.AuthorityExpiresAt) {
		v.AuthorityExpiresAt = in.AuthorityUntil
	}
	inbox, err := projectWindowsCompleteInbox(snapshot, map[string]windowscapacity.Input{in.DeviceID: in}, now, contactEpoch, capacityEpoch, windowsInboxQuery{Scope: "all", Ack: "all", Limit: store.MaxWindowsInboxIncidents})
	if err != nil {
		return v, err
	}
	for _, item := range inbox.Items {
		if item.Key == key {
			v.Incident = item
			break
		}
	}
	if v.Incident.Key != key || v.Incident.ServiceName == "" {
		return v, store.ErrWindowsIncident
	}
	inventory := (windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: true, CurrentLeaf: in.CurrentLeaf}).Inventory(now)
	if inventory != nil && inventory.Source != nil {
		for _, row := range inventory.Services {
			if row.Name == v.Incident.ServiceName {
				v.Observation = &windowsCompleteServiceReviewObservation{row.Name, row.DisplayName, row.State, *inventory.Source}
				break
			}
		}
	}
	return v, nil
}

func (h *operatorHandler) windowsCompleteServiceIncidentReview(w http.ResponseWriter, r *http.Request) {
	key, ok := windowsCompleteServiceIncidentReviewKey(r)
	if !ok {
		fail(w, 404, "not_found", "The retained service incident is unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_path", "Path is not canonical.")
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
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	conflict := func() {
		fail(w, 409, "windows_service_review_conflict", "The exact service incident or its authority changed. Refresh the incident inbox.")
	}
	started := m.source.Now().UTC()
	snapshot, err := m.store.WindowsCompleteIncidentSnapshot(ctx)
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	target, retained := snapshot.CompleteTargets()[key]
	if !retained || target.Domain != "service-complete" {
		conflict()
		return
	}
	name := ""
	for _, incident := range snapshot.Services[target.DeviceID].Incidents {
		if incident.ID == target.IncidentID && incident.OpenedAt.Equal(target.OpenedAt) {
			name = incident.Name
			break
		}
	}
	if name == "" {
		conflict()
		return
	}
	// Read exactly this retained name, even if it is no longer selected by the
	// current policy. This is a bounded source read, never a policy/evaluator write.
	ctx = windowsservicehealth.WithCompleteSelections(ctx, map[string][]string{target.DeviceID: {name}})
	r = r.WithContext(ctx)
	inputs, err := m.source.WindowsCapacityInputs(ctx, started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, started)
	if err != nil {
		conflict()
		return
	}
	in, admitted := authority[target.DeviceID]
	if !admitted || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) {
		conflict()
		return
	}
	// ViewAt is deliberately outside the source-authority lease: it uses its own
	// enrollment transaction and advances a durable clock floor. It creates no
	// preview, job, permit or grant. The immutable setup marker independently binds
	// this record to the original issued certificate anchor, never a renewed leaf.
	var record windowsactionjob.Record
	var observedAt time.Time
	var actionErr error
	can := windowsServiceReviewCanControl(r)
	configured := h.windowsActions != nil
	_, reviewSupported := h.windowsActions.(windowsServiceReviewActionManager)
	available := configured && reviewSupported && h.windowsActions.TransportProfile() == windowsactionmanager.Profile(map[bool]string{true: "http-test", false: "tls"}[h.insecureHTTPTest]) && h.windowsActions.Available()
	supported := windowsaction.ValidTarget(name)
	if supported && can && available {
		record, observedAt, actionErr = h.windowsActions.ViewAt(ctx, target.DeviceID)
	}
	at := m.source.Now().UTC()
	if !contactReadTime(started, at) {
		conflict()
		return
	}
	current, err := m.source.WindowsCapacityInputs(ctx, at)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	latest, err := windowsCapacityAuthority(current, at)
	fresh, found := latest[target.DeviceID]
	if err != nil || !found || !windowsInboxIdentity(fresh, target.DeviceID, target.InvitationID, target.CertificateHash) {
		conflict()
		return
	}
	now := m.source.Now().UTC()
	if !contactReadTime(started, now) || now.Before(at) || !observedAt.IsZero() && (observedAt.Before(started) || observedAt.After(now)) {
		conflict()
		return
	}
	contactEpoch, capacityEpoch := "", ""
	if c != nil && c.ready {
		contactEpoch = c.epoch
	}
	if m.ready {
		capacityEpoch = m.epoch
	}
	view, err := projectWindowsCompleteServiceIncidentReview(snapshot, fresh, key, now, contactEpoch, capacityEpoch)
	if err != nil {
		conflict()
		return
	}
	switch {
	case !supported:
		view.Control.Status = "unsupported_target"
	case !can:
		view.Control.Status = "operator_capability_required"
	case !configured:
		view.Control.Status = "not_configured"
	case !available || actionErr != nil || !windowsaction.ValidBinding(record.Binding):
		view.Control.Status = "unavailable"
	case record.Binding.EndpointID != target.DeviceID || record.Binding.IncarnationDigest != "sha256:"+target.CertificateHash || record.Binding.Target != view.Incident.ServiceName:
		view.Control.Status = "target_mismatch"
	case record.Ready(now) != "ready":
		view.Control.Status = "unavailable"
	default:
		binding := record.Binding
		digest := windowsaction.ServiceReviewBindingDigest(binding)
		view.Control = windowsServiceReviewControl{Status: "matched", Binding: &binding, BindingDigest: &digest}
		// A ready broker report expires independently of source observations.
		until := time.Unix(record.Capabilities.CapturedAt, 0).UTC().Add(time.Minute)
		if until.Before(view.AuthorityExpiresAt) {
			view.AuthorityExpiresAt = until
		}
	}
	// Pin present generation or explicit absence. A missing row stays unknown;
	// the full-source deadline still applies to the leased snapshot itself.
	source := completeInboxCurrentSource(fresh, now)
	if source != nil {
		for _, until := range []time.Time{source.CapturedAt.Add(windowsservicehealth.CompleteMaxAge), source.ReceivedAt.Add(windowsservicehealth.CompleteMaxAge), source.ExpiresAt} {
			if until.Before(view.AuthorityExpiresAt) {
				view.AuthorityExpiresAt = until
			}
		}
	}
	if until := view.Incident.StatusValidUntil; until != nil && until.After(view.AuthorityExpiresAt) {
		view.Incident.StatusValidUntil = inboxStamp(view.AuthorityExpiresAt)
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw)+1 > 16384 {
		fail(w, 503, "windows_inbox_unavailable", "The service review is unavailable.")
		return
	}
	defer clear(raw)
	lease, ok := m.source.(windowsCompleteIncidentAuthoritySource)
	if !ok {
		fail(w, 503, "windows_inbox_unavailable", "Current incident authority cannot be locked.")
		return
	}
	// No callback into enrollment is permitted here. The final locked original
	// identity/leaf check bridges the earlier immutable action binding comparison.
	written := false
	err = lease.WithWindowsCompleteIncidentAuthority(ctx, windowsservicehealth.Input{Input: fresh.Input, Sample: fresh.Services, Complete: true, CurrentLeaf: fresh.CurrentLeaf, Selection: source}, func(guard func(time.Time) error) error {
		end := m.source.Now().UTC()
		if ctx.Err() != nil || !contactReadTime(started, end) || end.Before(now) || !end.Before(view.AuthorityExpiresAt) {
			return store.ErrWindowsIncident
		}
		if err := guard(end); err != nil {
			return err
		}
		// The authority guard may itself wait/sample a later trusted time. Recheck
		// the shorter source/broker projection deadline after it, before release.
		releasedAt := m.source.Now().UTC()
		if !contactReadTime(started, releasedAt) || releasedAt.Before(end) || !releasedAt.Before(view.AuthorityExpiresAt) || ctx.Err() != nil {
			return store.ErrWindowsIncident
		}
		if !operatorStillActive(w, r) {
			written = true
			return store.ErrWindowsIncident
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		written = true
		_, err := w.Write(append(raw, '\n'))
		return err
	})
	if err != nil && !written {
		conflict()
	}
}
