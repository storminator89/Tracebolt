package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
)

const windowsServiceReviewHeader = "X-Tracebolt-Windows-Service-Review"

// The optional pin is allowed only on the existing status and manual-preview
// requests. Approval remains the existing exact preview ID/digest contract.
func validWindowsServiceReviewHeader(r *http.Request) bool {
	values := r.Header.Values(windowsServiceReviewHeader)
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || !windowsaction.ValidDigest(values[0]) {
		return false
	}
	_, op, ok := windowsServiceActionRoute(r)
	return ok && (op == "" && r.Method == http.MethodGet || op == "preview" && r.Method == http.MethodPost)
}

func windowsServiceIncidentReviewKey(r *http.Request) (string, bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "fleet" || parts[3] != "windows-incidents" || parts[5] != "service-review" || !enrollmentcrypto.ValidHash(parts[4]) {
		return "", false
	}
	return parts[4], true
}

type windowsServiceReviewObservation struct {
	Name          string    `json:"name"`
	DisplayName   string    `json:"displayName"`
	State         string    `json:"state"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	Sequence      uint64    `json:"sequence"`
	Quality       string    `json:"quality"`
	Complete      bool      `json:"complete"`
	Truncated     bool      `json:"truncated"`
	CountExact    bool      `json:"countExact"`
	ObservedCount uint32    `json:"observedCount"`
}

type windowsServiceReviewControl struct {
	Status        string                 `json:"status"`
	Binding       *windowsaction.Binding `json:"binding"`
	BindingDigest *string                `json:"bindingDigest"`
}

type windowsServiceIncidentReviewView struct {
	SchemaVersion      string                           `json:"schemaVersion"`
	ServerNow          time.Time                        `json:"serverNow"`
	AuthorityExpiresAt time.Time                        `json:"authorityExpiresAt"`
	Incident           windowsInboxItem                 `json:"incident"`
	Observation        *windowsServiceReviewObservation `json:"observation"`
	Control            windowsServiceReviewControl      `json:"control"`
}

// Resolve the opaque target and original retained episode before using the
// device lookup. A replacement with the same device ID cannot inherit the row.
func projectWindowsServiceIncidentReview(snapshot store.WindowsIncidentSnapshot, in windowscapacity.Input, key string, now time.Time, contactEpoch, capacityEpoch string) (windowsServiceIncidentReviewView, error) {
	v := windowsServiceIncidentReviewView{SchemaVersion: "tracebolt.windows-service-incident-review.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), Control: windowsServiceReviewControl{Status: "not_configured"}}
	target, ok := snapshot.Targets()[key]
	if !ok || target.Domain != "service" || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) || !now.Before(in.AuthorityUntil) {
		return v, store.ErrWindowsIncident
	}
	if in.AuthorityUntil.Before(v.AuthorityExpiresAt) {
		v.AuthorityExpiresAt = in.AuthorityUntil
	}
	// Reuse the exact inbox projection; lifecycle and source timestamps stay v1.
	inbox, err := projectWindowsInbox(snapshot, map[string]windowscapacity.Input{in.DeviceID: in}, now, contactEpoch, capacityEpoch, windowsInboxQuery{Scope: "all", Ack: "all", Limit: store.MaxWindowsInboxIncidents})
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
	inventory := (windowsservicehealth.Input{Input: in.Input, Sample: in.Services}).Inventory(now)
	if inventory != nil {
		for _, row := range inventory.Services {
			if row.Name == v.Incident.ServiceName {
				v.Observation = &windowsServiceReviewObservation{row.Name, row.DisplayName, row.State, inventory.CollectedAt, inventory.ReceivedAt, inventory.Sequence, inventory.Quality, inventory.Complete, inventory.Truncated, inventory.CountExact, inventory.ObservedCount}
				break
			}
		}
	}
	return v, nil
}

func windowsServiceReviewCanControl(r *http.Request) bool {
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() {
		return false
	}
	for _, capability := range owner.session.Capabilities() {
		if capability == operatorauth.WindowsServiceControl {
			return true
		}
	}
	return false
}

func (h *operatorHandler) windowsServiceIncidentReview(w http.ResponseWriter, r *http.Request) {
	key, ok := windowsServiceIncidentReviewKey(r)
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
	snapshot, err := m.store.WindowsIncidentSnapshot(ctx)
	if err != nil {
		fail(w, 503, "windows_inbox_unavailable", "Retained Windows incident history is unavailable.")
		return
	}
	target, retained := snapshot.Targets()[key]
	in, admitted := authority[target.DeviceID]
	if !retained || target.Domain != "service" || !admitted || !windowsInboxIdentity(in, target.DeviceID, target.InvitationID, target.CertificateHash) {
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
	if can && available {
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
	view, err := projectWindowsServiceIncidentReview(snapshot, fresh, key, now, contactEpoch, capacityEpoch)
	if err != nil {
		conflict()
		return
	}
	switch {
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
	// A positive row must also remain fresh at response release. Bound the
	// projection by original capture/receipt age, never by a new HTTP receipt.
	if observation := view.Observation; observation != nil {
		until := observation.CollectedAt.Add(windowsservicehealth.MaxAge)
		if receipt := observation.ReceivedAt.Add(windowsservicehealth.MaxAge); receipt.Before(until) {
			until = receipt
		}
		if !now.Before(until) {
			view.Observation = nil
		} else if until.Before(view.AuthorityExpiresAt) {
			view.AuthorityExpiresAt = until
		}
	}
	if until := view.Incident.StatusValidUntil; until != nil && until.After(view.AuthorityExpiresAt) {
		view.Incident.StatusValidUntil = inboxStamp(view.AuthorityExpiresAt)
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw) > 16384 {
		fail(w, 503, "windows_inbox_unavailable", "The service review is unavailable.")
		return
	}
	defer clear(raw)
	lease, ok := m.source.(windowsIncidentAuthoritySource)
	if !ok {
		fail(w, 503, "windows_inbox_unavailable", "Current incident authority cannot be locked.")
		return
	}
	// No callback into enrollment is permitted here. The final locked original
	// identity/leaf check bridges the earlier immutable action binding comparison.
	written := false
	err = lease.WithWindowsIncidentAuthority(ctx, fresh.Input, func(guard func(time.Time) error) error {
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
		if !contactReadTime(started, releasedAt) || releasedAt.Before(end) || !releasedAt.Before(view.AuthorityExpiresAt) {
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
