package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
)

type windowsCompleteNotificationTargetView struct {
	Key                  string     `json:"key"`
	DeviceID             string     `json:"deviceId"`
	Domain               string     `json:"domain"`
	Revision             uint64     `json:"revision"`
	Enabled              bool       `json:"enabled"`
	Effective            bool       `json:"effective"`
	MaintenanceUntil     *time.Time `json:"maintenanceUntil"`
	ChangedAt            *time.Time `json:"changedAt"`
	HealthPolicyRevision uint64     `json:"healthPolicyRevision"`
	GrantID              string     `json:"grantId"`
	GrantRevision        uint64     `json:"grantRevision"`
	Services             []string   `json:"services"`
	Actionable           bool       `json:"actionable"`
}
type windowsCompleteNotificationView struct {
	SchemaVersion      string                                  `json:"schemaVersion"`
	ServerNow          time.Time                               `json:"serverNow"`
	AuthorityExpiresAt time.Time                               `json:"authorityExpiresAt"`
	DestinationHost    string                                  `json:"destinationHost"`
	DestinationBinding string                                  `json:"destinationBinding"`
	DeliveryEnabled    bool                                    `json:"deliveryEnabled"`
	Targets            []windowsCompleteNotificationTargetView `json:"targets"`
	Counts             store.AlarmStatus                       `json:"counts"`
}
type windowsCompleteNotificationChoice struct {
	target     store.WindowsCompleteNotificationTarget
	retained   *store.WindowsCompleteNotificationPolicy
	input      windowsservicehealth.Input
	actionable bool
	services   []string
}

// Current health selections and retained notification approval are joined only
// by original enrollment identity. A new grant/reviewed health revision exposes
// a new exact key while retaining the independent notification revision.
func completeNotificationChoices(snapshot store.WindowsNotificationSnapshot, states map[string]windowsservicehealth.State, authority map[string]windowscapacity.Input, now time.Time) map[string]windowsCompleteNotificationChoice {
	choices := map[string]windowsCompleteNotificationChoice{}
	for id, in := range authority {
		if !in.Authorized || !now.Before(in.AuthorityUntil) {
			continue
		}
		choice := windowsCompleteNotificationChoice{input: windowsservicehealth.Input{Input: in.Input, Sample: in.Services, Complete: true, CurrentLeaf: in.CurrentLeaf}, services: []string{}}
		for _, policy := range snapshot.CompletePolicies {
			if policy.Target.DeviceID == id && policy.Target.InvitationID == in.InvitationID && policy.Target.CertificateHash == in.CertificateHash {
				p := policy
				choice.retained = &p
				choice.target = p.Target
			}
		}
		state, exists := states[id]
		if exists && state.SchemaVersion == windowsservicehealth.CompleteStateSchema && state.InvitationID == in.InvitationID && state.CertificateHash == in.CertificateHash && state.Policy.Source != nil && state.Policy.Revision > 0 {
			choice.target = store.WindowsCompleteNotificationTarget{WindowsMaintenanceTarget: maintenanceTarget(in, "service-complete"), Source: *state.Policy.Source, HealthPolicyRevision: state.Policy.Revision}
			choice.services = append([]string{}, state.Policy.Services...)
			inventory := state.View(choice.input, now, "").Inventory
			if state.Policy.Enabled && inventory != nil && inventory.Source != nil && inventory.Source.Binding() == *state.Policy.Source && enrollmentcrypto.ValidHash(in.CurrentLeaf) {
				p := *inventory.Source
				choice.input.Selection = &p
				choice.actionable = true
			}
		}
		if choice.target.Valid() {
			choices[choice.target.Key()] = choice
		}
	}
	return choices
}

func projectWindowsCompleteNotifications(snapshot store.WindowsNotificationSnapshot, maintenance []store.WindowsMaintenanceState, states map[string]windowsservicehealth.State, authority map[string]windowscapacity.Input, destination alarmdelivery.SourceDestination, now time.Time) (windowsCompleteNotificationView, map[string]windowsCompleteNotificationChoice, error) {
	view := windowsCompleteNotificationView{SchemaVersion: "tracebolt.windows-complete-notifications.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), DestinationHost: destination.Host, DestinationBinding: destination.Binding, DeliveryEnabled: destination.Enabled && snapshot.DeliveryEnabled && snapshot.Binding == destination.Binding, Targets: []windowsCompleteNotificationTargetView{}, Counts: snapshot.Counts}
	view.Counts.SchemaVersion = "tracebolt.alarm-status.v1"
	view.Counts.Enabled = view.DeliveryEnabled
	choices := completeNotificationChoices(snapshot, states, authority, now)
	for _, in := range authority {
		if in.Authorized {
			if !now.Before(in.AuthorityUntil) {
				return view, nil, store.ErrWindowsNotificationConflict
			}
			if in.AuthorityUntil.Before(view.AuthorityExpiresAt) {
				view.AuthorityExpiresAt = in.AuthorityUntil
			}
		}
	}
	for key, choice := range choices {
		target := choice.target
		row := windowsCompleteNotificationTargetView{Key: key, DeviceID: target.DeviceID, Domain: "service-complete", HealthPolicyRevision: target.HealthPolicyRevision, GrantID: target.Source.GrantID, GrantRevision: target.Source.GrantRevision, Services: choice.services, Actionable: choice.actionable}
		if choice.retained != nil {
			p := choice.retained
			if now.Before(p.ChangedAt) {
				return view, nil, store.ErrWindowsNotificationConflict
			}
			row.Revision, row.Enabled, row.ChangedAt = p.Revision, p.Enabled, inboxStamp(p.ChangedAt)
			row.Effective = p.Enabled && p.Target == target && p.Binding == destination.Binding && view.DeliveryEnabled && choice.actionable
		}
		if choice.actionable {
			source := choice.input.Selection
			for _, deadline := range []time.Time{source.CapturedAt.Add(windowsservicehealth.CompleteMaxAge), source.ReceivedAt.Add(windowsservicehealth.CompleteMaxAge), source.ExpiresAt} {
				if !now.Before(deadline) {
					row.Actionable = false
					row.Effective = false
				} else if deadline.Before(view.AuthorityExpiresAt) {
					view.AuthorityExpiresAt = deadline
				}
			}
		}
		for _, st := range maintenance {
			if st.Target.DeviceID == target.DeviceID && st.Target.InvitationID == target.InvitationID && st.Target.CertificateHash == target.CertificateHash && (st.Target.Domain == "all" || st.Target.Domain == "service") {
				if now.Before(st.ChangedAt) {
					return view, nil, store.ErrWindowsNotificationConflict
				}
				if st.Windows[0].Active(now) {
					row.MaintenanceUntil = inboxStamp(st.Windows[0].EndsAt)
				}
			}
		}
		view.Targets = append(view.Targets, row)
	}
	sort.Slice(view.Targets, func(i, j int) bool { return view.Targets[i].DeviceID < view.Targets[j].DeviceID })
	return view, choices, nil
}

func (h *operatorHandler) windowsCompleteNotificationsAPI(w http.ResponseWriter, r *http.Request) {
	const route = "/api/fleet/windows-notifications/complete"
	mutation := r.URL.Path == route+"/policy"
	if r.URL.Path != route && !mutation {
		fail(w, 404, "not_found", "Complete-service notifications are unavailable.")
		return
	}
	if !mutation && r.Method != http.MethodGet || mutation && r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !mutation && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		fail(w, 400, "invalid_windows_notifications", "Use the exact complete-service endpoint without query parameters or a read body.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Complete-service notifications are not configured.")
		return
	}
	var body struct {
		Key                 string `json:"key"`
		Revision            uint64 `json:"revision"`
		Enabled             bool   `json:"enabled"`
		DestinationBinding  string `json:"destinationBinding"`
		PayloadAcknowledged bool   `json:"payloadAcknowledged"`
	}
	if mutation {
		op, ok := operatorContext(r)
		if !ok || op.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change complete-service notification sources.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) || !readObject(w, r, 512, []string{"key", "revision", "enabled", "destinationBinding", "payloadAcknowledged"}, &body) {
			return
		}
		if !enrollmentcrypto.ValidHash(body.Key) || body.Revision >= store.MaxWindowsMaintenanceRevision || body.Enabled && (!body.PayloadAcknowledged || !enrollmentcrypto.ValidHash(body.DestinationBinding)) || !body.Enabled && (body.PayloadAcknowledged || body.DestinationBinding != "") {
			fail(w, 400, "invalid_windows_notifications", "Review the exact complete-service scope, revision, destination and bounded payload.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	states, err := m.store.WindowsServiceStates(ctx)
	if err != nil {
		fail(w, 503, "windows_notifications_unavailable", "Retained complete-service policy is unavailable.")
		return
	}
	selections := map[string][]string{}
	for id, state := range states {
		if state.SchemaVersion == windowsservicehealth.CompleteStateSchema && state.Policy.Enabled {
			selections[id] = state.Policy.Services
		}
	}
	ctx = windowsservicehealth.WithCompleteSelections(ctx, selections)
	r = r.WithContext(ctx)
	inputs, err := m.source.WindowsCapacityInputs(ctx, started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, started)
	if err != nil {
		fail(w, 503, "windows_notifications_unavailable", "Current Windows identity authority is unavailable.")
		return
	}
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) {
			fail(w, 409, "windows_notifications_conflict", "The time reference changed. Refresh notifications.")
			return false
		}
		rows, e := m.source.WindowsCapacityInputs(ctx, at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(rows, at)
		if e != nil || len(latest) != len(authority) {
			fail(w, 409, "windows_notifications_conflict", "Windows authority changed. Refresh notifications.")
			return false
		}
		for id, in := range authority {
			v, ok := latest[id]
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || v.CurrentLeaf != in.CurrentLeaf || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
				fail(w, 409, "windows_notifications_conflict", "Windows authority changed. Refresh notifications.")
				return false
			}
		}
		end := m.source.Now().UTC()
		if end.Before(at) || !contactReadTime(started, end) {
			fail(w, 409, "windows_notifications_conflict", "The time reference changed. Refresh notifications.")
			return false
		}
		for _, in := range latest {
			if in.Authorized && !end.Before(in.AuthorityUntil) {
				fail(w, 409, "windows_notifications_conflict", "Windows authority expired. Refresh notifications.")
				return false
			}
		}
		authority = latest
		return operatorStillActive(w, r)
	}
	snapshot, err := m.store.WindowsNotifications(ctx)
	if err != nil {
		fail(w, 503, "windows_notifications_unavailable", "Retained notification state is unavailable.")
		return
	}
	if mutation {
		if !recheck() {
			return
		}
		choices := completeNotificationChoices(snapshot, states, authority, m.source.Now().UTC())
		selected, ok := choices[body.Key]
		if !ok || body.Enabled && !selected.actionable || !body.Enabled && selected.retained == nil {
			fail(w, 409, "windows_notifications_conflict", "The exact complete-service source changed. Refresh and review again.")
			return
		}
		target := selected.target
		if !body.Enabled {
			target = selected.retained.Target
			selected.input.Selection = nil
		}
		lease, ok := m.source.(windowsCompleteServiceAuthoritySource)
		if !ok {
			fail(w, 503, "windows_notifications_unavailable", "Current complete-service authority cannot be locked.")
			return
		}
		err = h.alarmSettings.WithSourceDestination(body.DestinationBinding, body.Enabled, func() error {
			return lease.WithWindowsCompleteServiceAuthority(ctx, selected.input, func(authorityGuard func(time.Time) error) error {
				last := started
				_, e := m.store.ChangeWindowsCompleteNotificationPolicy(ctx, target, body.Revision, body.Enabled, body.DestinationBinding, selected.input, m.source.Now, func(sampled time.Time) error {
					at := m.source.Now().UTC()
					op, live := operatorContext(r)
					if !live || op.active == nil || !op.active() || ctx.Err() != nil || at.Before(sampled) || at.Before(last) || !contactReadTime(started, at) || !at.Before(selected.input.AuthorityUntil) {
						return store.ErrWindowsNotificationConflict
					}
					if e := authorityGuard(at); e != nil {
						return store.ErrWindowsNotificationConflict
					}
					final := m.source.Now().UTC()
					if final.Before(at) || !contactReadTime(started, final) || !final.Before(selected.input.AuthorityUntil) || selected.input.Selection != nil && !selected.input.Selection.Fresh(final) || !op.active() || ctx.Err() != nil {
						return store.ErrWindowsNotificationConflict
					}
					last = final
					return nil
				})
				return e
			})
		})
		if err != nil {
			if errors.Is(err, store.ErrWindowsNotificationConflict) || errors.Is(err, alarmdelivery.ErrSettingsConflict) || errors.Is(err, alarmdelivery.ErrSettingsBusy) || errors.Is(err, store.ErrLimit) {
				fail(w, 409, "windows_notifications_conflict", "The source, destination, revision or authority changed, or delivery is busy. Refresh and review again.")
			} else {
				fail(w, 503, "windows_notifications_unavailable", "The change could not be confirmed. Refresh without repeating the write.")
			}
			return
		}
		snapshot, err = m.store.WindowsNotifications(ctx)
		if err != nil {
			fail(w, 503, "windows_notifications_unavailable", "The change could not be read back. Refresh without repeating the write.")
			return
		}
	}
	destination := h.alarmSettings.SourceDestination()
	maintenance, err := m.store.WindowsMaintenance(ctx)
	if err != nil {
		fail(w, 503, "windows_notifications_unavailable", "Maintenance state is unavailable.")
		return
	}
	if !recheck() {
		return
	}
	if destination != h.alarmSettings.SourceDestination() {
		fail(w, 409, "windows_notifications_conflict", "The destination changed. Refresh notifications.")
		return
	}
	now := m.source.Now().UTC()
	view, _, err := projectWindowsCompleteNotifications(snapshot, maintenance, states, authority, destination, now)
	if err != nil {
		fail(w, 409, "windows_notifications_conflict", "The time or authority changed. Refresh notifications.")
		return
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw)+1 > 262144 {
		fail(w, 503, "windows_notifications_unavailable", "Notification state exceeds its bounded response.")
		return
	}
	defer clear(raw)
	final := m.source.Now().UTC()
	if final.Before(now) || !contactReadTime(started, final) || !final.Before(view.AuthorityExpiresAt) {
		fail(w, 409, "windows_notifications_conflict", "The time or authority expired. Refresh notifications.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(append(raw, '\n'))
}
