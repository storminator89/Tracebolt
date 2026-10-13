package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
)

type windowsNotificationTargetView struct {
	Key              string     `json:"key"`
	DeviceID         string     `json:"deviceId"`
	Domain           string     `json:"domain"`
	Revision         uint64     `json:"revision"`
	Enabled          bool       `json:"enabled"`
	Effective        bool       `json:"effective"`
	MaintenanceUntil *time.Time `json:"maintenanceUntil"`
	ChangedAt        *time.Time `json:"changedAt"`
}
type windowsNotificationView struct {
	SchemaVersion      string                          `json:"schemaVersion"`
	ServerNow          time.Time                       `json:"serverNow"`
	AuthorityExpiresAt time.Time                       `json:"authorityExpiresAt"`
	DestinationHost    string                          `json:"destinationHost"`
	DestinationBinding string                          `json:"destinationBinding"`
	DeliveryEnabled    bool                            `json:"deliveryEnabled"`
	Targets            []windowsNotificationTargetView `json:"targets"`
	Counts             store.AlarmStatus               `json:"counts"`
}

func projectWindowsNotifications(snapshot store.WindowsNotificationSnapshot, maintenance []store.WindowsMaintenanceState, authority map[string]windowscapacity.Input, destination alarmdelivery.SourceDestination, now time.Time) (windowsNotificationView, error) {
	v := windowsNotificationView{SchemaVersion: "tracebolt.windows-notifications.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), DestinationHost: destination.Host, DestinationBinding: destination.Binding, DeliveryEnabled: destination.Enabled && snapshot.DeliveryEnabled && snapshot.Binding == destination.Binding, Targets: []windowsNotificationTargetView{}, Counts: snapshot.Counts}
	v.Counts.SchemaVersion = "tracebolt.alarm-status.v1"
	v.Counts.Enabled = v.DeliveryEnabled
	byKey := map[string]store.WindowsNotificationPolicy{}
	for _, p := range snapshot.Policies {
		byKey[p.Target.Key()] = p
	}
	ids := []string{}
	for id, in := range authority {
		if in.Authorized {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		in := authority[id]
		if !now.Before(in.AuthorityUntil) {
			return v, store.ErrWindowsNotificationConflict
		}
		if in.AuthorityUntil.Before(v.AuthorityExpiresAt) {
			v.AuthorityExpiresAt = in.AuthorityUntil
		}
		for _, domain := range store.WindowsMaintenanceDomains() {
			if domain == "all" {
				continue
			}
			target := maintenanceTarget(in, domain)
			row := windowsNotificationTargetView{Key: target.Key(), DeviceID: id, Domain: domain}
			if p, ok := byKey[target.Key()]; ok {
				if p.Target != target || now.Before(p.ChangedAt) {
					return v, store.ErrWindowsNotificationConflict
				}
				row.Revision = p.Revision
				row.Enabled = p.Enabled
				row.Effective = p.Enabled && v.DeliveryEnabled && p.Binding == destination.Binding
				row.ChangedAt = inboxStamp(p.ChangedAt)
			}
			for _, st := range maintenance {
				if st.Target.DeviceID == target.DeviceID && st.Target.InvitationID == target.InvitationID && st.Target.CertificateHash == target.CertificateHash && (st.Target.Domain == "all" || st.Target.Domain == domain) {
					if now.Before(st.ChangedAt) {
						return v, store.ErrWindowsNotificationConflict
					}
					if st.Windows[0].Active(now) {
						row.MaintenanceUntil = inboxStamp(st.Windows[0].EndsAt)
					}
				}
			}
			v.Targets = append(v.Targets, row)
		}
	}
	return v, nil
}
func (h *operatorHandler) windowsNotificationsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/fleet/windows-notifications/complete" || strings.HasPrefix(r.URL.Path, "/api/fleet/windows-notifications/complete/") {
		h.windowsCompleteNotificationsAPI(w, r)
		return
	}
	const route = "/api/fleet/windows-notifications"
	mutation := r.URL.Path == route+"/policy"
	if r.URL.Path != route && !mutation {
		fail(w, 404, "not_found", "Windows notifications are unavailable.")
		return
	}
	if (!mutation && r.Method != "GET") || (mutation && r.Method != "POST") {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !mutation && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		fail(w, 400, "invalid_windows_notifications", "Use the exact notification endpoint without query parameters or a read body.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows notifications are not configured.")
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
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change Windows notification sources.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) || !readObject(w, r, 512, []string{"key", "revision", "enabled", "destinationBinding", "payloadAcknowledged"}, &body) {
			return
		}
		if !enrollmentcrypto.ValidHash(body.Key) || body.Revision >= store.MaxWindowsMaintenanceRevision || body.Enabled && (!body.PayloadAcknowledged || !enrollmentcrypto.ValidHash(body.DestinationBinding)) || !body.Enabled && (body.PayloadAcknowledged || body.DestinationBinding != "") {
			fail(w, 400, "invalid_windows_notifications", "Review the exact source, revision, destination and bounded Windows payload.")
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
	// Reads and response release recheck the same original identity. No projection
	// joins independently fetched incident rows using a mutable device identifier.
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
			fail(w, 409, "windows_notifications_conflict", "Windows identity authority changed. Refresh notifications.")
			return false
		}
		for id, in := range authority {
			v, ok := latest[id]
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
				fail(w, 409, "windows_notifications_conflict", "Windows identity authority changed. Refresh notifications.")
				return false
			}
		}
		final := m.source.Now().UTC()
		if final.Before(at) || !contactReadTime(started, final) {
			fail(w, 409, "windows_notifications_conflict", "The time reference changed. Refresh notifications.")
			return false
		}
		authority = latest
		return operatorStillActive(w, r)
	}
	if mutation {
		var target store.WindowsMaintenanceTarget
		var selected windowscapacity.Input
		for _, in := range authority {
			if !in.Authorized {
				continue
			}
			for _, domain := range store.WindowsMaintenanceDomains() {
				if domain == "all" {
					continue
				}
				t := maintenanceTarget(in, domain)
				if t.Key() == body.Key {
					target, selected = t, in
				}
			}
		}
		if !target.Valid() || !recheck() {
			if !target.Valid() {
				fail(w, 409, "windows_notifications_conflict", "The exact Windows identity or source changed. Refresh notifications.")
			}
			return
		}
		lease, ok := m.source.(windowsIncidentAuthoritySource)
		if !ok {
			fail(w, 503, "windows_notifications_unavailable", "Current Windows authority cannot be locked.")
			return
		}
		err = h.alarmSettings.WithSourceDestination(body.DestinationBinding, body.Enabled, func() error {
			return lease.WithWindowsIncidentAuthority(ctx, selected.Input, func(authorityGuard func(time.Time) error) error {
				sampled := started
				_, e := m.store.ChangeWindowsNotificationPolicy(ctx, target, body.Revision, body.Enabled, body.DestinationBinding, m.source.Now, func(at time.Time) error {
					op, live := operatorContext(r)
					if !live || op.active == nil || !op.active() || ctx.Err() != nil || at.Before(sampled) || !contactReadTime(started, at) || !at.Before(selected.AuthorityUntil) {
						return store.ErrWindowsNotificationConflict
					}
					sampled = at
					if e := authorityGuard(at); e != nil {
						return store.ErrWindowsNotificationConflict
					}
					final := m.source.Now().UTC()
					if final.Before(at) || !contactReadTime(started, final) || !final.Before(selected.AuthorityUntil) || !op.active() {
						return store.ErrWindowsNotificationConflict
					}
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
	}
	destination := h.alarmSettings.SourceDestination()
	snapshot, err := m.store.WindowsNotifications(ctx)
	if err != nil {
		fail(w, 503, "windows_notifications_unavailable", "Retained notification state is unavailable.")
		return
	}
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
	view, err := projectWindowsNotifications(snapshot, maintenance, authority, destination, now)
	if err != nil {
		fail(w, 409, "windows_notifications_conflict", "The time or authority changed. Refresh notifications.")
		return
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw) > 262144 {
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
