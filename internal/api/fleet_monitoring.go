package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
	"net/http"
	"strings"
	"time"
)

type windowsMonitoringAuthoritySource interface {
	Binding() enrollmentstate.Binding
	WithWindowsMonitoringAuthority(context.Context, []windowscontact.Input, func(func(time.Time) error) error) error
}

func monitoringIdentity(b enrollmentstate.Binding, in windowscontact.Input) string {
	return fleetHash(struct {
		Binding                    enrollmentstate.Binding
		Device, Invitation, Issued string
	}{b, in.DeviceID, in.InvitationID, in.CertificateHash})
}
func monitoringManager(b enrollmentstate.Binding) string {
	return fleetHash([]string{b.InstanceID, b.Origin, b.Profile, b.IssuerFingerprint})
}

type fleetMonitoringTarget struct {
	DeviceID             string                  `json:"deviceId"`
	Name                 string                  `json:"name"`
	Metric               string                  `json:"metric"`
	AssignmentRevision   uint64                  `json:"assignmentRevision"`
	Policy               windowscapacity.Policy  `json:"policy"`
	Desired              *fleetMonitoringDesired `json:"desired"`
	Status               string                  `json:"status"`
	Owned                bool                    `json:"owned"`
	CertificateExpiresAt time.Time               `json:"certificateExpiresAt"`
}
type fleetMonitoringDesired struct {
	Enabled          bool `json:"enabled"`
	ThresholdPercent int  `json:"thresholdPercent"`
}
type fleetMonitoringView struct {
	SchemaVersion          string                         `json:"schemaVersion"`
	ServerNow              time.Time                      `json:"serverNow"`
	GroupID                string                         `json:"groupId"`
	GroupRevision          uint64                         `json:"groupRevision"`
	Revision               uint64                         `json:"revision"`
	Definitions            []store.FleetMonitoringSetting `json:"definitions"`
	Targets                []fleetMonitoringTarget        `json:"targets"`
	UnavailableAssignments int                            `json:"unavailableAssignments"`
}

func (m *windowsCapacityMonitor) monitoringView(ctx context.Context, g store.FleetGroup, devices map[string]fleetGroupDevice, authority map[string]windowscapacity.Input, now time.Time) (fleetMonitoringView, error) {
	d, err := m.store.FleetMonitoringDefinition(ctx, g.Manager, g.ID)
	if err != nil {
		return fleetMonitoringView{}, err
	}
	assignments, err := m.store.FleetMonitoringAssignments(ctx)
	if err != nil {
		return fleetMonitoringView{}, err
	}
	byKey := map[string]store.FleetMonitoringAssignment{}
	for _, a := range assignments {
		byKey[a.DeviceID+"/"+a.Metric] = a
	}
	view := fleetMonitoringView{SchemaVersion: "tracebolt.fleet-group-monitoring.v1", ServerNow: now, GroupID: g.ID, GroupRevision: g.Revision, Revision: d.Revision, Definitions: d.Settings, Targets: []fleetMonitoringTarget{}}
	visible := map[string]bool{}
members:
	for _, member := range g.Members {
		device, ok := devices[member.DeviceID]
		in, admitted := authority[member.DeviceID]
		if !ok || device.identity != member.Identity || device.Platform != "windows" || !admitted || !in.Authorized {
			continue
		}
		// Do not expose a partial row-set (or any old-identity policy). A device
		// is selectable only when all three independent policies can be projected.
		states := map[string]windowscapacity.State{}
		for _, metric := range []string{"disk", "cpu", "memory"} {
			kind := windowsresource.Kind(metric)
			if metric == "disk" {
				kind = ""
			}
			state, e := m.policyState(ctx, member.DeviceID, kind)
			if e != nil {
				return view, e
			}
			if state.InvitationID != "" && (state.InvitationID != in.InvitationID || state.CertificateHash != in.CertificateHash) {
				continue members
			}
			states[metric] = state
		}
		for _, metric := range []string{"disk", "cpu", "memory"} {
			state := states[metric]
			key := member.DeviceID + "/" + metric
			a, exists := byKey[key]
			target := fleetMonitoringTarget{DeviceID: member.DeviceID, Name: device.Name, Metric: metric, Policy: state.Policy, Status: "manual", CertificateExpiresAt: in.AuthorityUntil}
			if exists {
				target.AssignmentRevision = a.Revision
			}
			if exists && a.Active && (a.GroupID != g.ID || a.Manager != g.Manager || a.Identity != member.Identity) {
				target.Status = "conflict"
			} else if exists && a.GroupID == g.ID && a.Manager == g.Manager && a.Identity == member.Identity {
				visible[key] = true
				target.Owned = a.Active
				target.Status = a.Status
				if setting, found := d.Setting(metric); found {
					target.Desired = &fleetMonitoringDesired{setting.Enabled, setting.ThresholdPercent}
				}
				if a.Active {
					target.Status = "pending"
					if a.PolicyRevision != state.Policy.Revision {
						target.Status = "conflict"
					} else if a.AppliedRevision == d.Revision && target.Desired != nil && state.Policy.Enabled == target.Desired.Enabled && state.Policy.ThresholdPercent == target.Desired.ThresholdPercent {
						target.Status = "inherited"
					}
				}
			}
			view.Targets = append(view.Targets, target)
		}
	}
	for _, a := range assignments {
		if a.GroupID == g.ID && a.Manager == g.Manager && !visible[a.DeviceID+"/"+a.Metric] {
			view.UnavailableAssignments++
		}
	}
	return view, nil
}
func (h *operatorHandler) fleetMonitoringAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "fleet" || parts[3] != "groups" || !enrollmentcrypto.ValidID(parts[4], "group_") || parts[5] != "monitoring" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 404, "not_found", "Group monitoring is unavailable.")
		return
	}
	mutation := r.Method == http.MethodPost
	if !mutation && r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Use GET or POST.")
		return
	}
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows monitoring is unavailable.")
		return
	}
	var body struct {
		GroupRevision uint64                          `json:"expectedGroupRevision"`
		Revision      uint64                          `json:"expectedRevision"`
		Consent       bool                            `json:"consent"`
		Definitions   fleetMonitoringSettingsInput    `json:"definitions"`
		Assignments   fleetMonitoringAssignmentsInput `json:"assignments"`
	}
	if mutation {
		op, ok := operatorContext(r)
		if !ok || op.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readObject(w, r, 32768, []string{"expectedGroupRevision", "expectedRevision", "consent", "definitions", "assignments"}, &body) {
			return
		}
		if body.GroupRevision < 1 || body.GroupRevision > store.MaxFleetGroupRevision || body.Revision >= store.MaxFleetGroupRevision || body.Definitions == nil || len(body.Definitions) > 3 || body.Assignments == nil || len(body.Assignments) > 75 {
			fail(w, 400, "invalid_body", "Choose exact bounded monitoring settings and revisions.")
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
	source, ok := m.source.(windowsMonitoringAuthoritySource)
	if !ok {
		fail(w, 503, "fleet_monitoring_unavailable", "Current Windows authority cannot be locked.")
		return
	}
	sources := h.groupSources()
	manager, started, devices, err := fleetGroupAdmission(r.Context(), sources)
	if err != nil || manager != monitoringManager(source.Binding()) {
		fail(w, 503, "fleet_monitoring_unavailable", "Current group admission is unavailable.")
		return
	}
	groups, err := m.store.FleetGroups(r.Context(), manager)
	if err != nil {
		fail(w, 503, "fleet_monitoring_unavailable", "Groups are unavailable.")
		return
	}
	var group store.FleetGroup
	for _, g := range groups {
		if g.ID == parts[4] {
			group = g
		}
	}
	if group.ID == "" {
		fail(w, 404, "not_found", "Group no longer exists.")
		return
	}
	rows, err := m.source.WindowsCapacityInputs(r.Context(), started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(rows, started)
	if err != nil {
		fail(w, 503, "fleet_monitoring_unavailable", "Windows authority is unavailable.")
		return
	}
	guard := func(authorityGuard func(time.Time) error) func() error {
		return func() error {
			at := m.source.Now().UTC()
			op, ok := operatorContext(r)
			if !ok || op.active == nil || !op.active() || r.Context().Err() != nil || !contactReadTime(started, at) {
				return store.ErrFleetMonitoringConflict
			}
			if authorityGuard != nil {
				if e := authorityGuard(at); e != nil {
					return store.ErrFleetMonitoringConflict
				}
			}
			final := m.source.Now().UTC()
			if final.Before(at) || !contactReadTime(started, final) || !op.active() || r.Context().Err() != nil {
				return store.ErrFleetMonitoringConflict
			}
			for _, in := range authority {
				if in.Authorized && !final.Before(in.AuthorityUntil) {
					return store.ErrFleetMonitoringConflict
				}
			}
			return nil
		}
	}
	if mutation {
		changes := []store.FleetMonitoringChange{}
		leaseInputs := []windowscontact.Input{}
		seen := map[string]bool{}
		for _, a := range body.Assignments {
			device, ok := devices[a.DeviceID]
			in, found := authority[a.DeviceID]
			if !ok || !found || device.Platform != "windows" || !in.Authorized || device.identity != monitoringIdentity(source.Binding(), in.Input) {
				fail(w, 409, "fleet_monitoring_conflict", "Exact device authority changed.")
				return
			}
			changes = append(changes, store.FleetMonitoringChange{DeviceID: a.DeviceID, Metric: a.Metric, Identity: device.identity, InvitationID: in.InvitationID, CertificateHash: in.CertificateHash, ExpectedRevision: a.Revision, ExpectedPolicyRevision: a.PolicyRevision, Inherit: a.Inherit})
			if !seen[a.DeviceID] {
				leaseInputs = append(leaseInputs, in.Input)
				seen[a.DeviceID] = true
			}
		}
		save := func(authorityGuard func(time.Time) error) error {
			return m.store.SaveFleetMonitoring(r.Context(), manager, group.ID, body.GroupRevision, body.Revision, body.Consent, body.Definitions, changes, guard(authorityGuard))
		}
		if len(leaseInputs) > 0 {
			err = source.WithWindowsMonitoringAuthority(r.Context(), leaseInputs, save)
		} else {
			err = save(nil)
		}
		if err != nil {
			status := 503
			if errors.Is(err, store.ErrFleetMonitoringConflict) || errors.Is(err, store.ErrFleetMonitoringInvalid) || errors.Is(err, store.ErrLimit) {
				status = 409
			}
			fail(w, status, "fleet_monitoring_conflict", "The change could not be confirmed. Refresh without repeating it.")
			return
		}
	}
	// Read-only projection after mutation, including uncertain/lost responses. Never
	// evaluate or repair policies while answering a GET.
	_, now, currentDevices, e := fleetGroupAdmission(r.Context(), sources)
	if e != nil || !contactReadTime(started, now) {
		fail(w, 503, "fleet_monitoring_unavailable", "Refresh group monitoring.")
		return
	}
	currentRows, e := m.source.WindowsCapacityInputs(r.Context(), now)
	if e != nil {
		systemInventoryError(w, e)
		return
	}
	current, e := windowsCapacityAuthority(currentRows, now)
	if e != nil {
		fail(w, 503, "fleet_monitoring_unavailable", "Windows authority is unavailable.")
		return
	}
	for id, in := range current {
		if in.Authorized {
			device, exists := currentDevices[id]
			if !exists || device.identity != monitoringIdentity(source.Binding(), in.Input) {
				delete(current, id)
			}
		}
	}
	view, e := m.monitoringView(r.Context(), group, currentDevices, current, now)
	if e != nil {
		fail(w, 503, "fleet_monitoring_unavailable", "Monitoring state is unavailable.")
		return
	}
	h.writeFleetIdentityBytes(w, r, view, 128*1024, guard(nil))
}

// One bounded sequential pass on the existing 30-second scheduler. With no
// active assignments it performs zero additional enrollment reads. Current
// original identity and every stored revision are checked again inside commit.
func (m *windowsCapacityMonitor) reconcileFleetMonitoring(ctx context.Context) error {
	assignments, err := m.store.FleetMonitoringAssignments(ctx)
	if err != nil {
		return err
	}
	active := []store.FleetMonitoringAssignment{}
	for _, a := range assignments {
		if a.Active {
			active = append(active, a)
		}
	}
	if len(active) == 0 {
		return nil
	}
	source, ok := m.source.(windowsMonitoringAuthoritySource)
	if !ok {
		return store.ErrFleetMonitoringInvalid
	}
	started := m.source.Now().UTC()
	rows, err := m.source.WindowsCapacityInputs(ctx, started)
	if err != nil {
		return err
	}
	authority, err := windowsCapacityAuthority(rows, started)
	if err != nil {
		return err
	}
	manager := monitoringManager(source.Binding())
	groups, err := m.store.FleetGroups(ctx, manager)
	if err != nil {
		return err
	}
	byID := map[string]store.FleetGroup{}
	for _, g := range groups {
		byID[g.ID] = g
	}
	for _, a := range active {
		if err = ctx.Err(); err != nil {
			return err
		}
		in, ok := authority[a.DeviceID]
		g, exists := byID[a.GroupID]
		if !ok || !exists || !in.Authorized || a.Manager != manager || a.Identity != monitoringIdentity(source.Binding(), in.Input) || a.InvitationID != in.InvitationID || a.CertificateHash != in.CertificateHash {
			continue
		}
		d, e := m.store.FleetMonitoringDefinition(ctx, manager, a.GroupID)
		if e != nil {
			return e
		}
		if a.AppliedRevision == d.Revision {
			continue
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) {
			return store.ErrFleetMonitoringConflict
		}
		err = source.WithWindowsMonitoringAuthority(ctx, []windowscontact.Input{in.Input}, func(authorityGuard func(time.Time) error) error {
			return m.store.ReconcileFleetMonitoring(ctx, in, a, d, g.Revision, at, func() error {
				now := m.source.Now().UTC()
				if now.Before(at) || !contactReadTime(started, now) || !now.Before(in.AuthorityUntil) {
					return store.ErrFleetMonitoringConflict
				}
				if e := authorityGuard(now); e != nil {
					return e
				}
				final := m.source.Now().UTC()
				if final.Before(now) || !contactReadTime(started, final) || !final.Before(in.AuthorityUntil) {
					return store.ErrFleetMonitoringConflict
				}
				return ctx.Err()
			})
		})
		if err != nil {
			return err
		}
	}
	return nil
}
