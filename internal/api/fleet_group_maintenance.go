package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
)

type fleetGroupMaintenanceMember struct {
	DeviceID string                         `json:"deviceId"`
	Name     string                         `json:"name"`
	Targets  []windowsMaintenanceTargetView `json:"targets"`
}

type fleetGroupMaintenanceView struct {
	SchemaVersion        string                        `json:"schemaVersion"`
	ServerNow            time.Time                     `json:"serverNow"`
	AuthorityExpiresAt   time.Time                     `json:"authorityExpiresAt"`
	GroupID              string                        `json:"groupId"`
	GroupName            string                        `json:"groupName"`
	GroupRevision        uint64                        `json:"groupRevision"`
	ExcludedLinuxMembers int                           `json:"excludedLinuxMembers"`
	UnavailableMembers   int                           `json:"unavailableMembers"`
	Members              []fleetGroupMaintenanceMember `json:"members"`
}

type fleetGroupMaintenanceRead struct {
	group   store.FleetGroup
	devices map[string]fleetGroupDevice
	binding enrollmentstate.Binding
}

var errFleetMaintenanceGroupMissing = errors.New("maintenance group missing")

func (h *operatorHandler) fleetGroupMaintenanceAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 6 && len(parts) != 7) || parts[1] != "api" || parts[2] != "fleet" || parts[3] != "groups" || !enrollmentcrypto.ValidID(parts[4], "group_") || parts[5] != "maintenance" || len(parts) == 7 && parts[6] != "start" {
		fail(w, 404, "not_found", "Group maintenance is unavailable.")
		return
	}
	h.serveWindowsMaintenance(w, r, parts[4])
}

// Admission and group reads happen outside the operator write transaction. The
// transaction later rechecks exact membership/revision with no enrollment calls
// or new locks, under the existing enrollment-to-operator lease.
func (h *operatorHandler) readFleetGroupMaintenance(ctx context.Context, id string, started time.Time) (*fleetGroupMaintenanceRead, error) {
	m := h.app.windowsCapacity
	source, ok := m.source.(interface {
		Binding() enrollmentstate.Binding
	})
	if !ok {
		return nil, store.ErrWindowsMaintenance
	}
	binding := source.Binding()
	manager, now, devices, err := fleetGroupAdmission(ctx, h.groupSources())
	if err != nil {
		return nil, err
	}
	if manager != monitoringManager(binding) || !contactReadTime(started, now) {
		return nil, store.ErrWindowsMaintenanceConflict
	}
	groups, err := m.store.FleetGroups(ctx, manager)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if group.ID == id {
			return &fleetGroupMaintenanceRead{group: group, devices: devices, binding: binding}, nil
		}
	}
	return nil, errFleetMaintenanceGroupMissing
}

func fleetGroupMaintenanceError(w http.ResponseWriter, err error) {
	if errors.Is(err, errFleetMaintenanceGroupMissing) {
		fail(w, 404, "not_found", "Group no longer exists.")
	} else if errors.Is(err, store.ErrWindowsMaintenanceConflict) {
		fail(w, 409, "windows_maintenance_conflict", "Group identity authority changed. Refresh maintenance.")
	} else {
		fail(w, 503, "windows_maintenance_unavailable", "Current group membership is unavailable.")
	}
}

func projectFleetGroupMaintenance(states []store.WindowsMaintenanceState, read fleetGroupMaintenanceRead, authority map[string]windowscapacity.Input, now time.Time) (fleetGroupMaintenanceView, error) {
	g := read.group
	view := fleetGroupMaintenanceView{SchemaVersion: "tracebolt.fleet-group-maintenance.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), GroupID: g.ID, GroupName: g.Name, GroupRevision: g.Revision, Members: []fleetGroupMaintenanceMember{}}
	if len(g.Members) > store.MaxFleetGroupMembers || g.Manager != monitoringManager(read.binding) {
		return view, store.ErrWindowsMaintenanceConflict
	}
	selected := map[string]windowscapacity.Input{}
	seen := map[string]bool{}
	for _, member := range g.Members {
		if seen[member.DeviceID] {
			return view, store.ErrWindowsMaintenanceConflict
		}
		seen[member.DeviceID] = true
		device, ok := read.devices[member.DeviceID]
		if !ok || device.identity != member.Identity {
			view.UnavailableMembers++
			continue
		}
		if !now.Before(device.expires) {
			return view, store.ErrWindowsMaintenanceConflict
		}
		if device.expires.Before(view.AuthorityExpiresAt) {
			view.AuthorityExpiresAt = device.expires
		}
		if device.Platform == "linux" {
			view.ExcludedLinuxMembers++
			continue
		}
		in, admitted := authority[member.DeviceID]
		if device.Platform != "windows" || !admitted || !in.Authorized || member.Identity != monitoringIdentity(read.binding, in.Input) {
			view.UnavailableMembers++
			continue
		}
		selected[member.DeviceID] = in
	}
	if len(selected) > 25 {
		return view, store.ErrWindowsMaintenanceConflict
	}
	maintenance, err := projectWindowsMaintenance(states, selected, now)
	if err != nil {
		return view, err
	}
	if maintenance.AuthorityExpiresAt.Before(view.AuthorityExpiresAt) {
		view.AuthorityExpiresAt = maintenance.AuthorityExpiresAt
	}
	// The existing projection fixes both device and domain order. Every member
	// carries its complete six-target identity-bound set from this single read.
	for _, target := range maintenance.Targets {
		if len(view.Members) == 0 || view.Members[len(view.Members)-1].DeviceID != target.DeviceID {
			view.Members = append(view.Members, fleetGroupMaintenanceMember{DeviceID: target.DeviceID, Name: read.devices[target.DeviceID].Name, Targets: []windowsMaintenanceTargetView{}})
		}
		last := &view.Members[len(view.Members)-1]
		last.Targets = append(last.Targets, target)
	}
	return view, nil
}
