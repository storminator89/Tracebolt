package api

import (
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"time"
)

type windowsMaintenanceScheduleTargetView struct {
	Key             string                                   `json:"key"`
	DeviceID        string                                   `json:"deviceId"`
	Domain          string                                   `json:"domain"`
	Revision        uint64                                   `json:"revision"`
	ChangedAt       *time.Time                               `json:"changedAt"`
	RetiredWindows  uint64                                   `json:"retiredWindows"`
	RemainingSlots  int                                      `json:"remainingSlots"`
	ImmediateActive bool                                     `json:"immediateActive"`
	Windows         []store.WindowsMaintenanceScheduleWindow `json:"windows"`
}
type windowsMaintenanceScheduleView struct {
	SchemaVersion      string                                 `json:"schemaVersion"`
	ServerNow          time.Time                              `json:"serverNow"`
	AuthorityExpiresAt time.Time                              `json:"authorityExpiresAt"`
	Targets            []windowsMaintenanceScheduleTargetView `json:"targets"`
}

func projectWindowsMaintenanceSchedules(states []store.WindowsMaintenanceScheduleState, immediate []store.WindowsMaintenanceState, authority map[string]windowscapacity.Input, now time.Time) (windowsMaintenanceScheduleView, error) {
	base, e := projectWindowsMaintenance(immediate, authority, now)
	v := windowsMaintenanceScheduleView{SchemaVersion: "tracebolt.windows-maintenance-schedule.v1", ServerNow: now, AuthorityExpiresAt: base.AuthorityExpiresAt, Targets: []windowsMaintenanceScheduleTargetView{}}
	if e != nil {
		return v, e
	}
	byKey := map[string]store.WindowsMaintenanceScheduleState{}
	for _, s := range states {
		byKey[s.Target.Key()] = s
	}
	for _, target := range base.Targets {
		row := windowsMaintenanceScheduleTargetView{Key: target.Key, DeviceID: target.DeviceID, Domain: target.Domain, RemainingSlots: store.MaxWindowsMaintenanceSchedules, Windows: []store.WindowsMaintenanceScheduleWindow{}}
		for _, other := range base.Targets {
			if other.DeviceID == target.DeviceID && (other.Domain == "all" || target.Domain == "all" || other.Domain == target.Domain) && len(other.Windows) > 0 && other.Windows[0].Active(now) {
				row.ImmediateActive = true
			}
		}
		if s, ok := byKey[target.Key]; ok {
			if now.Before(s.ObservedAt) {
				return v, store.ErrWindowsMaintenanceConflict
			}
			row.RetiredWindows = s.RetiredWindows
			row.Revision = s.Revision
			row.ChangedAt = inboxStamp(s.ChangedAt)
			row.Windows = s.Windows
			if len(row.Windows) > 4 {
				row.Windows = row.Windows[:4]
			}
			row.RemainingSlots -= len(s.Windows)
		}
		v.Targets = append(v.Targets, row)
	}
	return v, nil
}
