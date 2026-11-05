package health

import (
	"reflect"
	"regexp"
	"time"
)

const MaxMaintenanceWindows = 64

var maintenanceID = regexp.MustCompile(`^maintenance_[a-f0-9]{32}$`)

type MaintenanceCommand struct {
	RequestID        string     `json:"requestId"`
	ExpectedRevision uint64     `json:"expectedRevision,string"`
	Action           string     `json:"action"`
	WindowID         string     `json:"windowId"`
	StartsAt         *time.Time `json:"startsAt"`
	EndsAt           *time.Time `json:"endsAt"`
}
type MaintenanceWindow struct {
	ID              string     `json:"id"`
	CreatedAt       time.Time  `json:"createdAt"`
	StartsAt        time.Time  `json:"startsAt"`
	EndsAt          time.Time  `json:"endsAt"`
	ClosedAt        *time.Time `json:"closedAt"`
	ClosedRequestID string     `json:"closedRequestId"`
	ClosedReason    string     `json:"closedReason"`
}
type MaintenanceSchedule struct {
	Revision    uint64              `json:"revision,string"`
	ClockFloor  time.Time           `json:"clockFloor"`
	Windows     []MaintenanceWindow `json:"windows"`
	LastCommand MaintenanceCommand  `json:"lastCommand"`
}

func maintenanceTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999
}
func validMaintenanceID(id string) bool {
	return maintenanceID.MatchString(id) && id != "maintenance_00000000000000000000000000000000"
}
func maintenanceDuration(a, b time.Time) bool {
	d := b.Sub(a)
	return d == 15*time.Minute || d == time.Hour || d == 4*time.Hour
}
func (m *MaintenanceSchedule) validate() error {
	if m == nil || m.Revision == 0 || !maintenanceTime(m.ClockFloor) || len(m.Windows) == 0 || len(m.Windows) > MaxMaintenanceWindows {
		return ErrInvalid
	}
	seen := map[string]bool{}
	commands := uint64(len(m.Windows))
	for i, w := range m.Windows {
		if !validMaintenanceID(w.ID) || seen[w.ID] || !maintenanceTime(w.CreatedAt) || !maintenanceTime(w.StartsAt) || !maintenanceTime(w.EndsAt) || w.StartsAt.Nanosecond() != 0 || w.EndsAt.Nanosecond() != 0 || w.StartsAt.Sub(w.CreatedAt) < time.Minute || w.StartsAt.Sub(w.CreatedAt) > 7*24*time.Hour || !maintenanceDuration(w.StartsAt, w.EndsAt) || w.CreatedAt.After(m.ClockFloor) {
			return ErrInvalid
		}
		seen[w.ID] = true
		if w.ClosedRequestID != "" {
			commands++
			if !validMaintenanceID(w.ClosedRequestID) || seen[w.ClosedRequestID] {
				return ErrInvalid
			}
			seen[w.ClosedRequestID] = true
		}
		if w.ClosedAt == nil {
			if w.ClosedReason != "" || w.ClosedRequestID != "" || i != len(m.Windows)-1 {
				return ErrInvalid
			}
		} else {
			if !maintenanceTime(*w.ClosedAt) || w.ClosedAt.Before(w.CreatedAt) || w.ClosedAt.After(m.ClockFloor) {
				return ErrInvalid
			}
			switch w.ClosedReason {
			case "canceled":
				if w.ClosedRequestID == "" {
					return ErrInvalid
				}
				if !w.ClosedAt.Before(w.StartsAt) {
					return ErrInvalid
				}
			case "ended":
				if w.ClosedRequestID == "" {
					return ErrInvalid
				}
				if w.ClosedAt.Before(w.StartsAt) || !w.ClosedAt.Before(w.EndsAt) {
					return ErrInvalid
				}
			case "expired":
				if w.ClosedRequestID != "" {
					return ErrInvalid
				}
				if !w.ClosedAt.Equal(w.EndsAt) {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		if i > 0 {
			p := m.Windows[i-1]
			if p.ClosedAt == nil || w.CreatedAt.Before(*p.ClosedAt) {
				return ErrInvalid
			}
		}
	}
	if commands != m.Revision {
		return ErrInvalid
	}
	c := m.LastCommand
	if !validMaintenanceID(c.RequestID) || !validMaintenanceID(c.WindowID) || c.ExpectedRevision != m.Revision-1 {
		return ErrInvalid
	}
	found := false
	for _, w := range m.Windows {
		if w.ID == c.WindowID {
			found = true
		}
	}
	if !found {
		return ErrInvalid
	}
	switch c.Action {
	case "schedule":
		if c.RequestID != c.WindowID || c.StartsAt == nil || c.EndsAt == nil || !maintenanceTime(*c.StartsAt) || !maintenanceTime(*c.EndsAt) {
			return ErrInvalid
		}
		w := m.Windows[len(m.Windows)-1]
		if w.ID != c.WindowID || !c.StartsAt.Equal(w.StartsAt) || !c.EndsAt.Equal(w.EndsAt) {
			return ErrInvalid
		}
	case "cancel", "end":
		if c.StartsAt != nil || c.EndsAt != nil {
			return ErrInvalid
		}
		w := m.Windows[len(m.Windows)-1]
		reason := "canceled"
		if c.Action == "end" {
			reason = "ended"
		}
		if w.ID != c.WindowID || w.ClosedReason != reason || w.ClosedRequestID != c.RequestID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (s State) MaintenanceClockValid(now time.Time) bool {
	now = now.UTC()
	return maintenanceTime(now) && (s.EvaluatedAt == nil || !now.Before(*s.EvaluatedAt)) && (s.Schedule == nil || !now.Before(s.Schedule.ClockFloor))
}

// ObserveMaintenance persists a high-water mark at every feature-aware read or
// effect admission. Expiry is terminal at the ORIGINAL end, never a new window.
func (s *State) ObserveMaintenance(now time.Time) error {
	now = now.UTC()
	if !s.MaintenanceClockValid(now) {
		return ErrInvalid
	}
	if s.Schedule == nil {
		return nil
	}
	m := *s.Schedule
	m.Windows = append([]MaintenanceWindow(nil), m.Windows...)
	m.ClockFloor = now
	for i := range m.Windows {
		w := &m.Windows[i]
		if w.ClosedAt == nil && !now.Before(w.EndsAt) {
			w.ClosedAt = stamp(w.EndsAt)
			w.ClosedReason = "expired"
		}
	}
	s.Schedule = &m
	return nil
}
func (w MaintenanceWindow) Status(now time.Time) string {
	if w.ClosedAt != nil {
		return w.ClosedReason
	}
	if !now.Before(w.EndsAt) {
		return "expired"
	}
	if now.Before(w.StartsAt) {
		return "pending"
	}
	return "active"
}
func (s State) MaintenanceEnd(now time.Time) *time.Time {
	// A rollback cannot reactivate a previously observed expired window.
	if s.Schedule != nil && now.Before(s.Schedule.ClockFloor) {
		now = s.Schedule.ClockFloor
	}
	var end *time.Time
	if s.MaintenanceUntil != nil && now.Before(*s.MaintenanceUntil) {
		end = stamp(*s.MaintenanceUntil)
	}
	if s.Schedule != nil {
		for _, w := range s.Schedule.Windows {
			if w.Status(now) == "active" && (end == nil || w.EndsAt.After(*end)) {
				end = stamp(w.EndsAt)
			}
		}
	}
	return end
}

// ScheduledOpeningSuppressed also consumes queued/retry openings whose due time
// falls AFTER a window. In-flight outcomes remain untouched. Tombstones are never
// pruned, so a late retry cannot escape a replaced or early-ended original window.
func (s State) ScheduledOpeningSuppressed(created, now time.Time) bool {
	if s.Schedule == nil {
		return false
	}
	if now.Before(s.Schedule.ClockFloor) {
		now = s.Schedule.ClockFloor
	}
	for _, w := range s.Schedule.Windows {
		if now.Before(w.StartsAt) || w.ClosedReason == "canceled" {
			continue
		}
		end := w.EndsAt
		if w.ClosedAt != nil && w.ClosedAt.Before(end) {
			end = *w.ClosedAt
		}
		if end.After(w.StartsAt) && created.Before(end) {
			return true
		}
	}
	return false
}
func (s *State) ApplyMaintenance(c MaintenanceCommand, now time.Time) error {
	now = now.UTC()
	if s.Validate() != nil || !s.MaintenanceClockValid(now) || !validMaintenanceID(c.RequestID) || !validMaintenanceID(c.WindowID) {
		return ErrInvalid
	}
	if s.Schedule != nil && s.Schedule.LastCommand.RequestID == c.RequestID {
		if reflect.DeepEqual(s.Schedule.LastCommand, c) {
			return s.ObserveMaintenance(now)
		}
		return ErrInvalid
	}
	if s.Schedule != nil {
		for _, w := range s.Schedule.Windows {
			if w.ID == c.RequestID || w.ClosedRequestID == c.RequestID {
				return ErrInvalid
			}
		}
	}
	revision := uint64(0)
	if s.Schedule != nil {
		revision = s.Schedule.Revision
	}
	if c.ExpectedRevision != revision || revision == ^uint64(0) {
		return ErrInvalid
	}
	// Copy-on-write keeps failed callbacks and the pre-write transaction projection intact.
	m := MaintenanceSchedule{Windows: []MaintenanceWindow{}}
	if s.Schedule != nil {
		m = *s.Schedule
		m.Windows = append([]MaintenanceWindow(nil), m.Windows...)
	}
	next := *s
	next.Schedule = &m
	if s.Schedule != nil {
		if err := next.ObserveMaintenance(now); err != nil {
			return err
		}
		m = *next.Schedule
	}
	switch c.Action {
	case "schedule":
		if c.RequestID != c.WindowID || c.StartsAt == nil || c.EndsAt == nil || !maintenanceTime(*c.StartsAt) || !maintenanceTime(*c.EndsAt) || c.StartsAt.Nanosecond() != 0 || c.EndsAt.Nanosecond() != 0 || c.StartsAt.Sub(now) < time.Minute || c.StartsAt.Sub(now) > 7*24*time.Hour || !maintenanceDuration(*c.StartsAt, *c.EndsAt) || len(m.Windows) >= MaxMaintenanceWindows || s.MaintenanceUntil != nil && now.Before(*s.MaintenanceUntil) {
			return ErrInvalid
		}
		for _, w := range m.Windows {
			if w.ID == c.WindowID || w.ClosedAt == nil {
				return ErrInvalid
			}
		}
		m.Windows = append(m.Windows, MaintenanceWindow{ID: c.WindowID, CreatedAt: now, StartsAt: *c.StartsAt, EndsAt: *c.EndsAt})
	case "cancel", "end":
		if c.StartsAt != nil || c.EndsAt != nil || len(m.Windows) == 0 {
			return ErrInvalid
		}
		w := &m.Windows[len(m.Windows)-1]
		want := "pending"
		reason := "canceled"
		if c.Action == "end" {
			want = "active"
			reason = "ended"
		}
		if w.ID != c.WindowID || w.Status(now) != want {
			return ErrInvalid
		}
		w.ClosedAt = stamp(now)
		w.ClosedRequestID = c.RequestID
		w.ClosedReason = reason
	default:
		return ErrInvalid
	}
	m.Revision++
	m.ClockFloor = now
	m.LastCommand = c
	if c.StartsAt != nil {
		m.LastCommand.StartsAt = stamp(*c.StartsAt)
	}
	if c.EndsAt != nil {
		m.LastCommand.EndsAt = stamp(*c.EndsAt)
	}
	next.Version = 2
	next.Schedule = &m
	if next.Validate() != nil {
		return ErrInvalid
	}
	*s = next
	return nil
}
