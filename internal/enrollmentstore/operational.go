package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/operational"
	"time"
)

var ErrOperationalBusy = errors.New("operational read admission is busy")

const operationalSchema = `CREATE TABLE enrollment_operational(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072)) STRICT`
const OperationalDeviceQuota = 128 << 10
const OperationalGlobalQuota = 4 << 20
const OperationalRetention = 24 * time.Hour

// LastGood preserves each section's original generation/time. It is a bounded
// cache of successfully collected metadata, not a synthetic merged snapshot.
type LastGood struct {
	Volumes   *operational.VolumeSection   `json:"volumes"`
	Network   *operational.NetworkSection  `json:"network"`
	Services  *operational.ServiceSection  `json:"services"`
	Processes *operational.ProcessSection  `json:"processes"`
	Software  *operational.SoftwareSection `json:"software"`
	Events    *operational.EventSection    `json:"events"`
}
type operationalRecord struct {
	LastGood LastGood `json:"lastGood"`
}

func (s *Store) loadOperational(ctx context.Context, t *transaction) error {
	if !enrollmentcrypto.ManagedCollectionProfile(s.config.Binding.CollectionProfile) {
		return nil
	}
	var count, total, max int
	if t.conn.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(body)),0),coalesce(max(length(body)),0) FROM enrollment_operational").Scan(&count, &total, &max) != nil || count > s.config.RecordLimit || total > OperationalGlobalQuota || max > OperationalDeviceQuota {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, "SELECT invitation_id,body FROM enrollment_operational ORDER BY invitation_id")
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if rows.Scan(&id, &raw) != nil || len(raw) == 0 || len(raw) > OperationalDeviceQuota {
			return ErrStorage
		}
		var record operationalRecord
		if json.Unmarshal(raw, &record) != nil {
			return ErrStorage
		}
		canonical, e := json.Marshal(record)
		if e != nil || !bytes.Equal(canonical, raw) {
			return ErrStorage
		}
		t.operational[id] = record
		t.originalOperational[id] = raw
	}
	if rows.Err() != nil {
		return ErrStorage
	}
	return s.validateOperational(t)
}
func (s *Store) validateOperational(t *transaction) error {
	if !enrollmentcrypto.ManagedCollectionProfile(s.config.Binding.CollectionProfile) {
		if len(t.operational) != 0 {
			return ErrStorage
		}
		return nil
	}
	total := 0
	for id, c := range t.credentials {
		record, exists := t.operational[id]
		if len(c.Frame) == 0 {
			if exists {
				return ErrStorage
			}
			continue
		}
		if !exists {
			return ErrStorage
		}
		frame, e := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
		if e != nil || frame.Operational == nil {
			return ErrStorage
		}
		snap, _ := json.Marshal(frame.Operational)
		cached, _ := json.Marshal(record)
		packageBytes := 0
		if frame.Packages != nil {
			packages, e := json.Marshal(frame.Packages)
			if e != nil {
				return ErrStorage
			}
			packageBytes = len(packages)
		}
		if len(snap)+len(cached)+packageBytes > OperationalDeviceQuota || validateLastGood(record.LastGood, frame.Operational.CollectedAt) != nil {
			return ErrStorage
		}
		total += len(snap) + len(cached) + packageBytes
	}
	for id := range t.operational {
		if _, exists := t.credentials[id]; !exists {
			return ErrStorage
		}
	}
	if total > OperationalGlobalQuota {
		return ErrStorage
	}
	return nil
}
func (s *Store) saveOperational(ctx context.Context, t *transaction) error {
	if s.validateOperational(t) != nil {
		return ErrStorage
	}
	for id, record := range t.operational {
		raw, e := json.Marshal(record)
		if e != nil || len(raw) > OperationalDeviceQuota {
			return ErrStorage
		}
		if bytes.Equal(raw, t.originalOperational[id]) {
			continue
		}
		if _, e = t.conn.ExecContext(ctx, "INSERT INTO enrollment_operational(invitation_id,body) VALUES(?,?) ON CONFLICT(invitation_id) DO UPDATE SET body=excluded.body", id, raw); e != nil {
			return ErrStorage
		}
	}
	return nil
}
func validRetained(meta operational.SectionMeta, at time.Time) bool {
	return meta.Quality == operational.Healthy && !meta.ObservedAt.After(at)
}
func validateLastGood(g LastGood, at time.Time) error {
	if g.Volumes != nil && (!validRetained(g.Volumes.Meta, at) || operational.ValidateVolumeSection(*g.Volumes) != nil) {
		return ErrStorage
	}
	if g.Network != nil && (!validRetained(g.Network.Meta, at) || operational.ValidateNetworkSection(*g.Network) != nil) {
		return ErrStorage
	}
	if g.Services != nil && (!validRetained(g.Services.Meta, at) || operational.ValidateServiceSection(*g.Services) != nil) {
		return ErrStorage
	}
	if g.Processes != nil && (!validRetained(g.Processes.Meta, at) || operational.ValidateProcessSection(*g.Processes) != nil) {
		return ErrStorage
	}
	if g.Software != nil && (!validRetained(g.Software.Meta, at) || operational.ValidateSoftwareSection(*g.Software) != nil) {
		return ErrStorage
	}
	if g.Events != nil && (!validRetained(g.Events.Meta, at) || operational.ValidateEventSection(*g.Events) != nil) {
		return ErrStorage
	}
	return nil
}
func (t *transaction) pruneOperational(now time.Time) {
	for id, record := range t.operational {
		g := &record.LastGood
		expired := func(m operational.SectionMeta) bool { return !m.ObservedAt.Add(OperationalRetention).After(now) }
		if g.Volumes != nil && expired(g.Volumes.Meta) {
			g.Volumes = nil
		}
		if g.Network != nil && expired(g.Network.Meta) {
			g.Network = nil
		}
		if g.Services != nil && expired(g.Services.Meta) {
			g.Services = nil
		}
		if g.Processes != nil && expired(g.Processes.Meta) {
			g.Processes = nil
		}
		if g.Software != nil && expired(g.Software.Meta) {
			g.Software = nil
		}
		if g.Events != nil && expired(g.Events.Meta) {
			g.Events = nil
		}
		t.operational[id] = record
	}
}
func (t *transaction) retainOperational(id string, snapshot *operational.Snapshot) {
	record := t.operational[id]
	g := &record.LastGood
	s := snapshot.Sections
	if s.Volumes.Meta.Quality == operational.Healthy {
		g.Volumes = &s.Volumes
	}
	if s.Network.Meta.Quality == operational.Healthy {
		g.Network = &s.Network
	}
	if s.Services.Meta.Quality == operational.Healthy {
		g.Services = &s.Services
	}
	if s.Processes.Meta.Quality == operational.Healthy {
		g.Processes = &s.Processes
	}
	if s.Software.Meta.Quality == operational.Healthy {
		g.Software = &s.Software
	}
	if s.Events.Meta.Quality == operational.Healthy {
		g.Events = &s.Events
	}
	t.operational[id] = record
}

type AssessmentCoverage struct {
	Quality string `json:"quality"`
	Reason  string `json:"reason"`
}
type AssessmentStates struct {
	Updates         AssessmentCoverage `json:"updates"`
	Vulnerabilities AssessmentCoverage `json:"vulnerabilities"`
}
type OperationalView struct {
	SchemaVersion string                `json:"schemaVersion"`
	DeviceID      string                `json:"deviceId"`
	Status        string                `json:"status"`
	ServerNow     time.Time             `json:"serverNow"`
	ReceivedAt    *time.Time            `json:"receivedAt"`
	Sequence      *uint64               `json:"sequence"`
	MaxAgeSeconds int64                 `json:"maxAgeSeconds"`
	Snapshot      *operational.Snapshot `json:"snapshot"`
	LastGood      LastGood              `json:"lastGood"`
	Assessments   AssessmentStates      `json:"assessments"`
}

func EmptyOperationalView(id string, now time.Time) OperationalView {
	unknown := AssessmentCoverage{"unknown", "not_implemented"}
	return OperationalView{SchemaVersion: "tracebolt.operational-view.v1", DeviceID: id, Status: "not_configured", ServerNow: now.UTC(), MaxAgeSeconds: int64(lanstore.SampleMaxAge / time.Second), Assessments: AssessmentStates{unknown, unknown}}
}
func (s *Store) OperationalView(ctx context.Context, id string, now time.Time) (OperationalView, error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return OperationalView{}, ErrStorage
	}
	if ctx.Err() != nil {
		return OperationalView{}, ctx.Err()
	}
	select {
	case s.operationalReads <- struct{}{}:
		defer func() { <-s.operationalReads }()
	default:
		return OperationalView{}, ErrOperationalBusy
	}
	if !validStoreTime(now) {
		return OperationalView{}, enrollmentstate.ErrInvalid
	}
	out := EmptyOperationalView(id, now)
	err := s.transact(ctx, func(t *transaction) error {
		t.pruneOperational(now)
		var snapshot enrollmentstate.Snapshot
		found := false
		for _, entry := range t.engine.Snapshots() {
			if entry.Approval.DeviceID == id {
				snapshot = entry
				found = true
				break
			}
		}
		if !found {
			return enrollmentstate.ErrNotFound
		}
		if !enrollmentcrypto.ManagedCollectionProfile(snapshot.Binding.CollectionProfile) {
			return nil
		}
		out.Status = "awaiting"
		c, ok := t.credentials[snapshot.InvitationID]
		if ok && len(c.Frame) > 0 {
			frame, e := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
			if e != nil || frame.Operational == nil {
				return ErrStorage
			}
			seq := c.Replay.Sequence
			received := c.Replay.ReceivedAt
			out.Sequence = &seq
			out.ReceivedAt = &received
			out.Status = "fresh"
			copy := *frame.Operational
			out.Snapshot = &copy
			if now.Before(received) || now.Before(copy.CollectedAt) || now.Sub(received) > lanstore.SampleMaxAge || now.Sub(copy.CollectedAt) > lanstore.SampleMaxAge {
				out.Status = "stale"
				ageSnapshot(&copy)
			}
			if now.Sub(copy.CollectedAt) >= OperationalRetention {
				out.Status = "unavailable"
				out.Snapshot = nil
			}
			out.LastGood = agedLastGood(t.operational[snapshot.InvitationID].LastGood)
		}
		if snapshot.State == enrollmentstate.Revoked || snapshot.State == enrollmentstate.Canceled || snapshot.State == enrollmentstate.Rejected || snapshot.State == enrollmentstate.Expired || snapshot.Intent.NotAfter > 0 && now.Unix() >= snapshot.Intent.NotAfter {
			out.Status = "revoked"
			if out.Snapshot != nil {
				ageSnapshot(out.Snapshot)
			}
		}
		return nil
	})
	if err != nil {
		return OperationalView{}, err
	}
	return out, nil
}
func ageSnapshot(s *operational.Snapshot) {
	for _, m := range []*operational.SectionMeta{&s.Sections.Volumes.Meta, &s.Sections.Network.Meta, &s.Sections.Services.Meta, &s.Sections.Processes.Meta, &s.Sections.Software.Meta, &s.Sections.Events.Meta} {
		if m.Quality == operational.Healthy {
			m.Quality = "stale"
		}
	}
}

func agedLastGood(in LastGood) LastGood {
	out := in
	if in.Volumes != nil {
		v := *in.Volumes
		v.Meta.Quality = "stale"
		out.Volumes = &v
	}
	if in.Network != nil {
		v := *in.Network
		v.Meta.Quality = "stale"
		out.Network = &v
	}
	if in.Services != nil {
		v := *in.Services
		v.Meta.Quality = "stale"
		out.Services = &v
	}
	if in.Processes != nil {
		v := *in.Processes
		v.Meta.Quality = "stale"
		out.Processes = &v
	}
	if in.Software != nil {
		v := *in.Software
		v.Meta.Quality = "stale"
		out.Software = &v
	}
	if in.Events != nil {
		v := *in.Events
		v.Meta.Quality = "stale"
		out.Events = &v
	}
	return out
}
