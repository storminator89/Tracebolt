package packageupdate

import (
	"context"
	"time"
)

type View struct {
	SchemaVersion string       `json:"schemaVersion"`
	DeviceID      string       `json:"deviceId"`
	ServerNow     time.Time    `json:"serverNow"`
	ExecutionMode string       `json:"executionMode"`
	Available     bool         `json:"available"`
	Reason        string       `json:"reason"`
	Preview       *PreviewView `json:"preview"`
	Job           *JobView     `json:"job"`
}
type PreviewItem struct {
	Name          string `json:"name"`
	Architecture  string `json:"architecture"`
	FromVersion   string `json:"fromVersion"`
	ToVersion     string `json:"toVersion"`
	SourcePackage string `json:"sourcePackage"`
	SourceVersion string `json:"sourceVersion"`
	SourceLabel   string `json:"sourceLabel"`
	Suite         string `json:"suite"`
	Component     string `json:"component"`
	ArchiveSHA256 string `json:"archiveSHA256"`
}
type PreviewView struct {
	RequestID        string        `json:"requestId"`
	Digest           string        `json:"digest"`
	ActorID          string        `json:"actorId"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	TransportProfile string        `json:"transportProfile"`
	ConffilePolicy   string        `json:"conffilePolicy"`
	TotalBytes       uint64        `json:"totalBytes"`
	Items            []PreviewItem `json:"items"`
}
type JobView struct {
	RequestID  string      `json:"requestId"`
	State      string      `json:"state"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	ApprovedAt *time.Time  `json:"approvedAt"`
	Result     *ResultView `json:"result"`
}
type RebootView struct {
	State      string    `json:"state"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observedAt"`
}
type ResultView struct {
	Phase      string          `json:"phase"`
	ObservedAt time.Time       `json:"observedAt"`
	Packages   []PackageResult `json:"packages"`
	Reboot     RebootView      `json:"reboot"`
	Reason     string          `json:"reason"`
}

func stamp(t int64) time.Time { return time.Unix(t, 0).UTC() }
func unavailableView(device string, now time.Time) View {
	return View{SchemaVersion: ViewVersion, DeviceID: device, ServerNow: now, ExecutionMode: "unavailable", Reason: "native_adapter_unavailable"}
}
func projectView(r Record, now time.Time) View {
	v := View{SchemaVersion: ViewVersion, DeviceID: r.Binding.DeviceID, ServerNow: now, ExecutionMode: r.Mode, Available: r.RevokedAt == 0 && len(r.Jobs) < MaxJobs, Reason: "simulation_only"}
	if r.Mode == "native" {
		v.Reason = "ready"
	}
	if len(r.Jobs) == 0 {
		return v
	}
	j := r.Jobs[len(r.Jobs)-1]
	v.Job = &JobView{RequestID: j.Request.RequestID, State: j.State, CreatedAt: stamp(j.CreatedAt), UpdatedAt: stamp(j.UpdatedAt)}
	if j.ApprovedAt != 0 {
		t := stamp(j.ApprovedAt)
		v.Job.ApprovedAt = &t
	}
	if !terminal(j) {
		v.Available = false
	}
	if j.State == Preparing || j.State == Approved || j.State == Applying || j.State == Verifying {
		v.Reason = "operation_in_progress"
	}
	if j.State == DeliveryUnknown || j.State == NeedsIntervention {
		v.Reason = "needs_intervention"
	}
	if j.Preview != nil {
		p := j.Preview
		v.Preview = &PreviewView{RequestID: p.RequestID, Digest: p.Digest, ActorID: p.ActorID, ExpiresAt: stamp(p.Plan.ExpiresAt), TransportProfile: p.Binding.TransportProfile, ConffilePolicy: p.ConffilePolicy, Items: []PreviewItem{}}
		sources := map[string]Source{}
		for _, s := range p.Sources {
			sources[s.IdentityDigest] = s
		}
		for _, u := range p.Plan.Packages {
			s := sources[u.Archive.SourceIdentityDigest]
			v.Preview.TotalBytes += u.Archive.Size
			v.Preview.Items = append(v.Preview.Items, PreviewItem{u.Name, u.Architecture, u.From.Version, u.To.Version, u.To.SourcePackage, u.To.SourceVersion, s.Label, s.Suite, s.Component, u.Archive.SHA256})
		}
	}
	if len(j.Results) > 0 {
		r := j.Results[len(j.Results)-1]
		v.Job.Result = &ResultView{r.Phase, stamp(r.ObservedAt), append([]PackageResult(nil), r.Packages...), RebootView{r.Reboot.State, r.Reboot.Source, stamp(r.Reboot.ObservedAt)}, r.Reason}
	}
	return v
}

// Project validates a saved snapshot before returning its read-only projection.
func Project(ctx context.Context, r Record, now time.Time) (View, error) {
	if e := Validate(ctx, r); e != nil {
		return View{}, e
	}
	if now.Location() != time.UTC || now.Unix() < r.ClockFloor {
		return View{}, ErrInvalid
	}
	return projectView(r, now), nil
}
