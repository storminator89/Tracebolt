package packageupdate

import (
	"bytes"
	"context"
	"encoding/json"
)

// Result is a structured observation bound to the persisted execution mode.
// Native observations enter through the authenticated enrolled endpoint path.
type PackageResult struct {
	Name            string  `json:"name"`
	Architecture    string  `json:"architecture"`
	ExpectedVersion string  `json:"expectedVersion"`
	ObservedVersion *string `json:"observedVersion"`
	Outcome         string  `json:"outcome"`
}
type RebootEvidence struct {
	State      string `json:"state"`
	Source     string `json:"source"`
	ObservedAt int64  `json:"observedAt"`
}
type Result struct {
	Sequence   uint64          `json:"sequence,string"`
	Phase      string          `json:"phase"`
	ObservedAt int64           `json:"observedAt"`
	Packages   []PackageResult `json:"packages"`
	Reboot     RebootEvidence  `json:"reboot"`
	DpkgState  string          `json:"dpkgState"`
	Reason     string          `json:"reason"`
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func resultStep(from, to string) bool {
	switch from {
	case DeliveryUnknown:
		return to == Applying || to == NeedsIntervention
	case Applying:
		return to == Verifying || to == NeedsIntervention
	case Verifying:
		return to == Succeeded || to == NeedsIntervention
	}
	return false
}
func validateResults(j Job, mode string) error {
	if len(j.Results) > MaxResults || len(j.Results) > 0 && (j.Preview == nil || j.ClaimedAt == 0) {
		return ErrInvalid
	}
	phase := DeliveryUnknown
	observed := j.ClaimedAt
	for i, r := range j.Results {
		if r.Sequence != uint64(i+1) || !resultStep(phase, r.Phase) || !validTime(r.ObservedAt) || r.ObservedAt < observed || r.ObservedAt > j.UpdatedAt || r.Reboot.Source != mode || r.Reboot.ObservedAt != r.ObservedAt || (r.Reboot.State != "required" && r.Reboot.State != "not_reported" && r.Reboot.State != "unknown") || (r.DpkgState != "clean" && r.DpkgState != "unknown") || len(r.Packages) != len(j.Preview.Plan.Packages) {
			return ErrInvalid
		}
		if r.Phase == Succeeded && (r.DpkgState != "clean" || r.Reason != map[string]string{"simulation": "simulated_verified", "native": "native_verified"}[mode]) {
			return ErrInvalid
		}
		if (r.Phase == Applying || r.Phase == Verifying) && (r.Reason != map[string]string{"simulation": "simulated_running", "native": "native_running"}[mode] || r.DpkgState != "unknown" || r.Reboot.State != "unknown") {
			return ErrInvalid
		}
		if r.Phase == NeedsIntervention && r.Reason != "runner_state_unknown" && r.Reason != "verification_mismatch" {
			return ErrInvalid
		}
		for k, p := range r.Packages {
			wanted := j.Preview.Plan.Packages[k]
			if p.Name != wanted.Name || p.Architecture != wanted.Architecture || p.ExpectedVersion != wanted.To.Version {
				return ErrInvalid
			}
			switch p.Outcome {
			case "verified":
				if p.ObservedVersion == nil || *p.ObservedVersion != p.ExpectedVersion {
					return ErrInvalid
				}
			case "mismatch":
				if p.ObservedVersion == nil || *p.ObservedVersion == p.ExpectedVersion || len(*p.ObservedVersion) > 1024 || *p.ObservedVersion == "" {
					return ErrInvalid
				}
			case "unknown":
				if p.ObservedVersion != nil {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
			if r.Phase == Succeeded && p.Outcome != "verified" {
				return ErrInvalid
			}
		}
		phase = r.Phase
		observed = r.ObservedAt
	}
	return nil
}

// ObserveResult preserves exact prefixes and refuses changed/reordered evidence.
// Expiry and revocation cannot kill or fabricate the result of a claimed job.
func ObserveResult(ctx context.Context, r Record, id, digest string, result Result, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	for i := range out.Jobs {
		j := &out.Jobs[i]
		if j.Request.RequestID != id {
			continue
		}
		if j.Preview == nil || j.Preview.Digest != digest || j.ClaimedAt == 0 {
			return Record{}, ErrConflict
		}
		if result.Sequence > 0 && result.Sequence <= uint64(len(j.Results)) {
			if equalJSON(result, j.Results[result.Sequence-1]) {
				return out, nil
			}
			return Record{}, ErrConflict
		}
		if !resultStep(j.State, result.Phase) || result.Sequence != uint64(len(j.Results)+1) {
			return Record{}, ErrConflict
		}
		raw, _ := json.Marshal(result)
		var owned Result
		_ = json.Unmarshal(raw, &owned)
		j.Results = append(j.Results, owned)
		j.State = owned.Phase
		j.UpdatedAt = now
		return out, Validate(ctx, out)
	}
	return Record{}, ErrConflict
}
func FailPreparation(ctx context.Context, r Record, id string, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if len(out.Jobs) == 0 {
		return Record{}, ErrConflict
	}
	j := &out.Jobs[len(out.Jobs)-1]
	if j.Request.RequestID != id || j.State != Preparing {
		return Record{}, ErrConflict
	}
	j.State = PreparationFailed
	j.UpdatedAt = now
	return out, Validate(ctx, out)
}

// ValidateSuccessor is the SQLite CAS history boundary. A valid standalone
// snapshot is insufficient: previous immutable bytes and monotonic floors must
// survive. One committed revision is exactly one semantic transition/observation.
func ValidateSuccessor(ctx context.Context, old, next Record) error {
	if Validate(ctx, old) != nil || Validate(ctx, next) != nil || old.Binding != next.Binding || old.Mode != next.Mode || !bytes.Equal(old.PublicKey, next.PublicKey) || old.Revision == ^uint64(0) || next.Revision != old.Revision+1 || next.ClockFloor < old.ClockFloor || len(next.Jobs) < len(old.Jobs) || len(next.Jobs) > len(old.Jobs)+1 || old.RevokedAt != 0 && next.RevokedAt != old.RevokedAt {
		return ErrConflict
	}
	if old.RevokedAt == 0 && next.RevokedAt != 0 && next.RevokedAt != next.ClockFloor {
		return ErrConflict
	}
	for i, a := range old.Jobs {
		b := next.Jobs[i]
		if a.Sequence != b.Sequence || !bytes.Equal(a.PreparationEnvelope, b.PreparationEnvelope) || a.PreparationClaimedAt != 0 && a.PreparationClaimedAt != b.PreparationClaimedAt || len(a.ExecutionEnvelope) > 0 && !bytes.Equal(a.ExecutionEnvelope, b.ExecutionEnvelope) || !equalJSON(a.Request, b.Request) || a.ActorID != b.ActorID || a.CreatedAt != b.CreatedAt || b.UpdatedAt < a.UpdatedAt || a.Preview != nil && !equalJSON(a.Preview, b.Preview) || a.ApprovedAt != 0 && a.ApprovedAt != b.ApprovedAt || a.ClaimedAt != 0 && a.ClaimedAt != b.ClaimedAt || len(b.Results) < len(a.Results) || len(b.Results) > len(a.Results)+1 {
			return ErrConflict
		}
		for k, result := range a.Results {
			if !equalJSON(result, b.Results[k]) {
				return ErrConflict
			}
		}
		if terminal(a) && !equalJSON(a, b) {
			return ErrConflict
		}
		if a.State != b.State {
			allowed := false
			switch a.State {
			case Preparing:
				allowed = b.State == PreviewReady || b.State == PreparationFailed || b.State == Revoked || old.Mode == "native" && (b.State == NeedsIntervention || b.State == Expired)
			case PreviewReady:
				allowed = b.State == Approved || b.State == Expired || b.State == Revoked || old.Mode == "native" && b.State == NeedsIntervention
			case Approved:
				allowed = b.State == DeliveryUnknown || b.State == Expired || b.State == Revoked
			case DeliveryUnknown, Applying, Verifying:
				allowed = resultStep(a.State, b.State)
			}
			if !allowed {
				return ErrConflict
			}
		} else if !equalJSON(a, b) {
			x := b
			if old.Mode == "native" && a.State == Preparing && a.PreparationClaimedAt == 0 && b.PreparationClaimedAt == next.ClockFloor {
				x.PreparationClaimedAt = 0
				x.UpdatedAt = a.UpdatedAt
			}
			if !equalJSON(a, x) {
				return ErrConflict
			}
		}
		if a.PreparationClaimedAt == 0 && b.PreparationClaimedAt != 0 && (old.Mode != "native" || a.State != Preparing || b.State != Preparing || b.PreparationClaimedAt != next.ClockFloor) {
			return ErrConflict
		}
		if len(a.ExecutionEnvelope) == 0 && len(b.ExecutionEnvelope) > 0 && (old.Mode != "native" || a.State != PreviewReady || b.State != Approved) {
			return ErrConflict
		}
		if a.Preview == nil && b.Preview != nil && (a.State != Preparing || (b.State != PreviewReady && !(old.Mode == "native" && b.State == Expired))) {
			return ErrConflict
		}
		if a.ApprovedAt == 0 && b.ApprovedAt != 0 && (a.State != PreviewReady || b.State != Approved || b.ApprovedAt != next.ClockFloor) {
			return ErrConflict
		}
		if a.ClaimedAt == 0 && b.ClaimedAt != 0 && (a.State != Approved || b.State != DeliveryUnknown || b.ClaimedAt != next.ClockFloor) {
			return ErrConflict
		}
	}
	if len(next.Jobs) > len(old.Jobs) {
		j := next.Jobs[len(old.Jobs)]
		if old.RevokedAt != 0 || next.RevokedAt != 0 || j.State != Preparing || j.CreatedAt != next.ClockFloor || j.UpdatedAt != next.ClockFloor || len(old.Jobs) > 0 && !terminal(old.Jobs[len(old.Jobs)-1]) {
			return ErrConflict
		}
	}
	return nil
}

// MarkPreparationUncertain preserves a consumed preparation after custody was
// lost. It never fabricates package results or authorizes another operation.
func MarkPreparationUncertain(ctx context.Context, r Record, id string, now int64) (Record, error) {
	out, e := advance(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if out.Mode != "native" || len(out.Jobs) == 0 {
		return Record{}, ErrInvalid
	}
	j := &out.Jobs[len(out.Jobs)-1]
	if j.Request.RequestID != id || j.PreparationClaimedAt == 0 || j.ApprovedAt != 0 || j.ClaimedAt != 0 {
		return Record{}, ErrConflict
	}
	if j.State == NeedsIntervention {
		return out, nil
	}
	if j.State != Preparing && j.State != PreviewReady {
		return Record{}, ErrConflict
	}
	j.State = NeedsIntervention
	j.UpdatedAt = now
	return out, Validate(ctx, out)
}
