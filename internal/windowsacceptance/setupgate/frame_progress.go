package setupgate

import (
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/profile"
)

// FrameProgress is a finite projection of the latest receiver observation, not
// a telemetry body or a host-completeness claim. Qualities describe the latest
// accepted frame; receiver counters are cumulative. No new collection occurs.
type FrameProgress struct {
	Reason         string                       `json:"reason"`
	AcceptedFrames uint64                       `json:"acceptedFrames"`
	Inventory      profile.Observation          `json:"inventory"`
	Extensions     profile.ExtensionObservation `json:"extensions"`
	Telemetry      fixture.TelemetryObservation `json:"telemetry"`
}

func ZeroFrameProgress() FrameProgress {
	return FrameProgress{Reason: "not_started", Inventory: profile.ZeroObservation(), Extensions: profile.ZeroExtensionObservation()}
}

// ObserveFrames must be called even when the positive predicate has not passed.
// It preserves honest denied/first-sample/partial observations, independently of
// receiver rejections, without turning any incomplete state into acceptance.
func ObserveFrames(e fixture.Evidence) (FrameProgress, error) {
	p := FrameProgress{AcceptedFrames: e.Frames, Inventory: e.Inventory, Extensions: e.Extensions, Telemetry: e.Telemetry}
	p.Reason = p.reason()
	if p.Validate() != nil {
		return ZeroFrameProgress(), ErrGuard
	}
	return p, nil
}

func (p FrameProgress) reason() string {
	switch {
	case p.AcceptedFrames == 0:
		return "no_accepted_frames"
	case !p.Inventory.Usable():
		return "inventory_unusable"
	case !p.Extensions.Usable():
		return "extensions_unusable"
	case p.Extensions.V5Frames < 2:
		return "insufficient_v5_frames"
	default:
		return "complete"
	}
}

func (p FrameProgress) Validate() error {
	if p.Inventory.Validate() != nil || p.Extensions.Validate() != nil || p.Telemetry.Validate() != nil || p.AcceptedFrames > fixture.MaxFrames || p.AcceptedFrames != p.Inventory.Frames || p.AcceptedFrames != p.Telemetry.Accepted || p.Extensions.Frames > p.Inventory.Frames {
		return ErrGuard
	}
	if p.Reason == "not_started" {
		if p != ZeroFrameProgress() {
			return ErrGuard
		}
		return nil
	}
	if p.Reason != p.reason() {
		return ErrGuard
	}
	return nil
}

// Ready preserves the existing native success predicate exactly, plus report
// integrity. Diagnostics never waive a missing quality, peer row or CPU delta.
func (p FrameProgress) Ready() bool {
	return p.Validate() == nil && p.Inventory.Usable() && p.Extensions.Usable() && p.Extensions.V5Frames >= 2
}
