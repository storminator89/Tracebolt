package enrollmentstore

import (
	"crypto/sha256"
	"localrmm/internal/lanstore"
	"slices"
	"time"
)

type frameValidationKey struct {
	Digest     [32]byte
	ReceivedAt time.Time
}

// validateFrame reuses only pure parsing inside one durable transaction. The
// cache cannot outlive BEGIN/COMMIT, and contains no authority/replay/freshness
// decision. Receipt time is part of the key, preserving historical validation.
// Every returned mutable value is detached from the cached parse.
func (t *transaction) validateFrame(raw []byte, receivedAt time.Time) (lanstore.Frame, error) {
	key := frameValidationKey{sha256.Sum256(raw), receivedAt.UTC()}
	if frame, ok := t.validatedFrames[key]; ok {
		return cloneFrame(frame), nil
	}
	frame, e := lanstore.ValidateFrame(raw, receivedAt)
	if e != nil {
		return frame, e
	}
	if t.validatedFrames == nil {
		t.validatedFrames = make(map[frameValidationKey]lanstore.Frame)
	}
	t.validatedFrames[key] = cloneFrame(frame)
	return frame, nil
}
func copiedPointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	value := *p
	return &value
}
func cloneFrame(f lanstore.Frame) lanstore.Frame {
	f.Observation.Privacy = slices.Clone(f.Observation.Privacy)
	d := &f.Observation.Observation
	d.IP = copiedPointer(d.IP)
	d.CPU.Value = copiedPointer(d.CPU.Value)
	d.Memory.Value = copiedPointer(d.Memory.Value)
	d.Disk.Value = copiedPointer(d.Disk.Value)
	d.Tags = slices.Clone(d.Tags)
	d.Capabilities = slices.Clone(d.Capabilities)
	d.Evidence = slices.Clone(d.Evidence)
	d.Trend = slices.Clone(d.Trend)
	d.CaseIDs = slices.Clone(d.CaseIDs)
	if f.Operational != nil {
		op := *f.Operational
		v := &op.Sections
		v.Volumes.Items = slices.Clone(v.Volumes.Items)
		for i := range v.Volumes.Items {
			p := &v.Volumes.Items[i]
			p.TotalBytes = copiedPointer(p.TotalBytes)
			p.AvailableBytes = copiedPointer(p.AvailableBytes)
			p.UsedPercent = copiedPointer(p.UsedPercent)
		}
		v.Network.Items = slices.Clone(v.Network.Items)
		for i := range v.Network.Items {
			p := &v.Network.Items[i]
			p.MTU = copiedPointer(p.MTU)
			p.RXBytes = copiedPointer(p.RXBytes)
			p.TXBytes = copiedPointer(p.TXBytes)
			p.RXErrors = copiedPointer(p.RXErrors)
			p.TXErrors = copiedPointer(p.TXErrors)
			p.IPv4Count = copiedPointer(p.IPv4Count)
			p.IPv6Count = copiedPointer(p.IPv6Count)
		}
		v.Processes.Items = slices.Clone(v.Processes.Items)
		for i := range v.Processes.Items {
			p := &v.Processes.Items[i]
			p.ParentPID = copiedPointer(p.ParentPID)
			p.RSSBytes = copiedPointer(p.RSSBytes)
			p.CPUTimeSeconds = copiedPointer(p.CPUTimeSeconds)
			p.Threads = copiedPointer(p.Threads)
		}
		v.Services.Items = slices.Clone(v.Services.Items)
		v.Software.Items = slices.Clone(v.Software.Items)
		v.Events.Items = slices.Clone(v.Events.Items)
		f.Operational = &op
	}
	f.Packages = clonePackageSnapshot(f.Packages)
	return f
}
