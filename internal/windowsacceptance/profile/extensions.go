package profile

// QualityCounts contains no process identifiers, capacities or metric values.
type QualityCounts struct {
	Observed    uint32 `json:"observed"`
	Denied      uint32 `json:"denied"`
	Unavailable uint32 `json:"unavailable"`
	FirstSample uint32 `json:"firstSample"`
	Reset       uint32 `json:"reset"`
}

// Quality summarizes retained rows only; mixed qualities remain explicitly partial.
func (c QualityCounts) Quality() string {
	n := 0
	q := "empty"
	for _, v := range []struct {
		n uint32
		q string
	}{{c.Observed, "observed"}, {c.Denied, "denied"}, {c.Unavailable, "unavailable"}, {c.FirstSample, "first-sample"}, {c.Reset, "reset"}} {
		if v.n > 0 {
			n++
			q = v.q
		}
	}
	if n > 1 {
		return "partial"
	}
	return q
}
func (c QualityCounts) valid(rows uint32, cpu bool) bool {
	if !cpu && (c.FirstSample != 0 || c.Reset != 0) {
		return false
	}
	return uint64(c.Observed)+uint64(c.Denied)+uint64(c.Unavailable)+uint64(c.FirstSample)+uint64(c.Reset) == uint64(rows)
}

// ExtensionObservation retains finite qualities and bounded retained-row counts.
// V5Frames proves all four extensions shared a validated v5 frame, not separate
// native v2/v3/v4 acceptance. Native origin is established by the controller.
// These are retained row counts, never claims of whole-machine coverage.
type ExtensionObservation struct {
	FreshOrchestrationAcceptance bool          `json:"freshOrchestrationAcceptance"`
	VolumeCapacityCounts         QualityCounts `json:"volumeCapacityCounts"`
	ProcessCPUCounts             QualityCounts `json:"processCPUCounts"`
	ProcessMemoryCounts          QualityCounts `json:"processMemoryCounts"`
	Frames                       uint64        `json:"frames"`
	V5Frames                     uint64        `json:"v5Frames"`
	EventApplication             string        `json:"eventApplication"`
	EventSystem                  string        `json:"eventSystem"`
	Volumes                      string        `json:"volumes"`
	VolumeCapacity               string        `json:"volumeCapacity"`
	ProcessCPU                   string        `json:"processCPU"`
	ProcessMemory                string        `json:"processMemory"`
	Network                      string        `json:"network"`
	EventRows                    uint32        `json:"eventRows"`
	VolumeRows                   uint32        `json:"volumeRows"`
	ProcessRows                  uint32        `json:"processRows"`
	PeerLoopbackRows             uint32        `json:"peerLoopbackRows"`
	NetworkRows                  uint32        `json:"networkRows"`
	ProcessCPUFirstSampleRows    uint32        `json:"processCPUFirstSampleRows"`
}

func ZeroExtensionObservation() ExtensionObservation {
	return ExtensionObservation{EventApplication: "not_run", EventSystem: "not_run", Volumes: "not_run", VolumeCapacity: "not_run", ProcessCPU: "not_run", ProcessMemory: "not_run", Network: "not_run"}
}
func oneOf(v string, choices ...string) bool {
	for _, c := range choices {
		if v == c {
			return true
		}
	}
	return false
}
func (o ExtensionObservation) Validate() error {
	if o.FreshOrchestrationAcceptance {
		return ErrObservation
	}
	if o.Frames == 0 {
		if o != ZeroExtensionObservation() {
			return ErrObservation
		}
		return nil
	}
	if o.Frames > 64 || o.V5Frames != o.Frames || o.EventRows > 32 || o.VolumeRows > 64 || o.ProcessRows > 128 || o.NetworkRows > 64 || o.PeerLoopbackRows > o.NetworkRows || o.ProcessCPUFirstSampleRows > o.ProcessRows {
		return ErrObservation
	}
	for _, q := range []string{o.EventApplication, o.EventSystem, o.Volumes} {
		if !oneOf(q, "observed", "bounded", "partial", "denied", "unavailable") {
			return ErrObservation
		}
	}
	if !o.VolumeCapacityCounts.valid(o.VolumeRows, false) || !o.ProcessCPUCounts.valid(o.ProcessRows, true) || !o.ProcessMemoryCounts.valid(o.ProcessRows, false) || o.VolumeCapacity != o.VolumeCapacityCounts.Quality() || o.ProcessCPU != o.ProcessCPUCounts.Quality() || o.ProcessMemory != o.ProcessMemoryCounts.Quality() || o.ProcessCPUFirstSampleRows != o.ProcessCPUCounts.FirstSample || !oneOf(o.Network, "observed", "partial", "denied", "unavailable") {
		return ErrObservation
	}
	if oneOf(o.Volumes, "denied", "unavailable") && o.VolumeRows != 0 || oneOf(o.Network, "denied", "unavailable") && o.NetworkRows != 0 || oneOf(o.EventApplication, "denied", "unavailable") && oneOf(o.EventSystem, "denied", "unavailable") && o.EventRows != 0 {
		return ErrObservation
	}
	return nil
}
func (o ExtensionObservation) Usable() bool {
	if o.Validate() != nil || o.Frames == 0 {
		return false
	}
	for _, q := range []string{o.EventApplication, o.EventSystem, o.Volumes} {
		if !oneOf(q, "observed", "bounded", "partial") {
			return false
		}
	}
	return o.PeerLoopbackRows > 0 && o.VolumeCapacityCounts.Observed > 0 && o.ProcessCPUCounts.Observed > 0 && o.ProcessMemoryCounts.Observed > 0 && oneOf(o.Network, "observed", "partial")
}
