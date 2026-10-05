package actionstate

import (
	"bytes"
	"encoding/json"
	"time"

	"localrmm/internal/actionpermit"
)

// Only signed bounded action descriptions and structured admission state are
// retained. No arbitrary output, credentials or user-controlled result strings.
type diskRecord struct {
	Version       string    `json:"version"`
	BindingDigest string    `json:"bindingDigest"`
	Floor         uint64    `json:"floor,string"`
	HighWater     int64     `json:"highWater"`
	Jobs          []diskJob `json:"jobs"`
}
type diskJob struct {
	Envelope   []byte         `json:"envelope"`
	Phase      string         `json:"phase"`
	ConsumedAt int64          `json:"consumedAt"`
	Lifecycle  *diskLifecycle `json:"lifecycle,omitempty"`
}

// Omitted on legacy jobs, including after an in-place version upgrade. Original
// signed descriptions and consumption times never change. TransitionAt extends
// the existing clock high-water rather than introducing a new sequence domain.
type diskLifecycle struct {
	DispatchAt    int64            `json:"dispatchAt"`
	TransitionAt  int64            `json:"transitionAt"`
	Reason        NotStartedReason `json:"reason"`
	Outcome       Outcome          `json:"outcome"`
	ObservedState ObservedState    `json:"observedState"`
}

func encodeRecord(r diskRecord) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil || len(b) == 0 || len(b) > MaxStateBytes || len(r.Jobs) > MaxJobs {
		return nil, ErrCorrupt
	}
	return b, nil
}

func decodeRecord(raw []byte, verifier actionpermit.Verifier) (diskRecord, error) {
	var r diskRecord
	if len(raw) == 0 || len(raw) > MaxStateBytes || json.Unmarshal(raw, &r) != nil {
		return r, ErrCorrupt
	}
	canonical, err := encodeRecord(r)
	if err != nil || !bytes.Equal(raw, canonical) || (r.Version != Version && r.Version != RunnerVersion) || !actionpermit.ValidDigest(r.BindingDigest) || r.Jobs == nil {
		return r, ErrCorrupt
	}
	binding, err := verifier.BindingDigest()
	if err != nil || r.BindingDigest != binding {
		return r, ErrBinding
	}
	seen := map[string]bool{}
	var floor uint64
	var highWater int64
	unresolved := false
	for _, job := range r.Jobs {
		p, err := verifier.CheckSignature(job.Envelope)
		if err != nil || seen[p.JobID] || p.Sequence <= floor || job.ConsumedAt <= 0 || job.ConsumedAt < highWater || unresolved {
			return r, ErrCorrupt
		}
		now := time.UnixMicro(job.ConsumedAt).UTC()
		if now.Year() > 9999 || now.Unix() < p.NotBefore {
			return r, ErrCorrupt
		}
		last, pending, ok := validateJob(job, p, r.Version)
		if !ok {
			return r, ErrCorrupt
		}
		unresolved = pending
		seen[p.JobID], floor, highWater = true, p.Sequence, last
	}
	if r.Floor != floor || r.HighWater != highWater {
		return r, ErrCorrupt
	}
	return r, nil
}

func validateJob(job diskJob, p actionpermit.Permit, version string) (last int64, pending, ok bool) {
	last = job.ConsumedAt
	consumed := time.UnixMicro(job.ConsumedAt).Unix()
	if job.Lifecycle == nil {
		switch job.Phase {
		case Admitted, NeedsIntervention:
			return last, true, consumed < p.StartDeadline
		case Expired:
			return last, false, consumed >= p.StartDeadline
		}
		return last, false, false
	}
	l := job.Lifecycle
	if version != RunnerVersion || consumed >= p.StartDeadline || l.TransitionAt < job.ConsumedAt || time.UnixMicro(l.TransitionAt).UTC().Year() > 9999 || l.DispatchAt < 0 {
		return last, false, false
	}
	last = l.TransitionAt
	if l.DispatchAt != 0 && (l.DispatchAt < job.ConsumedAt || l.DispatchAt > l.TransitionAt || time.UnixMicro(l.DispatchAt).Unix() >= p.StartDeadline) {
		return last, false, false
	}
	switch job.Phase {
	case Admitted:
		return last, true, l.DispatchAt == 0 && l.TransitionAt == job.ConsumedAt && l.Reason == "" && l.Outcome == "" && l.ObservedState == ""
	case Dispatching:
		return last, true, l.DispatchAt != 0 && l.TransitionAt == l.DispatchAt && l.Reason == "" && l.Outcome == "" && l.ObservedState == ""
	case NotStarted:
		return last, false, validReason(l.Reason) && l.Outcome == "" && l.ObservedState == ""
	case OperationCompleted:
		return last, false, l.DispatchAt != 0 && l.Reason == "" && l.Outcome == OutcomeCompleted && validObserved(l.ObservedState)
	case NeedsIntervention:
		// A recovered admission has no invocation time. Recovery changes only
		// bounded uncertainty fields, never the original recorded timestamps.
		return last, true, l.Reason == "" && l.Outcome == OutcomeUnknown && validObserved(l.ObservedState) && (l.DispatchAt != 0 || (l.TransitionAt == job.ConsumedAt && l.ObservedState == ObservedUnknown))
	}
	return last, false, false
}

func status(job diskJob) Status {
	p, _ := actionpermit.Decode(job.Envelope)
	s := Status{Permit: p, EnvelopeDigest: actionpermit.Digest(job.Envelope), Phase: job.Phase, ConsumedAt: time.UnixMicro(job.ConsumedAt).UTC(), TransitionAt: time.UnixMicro(job.ConsumedAt).UTC()}
	if l := job.Lifecycle; l != nil {
		if l.DispatchAt != 0 {
			s.DispatchAt = time.UnixMicro(l.DispatchAt).UTC()
		}
		s.TransitionAt = time.UnixMicro(l.TransitionAt).UTC()
		s.Reason, s.Outcome, s.ObservedState = l.Reason, l.Outcome, l.ObservedState
	}
	return s
}
