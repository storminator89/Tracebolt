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
	Envelope   []byte `json:"envelope"`
	Phase      string `json:"phase"`
	ConsumedAt int64  `json:"consumedAt"`
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
	if err != nil || !bytes.Equal(raw, canonical) || r.Version != Version || !actionpermit.ValidDigest(r.BindingDigest) || r.Jobs == nil {
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
		switch job.Phase {
		case Admitted, NeedsIntervention:
			if now.Unix() >= p.StartDeadline {
				return r, ErrCorrupt
			}
			unresolved = true
		case Expired:
			if now.Unix() < p.StartDeadline {
				return r, ErrCorrupt
			}
		default:
			return r, ErrCorrupt
		}
		seen[p.JobID], floor, highWater = true, p.Sequence, job.ConsumedAt
	}
	if r.Floor != floor || r.HighWater != highWater {
		return r, ErrCorrupt
	}
	return r, nil
}

func status(job diskJob) Status {
	p, _ := actionpermit.Decode(job.Envelope)
	return Status{p, actionpermit.Digest(job.Envelope), job.Phase, time.UnixMicro(job.ConsumedAt).UTC()}
}
