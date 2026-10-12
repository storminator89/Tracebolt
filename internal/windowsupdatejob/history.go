package windowsupdatejob

import (
	"context"
	"encoding/json"
)

const HistoryVersion = "tracebolt.windows-selected-update-history.v1"

type JobSummary struct {
	ID          string    `json:"id"`
	Selection   Selection `json:"selection"`
	State       string    `json:"state"`
	Reason      string    `json:"reason"`
	Result      *Result   `json:"result"`
	RequestedAt int64     `json:"requestedAt"`
	ApprovedAt  int64     `json:"approvedAt"`
	ClaimedAt   int64     `json:"claimedAt"`
}
type History struct {
	Version           string       `json:"version"`
	DeviceID          string       `json:"deviceId"`
	ServerNow         int64        `json:"serverNow"`
	Available         bool         `json:"available"`
	Reason            string       `json:"reason"`
	RemainingCapacity int          `json:"remainingCapacity"`
	Jobs              []JobSummary `json:"jobs"`
}

func publicJob(j Job, n int64, key []byte) PublicJob {
	p := PublicJob{ID: j.ID, Selection: j.Selection, State: j.State, Reason: j.Reason, Result: j.Result}
	if j.State == "requested" {
		challenge, _ := VerifyChallenge(j.Challenge, key)
		if n >= challenge.Deadline {
			p.State = "expired"
		}
	}
	if j.Preview != nil && (j.State == "approved" || j.State == "preview") && n >= j.Preview.ExpiresAt {
		p.State = "expired"
	}
	return p
}
func (m *Manager) History(ctx context.Context, device string) (History, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID {
		return History{}, ErrInvalid
	}
	h := History{Version: HistoryVersion, DeviceID: device, Jobs: []JobSummary{}}
	err := m.transaction(ctx, func(_ Current, n int64) error {
		h.ServerNow = n
		h.Available = !m.blocked(n, "")
		h.Reason = "ready"
		h.RemainingCapacity = MaxJobs - int(m.record.Sequence)
		if !h.Available {
			h.Reason = "job_pending_or_intervention"
			if h.RemainingCapacity == 0 {
				h.Reason = "capacity_exhausted"
			}
		}
		for i := len(m.record.Jobs) - 1; i >= 0; i-- {
			j := m.record.Jobs[i]
			p := publicJob(j, n, m.record.PublicKey)
			h.Jobs = append(h.Jobs, JobSummary{j.ID, j.Selection, p.State, p.Reason, j.Result, j.RequestedAt, j.ApprovedAt, j.ClaimedAt})
		}
		return nil
	})
	if err != nil {
		return History{}, err
	}
	raw, _ := json.Marshal(h)
	var copy History
	_ = json.Unmarshal(raw, &copy)
	return copy, nil
}
