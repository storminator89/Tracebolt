package windowsupdatejob

import (
	"context"
	"encoding/json"
)

const HistoryVersion = "tracebolt.windows-selected-update-history.v1"

type JobSummary struct {
	Purpose     string          `json:"purpose,omitempty"`
	Occurrence  uint64          `json:"occurrence,string,omitempty"`
	Retirement  *RetirementView `json:"retirement,omitempty"`
	ID          string          `json:"id"`
	Selection   Selection       `json:"selection"`
	State       string          `json:"state"`
	Reason      string          `json:"reason"`
	Result      *Result         `json:"result"`
	RequestedAt int64           `json:"requestedAt"`
	ApprovedAt  int64           `json:"approvedAt"`
	ClaimedAt   int64           `json:"claimedAt"`
	Schedule    *ScheduleView   `json:"schedule,omitempty"`
}
type History struct {
	ReusableJobs      bool         `json:"reusableJobs,omitempty"`
	GrantExpiresAt    int64        `json:"grantExpiresAt,omitempty"`
	RetiredFloor      uint64       `json:"retiredFloor,string,omitempty"`
	Version           string       `json:"version"`
	DeviceID          string       `json:"deviceId"`
	ServerNow         int64        `json:"serverNow"`
	Available         bool         `json:"available"`
	Reason            string       `json:"reason"`
	RemainingCapacity int          `json:"remainingCapacity"`
	Jobs              []JobSummary `json:"jobs"`
}

func publicJob(j Job, n int64, key []byte) PublicJob {
	p := PublicJob{Purpose: j.Purpose, ID: j.ID, Selection: j.Selection, State: j.State, Reason: j.Reason, Result: j.Result}
	if j.Occurrence != 0 {
		p.Occurrence = j.Occurrence
		p.Retirement = retirementView(j, n)
		if len(j.ResultReport) > 0 {
			p.ResultDigest = digestBytes(j.ResultReport)
		}
	}
	if j.State == "requested" {
		challenge, _ := VerifyChallenge(j.Challenge, key)
		if n >= challenge.Deadline {
			p.State = "expired"
		}
	}
	if j.Preview != nil && (j.State == "approved" || j.State == "preview") && n >= j.Preview.ExpiresAt {
		p.State = "expired"
	}
	if j.Schedule != nil {
		p.Schedule = scheduleView(j)
		if p.State == "expired" || !scheduleActive(j, n) && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
			p.State = "schedule_expired"
		}
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
		h.RemainingCapacity = MaxJobs - reservedOperations(m.record)
		if m.record.Consent.Reusable() {
			h.ReusableJobs = true
			h.GrantExpiresAt = m.record.Consent.ExpiresAt
			h.RetiredFloor = m.record.RetiredFloor
			h.RemainingCapacity = 1
			for _, j := range m.record.Jobs {
				if j.Occurrence != 0 && len(j.RetireReport) == 0 {
					h.RemainingCapacity = 0
				}
			}
		}
		if !h.Available {
			h.Reason = "job_pending_or_intervention"
			if !h.ReusableJobs && h.RemainingCapacity == 0 {
				h.Reason = "capacity_exhausted"
			}
		}
		for i := len(m.record.Jobs) - 1; i >= 0; i-- {
			j := m.record.Jobs[i]
			p := publicJob(j, n, m.record.PublicKey)
			h.Jobs = append(h.Jobs, JobSummary{Purpose: p.Purpose, ID: j.ID, Selection: j.Selection, State: p.State, Reason: p.Reason, Result: j.Result, RequestedAt: j.RequestedAt, ApprovedAt: j.ApprovedAt, ClaimedAt: j.ClaimedAt, Schedule: p.Schedule, Occurrence: p.Occurrence, Retirement: p.Retirement})
		}
		for i := len(m.record.Recent) - 1; i >= 0; i-- {
			old := m.record.Recent[i]
			duplicate := false
			for _, j := range h.Jobs {
				if j.ID == old.JobID {
					duplicate = true
				}
			}
			if !duplicate {
				p := retiredPublicJob(old)
				h.Jobs = append(h.Jobs, JobSummary{Purpose: p.Purpose, ID: old.JobID, Selection: old.Selection, State: p.State, Reason: p.Reason, Result: p.Result, RequestedAt: old.RequestedAt, ApprovedAt: old.ApprovedAt, ClaimedAt: old.ClaimedAt, Occurrence: old.Occurrence, Retirement: p.Retirement})
			}
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
