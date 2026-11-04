package api

import (
	"encoding/json"
	"net/http"
	"time"

	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/operatorauth"
)

const serviceActionHistoryBytes = 128 << 10

type serviceActionHistoryReport struct {
	ReceivedAt time.Time           `json:"receivedAt"`
	Result     serviceActionResult `json:"result"`
}
type serviceActionHistoryEntry struct {
	Sequence  uint64                       `json:"sequence,string"`
	Job       serviceActionJob             `json:"job"`
	ClaimedAt *time.Time                   `json:"claimedAt"`
	Reports   []serviceActionHistoryReport `json:"reports"`
}
type serviceActionHistoryView struct {
	SchemaVersion     string                      `json:"schemaVersion"`
	DeviceID          string                      `json:"deviceId"`
	ServerNow         time.Time                   `json:"serverNow"`
	IncarnationDigest string                      `json:"incarnationDigest"`
	KeyID             string                      `json:"keyId"`
	Limit             int                         `json:"limit"`
	Jobs              []serviceActionHistoryEntry `json:"jobs"`
}

// Project only the existing bounded action ledger. No preview, permit, raw
// envelope, helper access or alternate/archive identity lookup is performed.
func (h *operatorHandler) writeServiceActionHistory(w http.ResponseWriter, r *http.Request, device string) {
	owner, ok := operatorContext(r)
	allowed := false
	if ok && owner.session.Named() {
		for _, capability := range owner.session.Capabilities() {
			if capability == operatorauth.RestartService {
				allowed = true
			}
		}
	}
	if !allowed {
		fail(w, 403, "operator_capability_required", "A named service restart operator is required.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if h.actions == nil {
		serviceActionError(w, actionjob.ErrUnavailable)
		return
	}
	record, now, err := h.actions.ViewAt(r.Context(), device)
	if err != nil {
		serviceActionError(w, err)
		return
	}
	if record.DeviceID != device || actionjob.Validate(record) != nil || !actionjob.ValidTime(now) || now.Before(record.ClockFloor) {
		serviceActionError(w, actionjob.ErrUnavailable)
		return
	}
	out := serviceActionHistoryView{"tracebolt.service-action-history.v1", device, now, record.IncarnationDigest, actionpermit.Digest(record.PublicKey), actionjob.MaxJobs, make([]serviceActionHistoryEntry, 0, len(record.Jobs))}
	for n := len(record.Jobs) - 1; n >= 0; n-- {
		j := record.Jobs[n]
		row := serviceActionHistoryEntry{Sequence: j.Preview.Sequence, ClaimedAt: j.ClaimedAt, Reports: make([]serviceActionHistoryReport, 0, len(j.Results))}
		row.Job = serviceActionJob{ID: j.Preview.ID, Unit: j.Preview.Plan.Unit, ActorID: j.Preview.ActorID, ApprovedAt: j.Approval.ApprovedAt, StartDeadline: j.Deadline(), State: j.State(now), EnvelopeDigest: j.Identity().EnvelopeDigest}
		for i, x := range j.Results {
			result := serviceActionResult{x.Phase, x.Reason, x.Outcome, x.ObservedState}
			row.Reports = append(row.Reports, serviceActionHistoryReport{j.ResultReceivedAt[i], result})
		}
		if len(row.Reports) > 0 {
			result := row.Reports[len(row.Reports)-1].Result
			row.Job.Result = &result
		}
		out.Jobs = append(out.Jobs, row)
	}
	// Encode before publishing: a future accidental field expansion fails closed.
	b, err := json.Marshal(out)
	if err != nil || len(b) > serviceActionHistoryBytes {
		serviceActionError(w, actionjob.ErrUnavailable)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
