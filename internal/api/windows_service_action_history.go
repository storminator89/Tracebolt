package api

import (
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"net/http"
	"strings"
	"time"
)

// History is a projection of the existing immutable, same-binding ledger. It
// never calls preview, approval, claim, setup or a different enrollment lookup.
type windowsServiceActionHistorySummary struct {
	Identity   windowsaction.Identity `json:"identity"`
	Operation  string                 `json:"operation"`
	ApprovedAt time.Time              `json:"approvedAt"`
	State      string                 `json:"state"`
	Outcome    *string                `json:"outcome"`
}
type windowsServiceActionHistoryView struct {
	SchemaVersion string                               `json:"schemaVersion"`
	DeviceID      string                               `json:"deviceId"`
	ServerNow     time.Time                            `json:"serverNow"`
	Binding       windowsaction.Binding                `json:"binding"`
	Limit         int                                  `json:"limit"`
	Jobs          []windowsServiceActionHistorySummary `json:"jobs"`
}
type windowsServiceActionHistoryDetail struct {
	SchemaVersion string                  `json:"schemaVersion"`
	DeviceID      string                  `json:"deviceId"`
	ServerNow     time.Time               `json:"serverNow"`
	Binding       windowsaction.Binding   `json:"binding"`
	Job           windowsServiceActionJob `json:"job"`
	ClaimedAt     *time.Time              `json:"claimedAt"`
}

func windowsServiceActionHistoryJob(j windowsactionjob.Job, now time.Time) windowsServiceActionJob {
	out := windowsServiceActionJob{Identity: j.Identity(), Target: j.Preview.Binding.Target, Operation: j.Preview.Operation, ActorID: j.Preview.ActorID, ApprovedAt: j.ApprovedAt, StartDeadline: j.Deadline(), State: j.State(now)}
	if len(j.Results) > 0 {
		result := j.Results[len(j.Results)-1]
		out.Result = &result
	}
	return out
}
func (h *operatorHandler) writeWindowsServiceActionHistory(w http.ResponseWriter, r *http.Request, device, selected string) {
	owner, ok := operatorContext(r)
	allowed := false
	if ok && owner.session.Named() {
		for _, c := range owner.session.Capabilities() {
			if c == operatorauth.WindowsServiceControl {
				allowed = true
			}
		}
	}
	if !allowed {
		fail(w, 403, "operator_capability_required", "A named Windows service control operator is required.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	// There is intentionally no archive fallback when the current identity,
	// credential, ledger or key is unavailable. ViewAt retains its final after-wait
	// enrollment expiry/revocation checks and original admission binding.
	if h.windowsActions == nil {
		windowsServiceActionError(w, windowsaction.ErrUnavailable)
		return
	}
	record, now, err := h.windowsActions.ViewAt(r.Context(), device)
	if err != nil {
		windowsServiceActionError(w, err)
		return
	}
	if record.Binding.EndpointID != device || windowsactionjob.Validate(record) != nil || now.Before(record.EffectiveClockFloor()) {
		windowsServiceActionError(w, windowsaction.ErrUnavailable)
		return
	}
	if selected != "" {
		for _, j := range record.Jobs {
			if j.Preview.ID != strings.TrimPrefix(selected, "/") {
				continue
			}
			out := windowsServiceActionHistoryDetail{"tracebolt.windows-service-action-history-detail.v1", device, now, record.Binding, windowsServiceActionHistoryJob(j, now), j.ClaimedAt}
			if operatorStillActive(w, r) {
				write(w, 200, out)
			}
			return
		}
		if operatorStillActive(w, r) {
			windowsServiceActionError(w, windowsactionjob.ErrNotFound)
		}
		return
	}
	out := windowsServiceActionHistoryView{"tracebolt.windows-service-action-history.v1", device, now, record.Binding, 64, make([]windowsServiceActionHistorySummary, 0, len(record.Jobs))}
	for n := len(record.Jobs) - 1; n >= 0; n-- {
		j := record.Jobs[n]
		row := windowsServiceActionHistorySummary{Identity: j.Identity(), Operation: j.Preview.Operation, ApprovedAt: j.ApprovedAt, State: j.State(now)}
		if len(j.Results) > 0 {
			outcome := j.Results[len(j.Results)-1].Outcome
			row.Outcome = &outcome
		}
		out.Jobs = append(out.Jobs, row)
	}
	if operatorStillActive(w, r) {
		write(w, 200, out)
	}
}
