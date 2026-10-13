package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsupdateipc"
	"localrmm/internal/windowsupdatejob"
)

const windowsUpdateJobsRelayPrefix = "/v1/windows-update-jobs/"
const windowsUpdateRelayReportsPerPass = 4

// windowsUpdateExecutorClient is an injection seam for a separately reviewed
// protected IPC client. The production factory uses its independently checked
// fixed local pipe; a missing or unproven peer never reaches manager claims.
// Each method must verify the fixed live peer and honor its bounded context.
// CheckPeer binds that proof to the exact local grant. Submit forwards original
// permit bytes once; no adapter, private key, broker opcode or elevated handle
// belongs here. Status and immutable Outbox recover lost execution replies; the
// optional metadata-only retirement seam accepts exact reviewed replay.
type windowsUpdateExecutorClient interface {
	CheckPeer(context.Context, windowsupdatejob.Binding) error
	Readiness(context.Context, []byte) ([]byte, error)
	Submit(context.Context, []byte) error
	Status(context.Context) (windowsupdatejob.ExecutorStatus, error)
	Outbox(context.Context, string, string, string) ([]byte, error)
}

// Retirement is an optional metadata-only extension to the legacy client seam.
type windowsUpdateRetirementClient interface {
	Retire(context.Context, []byte) ([]byte, error)
}
type unavailableWindowsUpdateExecutorClient struct{}

func (unavailableWindowsUpdateExecutorClient) CheckPeer(context.Context, windowsupdatejob.Binding) error {
	return windowsupdatejob.ErrUnavailable
}
func (unavailableWindowsUpdateExecutorClient) Readiness(context.Context, []byte) ([]byte, error) {
	return nil, windowsupdatejob.ErrUnavailable
}
func (unavailableWindowsUpdateExecutorClient) Submit(context.Context, []byte) error {
	return windowsupdatejob.ErrUnavailable
}
func (unavailableWindowsUpdateExecutorClient) Status(context.Context) (windowsupdatejob.ExecutorStatus, error) {
	return windowsupdatejob.ExecutorStatus{}, windowsupdatejob.ErrUnavailable
}
func (unavailableWindowsUpdateExecutorClient) Outbox(context.Context, string, string, string) ([]byte, error) {
	return nil, windowsupdatejob.ErrUnavailable
}

type windowsUpdateJobSender struct {
	material    Material
	client      *http.Client
	executor    windowsUpdateExecutorClient
	newExecutor func(WindowsUpdateRelayGrant) (windowsUpdateExecutorClient, error)
	local       func(Material) (WindowsUpdateRelayGrant, error)
	current     func(Material) bool
	now         func() time.Time
	exchange    func(context.Context, string, []byte) ([]byte, int, error)
	delivered   map[string]string // Bounded by current advertised evidence; optimization only.
	cursor      int
}

func openWindowsUpdateJobSender(m Material) *windowsUpdateJobSender {
	if !m.config.windowsInventory() || m.config.Profile != "tls" {
		return nil
	}
	s := &windowsUpdateJobSender{material: m, client: newHTTPClient(m.tlsConfig, false), executor: unavailableWindowsUpdateExecutorClient{}, local: readWindowsUpdateRelay, current: func(m Material) bool { return currentWindowsUpdateRelayMaterial(m, Load) }, now: func() time.Time { return time.Now().UTC() }, delivered: map[string]string{}}
	s.newExecutor = func(g WindowsUpdateRelayGrant) (windowsUpdateExecutorClient, error) {
		return windowsupdateipc.NewClient(g.ExecutorPeer)
	}
	s.exchange = s.request
	return s
}
func (s *windowsUpdateJobSender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *windowsUpdateJobSender) recheck(ctx context.Context, g WindowsUpdateRelayGrant) bool {
	if ctx == nil || ctx.Err() != nil || !s.current(s.material) || validateWindowsUpdateRelayGrant(s.material, g, s.now()) != nil || !g.Enabled {
		return false
	}
	fresh, e := s.local(s.material)
	before, _ := json.Marshal(g)
	after, _ := json.Marshal(fresh)
	// The final protected-material read may itself block. Check finite grant,
	// current-leaf time and cancellation once more after it returns.
	return e == nil && bytes.Equal(before, after) && s.current(s.material) && ctx.Err() == nil && validateWindowsUpdateRelayGrant(s.material, g, s.now()) == nil
}
func (s *windowsUpdateJobSender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "disabled"
	}
	g, e := s.local(s.material)
	if errors.Is(e, os.ErrNotExist) || e == nil && !g.Enabled {
		return "disabled"
	}
	if e != nil || !s.recheck(ctx, g) {
		return "denied"
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(g.ExpiresAt, 0))
	defer cancel()
	// Factory construction uses public pins only and neither opens authority
	// nor starts a helper. Every client method independently verifies the peer.
	if s.newExecutor != nil {
		s.executor, e = s.newExecutor(g)
		if e != nil || !s.recheck(ctx, g) {
			return "unavailable"
		}
	}
	// A missing/stopped/unproven executor never permits manager claims.
	if s.executor == nil || s.executor.CheckPeer(ctx, g.Binding) != nil {
		return "unavailable"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	status, e := s.executor.Status(ctx)
	if !s.recheck(ctx, g) {
		return "denied"
	}
	if e != nil || !validWindowsUpdateRelayStatus(status, s.now()) {
		return "unavailable"
	}
	if len(status.MutationReport) > 0 {
		report, err := windowsupdatejob.VerifyStatement(status.MutationReport, g.ExecutorPublicKey)
		if err != nil || report.Kind != "mutation" || report.Binding != g.Binding || report.IssuedAt > s.now().Unix() || s.now().Unix() >= report.ExpiresAt {
			return "denied"
		}
		reportCtx, cancel := context.WithDeadline(ctx, time.Unix(min(report.ExpiresAt, g.ExpiresAt), 0))
		_, code, err := s.exchange(reportCtx, windowsUpdateJobsRelayPrefix+"report", status.MutationReport)
		cancel()
		if err != nil || code != http.StatusOK || !s.recheck(ctx, g) {
			return "unavailable"
		}
	}
	if result := s.reconcile(ctx, g, status); result != "" {
		return result
	}
	if status.InterventionRequired && !status.RetirementPending {
		return "needs_intervention"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	raw, code, e := s.exchange(ctx, windowsUpdateJobsRelayPrefix+"poll", []byte("{}"))
	if !s.recheck(ctx, g) {
		return "denied"
	}
	if e != nil || code != http.StatusOK {
		return "unavailable"
	}
	var pending *windowsupdatejob.Pending
	if decodeWindowsUpdateRelayJSON(raw, &pending, 256) != nil {
		return "denied"
	}
	if pending == nil {
		if status.InterventionRequired {
			return "needs_intervention"
		}
		return "idle"
	}
	if !enrollmentcrypto.ValidID(pending.JobID, "update_") || (pending.Kind != "readiness" && pending.Kind != "install" && pending.Kind != "download" && pending.Kind != "retire") || pending.Deadline <= s.now().Unix() || pending.Deadline > g.ExpiresAt {
		return "denied"
	}
	if status.InterventionRequired && pending.Kind != "retire" {
		return "needs_intervention"
	}
	if pending.Kind == "retire" {
		if !status.Reusable {
			return "denied"
		}
		if _, ok := s.executor.(windowsUpdateRetirementClient); !ok {
			return "unavailable"
		}
	}
	if (pending.Kind == "install" || pending.Kind == "download") && status.InstallCapacityRemaining == 0 {
		return "capacity_exhausted"
	}
	// Repeat verified-peer/current-authority checks after potentially blocking
	// status/outbox/network work, before consuming the manager's only delivery.
	if s.executor.CheckPeer(ctx, g.Binding) != nil || !s.recheck(ctx, g) || s.now().Unix() >= pending.Deadline {
		return "denied"
	}
	body, _ := json.Marshal(struct {
		JobID string `json:"jobId"`
	}{pending.JobID})
	path := "readiness-claim"
	if pending.Kind == "install" {
		path = "install-claim"
	} else if pending.Kind == "download" {
		path = "download-claim"
	} else if pending.Kind == "retire" {
		path = "retire-claim"
	}
	claimContext, stopClaim := context.WithDeadline(ctx, time.Unix(pending.Deadline, 0))
	raw, code, e = s.exchange(claimContext, windowsUpdateJobsRelayPrefix+path, body)
	stopClaim()
	// A claim error ends this pass. Readiness/install claims never replay; only
	// the separate retirement route may redeliver its exact saved metadata permit
	// on a later poll. No permit is cached for another installation.
	if e != nil || code != http.StatusOK {
		return "outcome_unknown"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	reference := actionpermit.Digest(raw)
	if pending.Kind == "readiness" {
		challenge, err := windowsupdatejob.VerifyChallenge(raw, g.ManagerPublicKey)
		if err != nil || challenge.Binding != g.Binding || challenge.JobID != pending.JobID || challenge.Deadline != pending.Deadline || s.now().Unix() < challenge.IssuedAt || s.now().Unix() >= challenge.Deadline {
			return "denied"
		}
	} else if pending.Kind == "retire" {
		permit, err := windowsupdatejob.VerifyRetirement(raw, g.ManagerPublicKey)
		if err != nil || permit.Binding != g.Binding || permit.JobID != pending.JobID || permit.ExpiresAt != pending.Deadline || s.now().Unix() < permit.IssuedAt || s.now().Unix() >= permit.ExpiresAt {
			return "denied"
		}
	} else {
		permit, err := windowsupdatejob.Verify(raw, g.ManagerPublicKey)
		if err != nil || permit.Download() != (pending.Kind == "download") || permit.Preview.Binding != g.Binding || permit.Preview.ID != pending.JobID || permit.Preview.ExpiresAt != pending.Deadline || s.now().Unix() < permit.ApprovedAt || s.now().Unix() >= permit.Preview.ExpiresAt {
			return "denied"
		}
	}
	if s.executor.CheckPeer(ctx, g.Binding) != nil || !s.recheck(ctx, g) || s.now().Unix() >= pending.Deadline {
		return "denied"
	}
	kind := "result"
	if pending.Kind == "readiness" {
		kind = "readiness"
		// Returned bytes are not authority to re-sign or repeat readiness. Use only
		// the durable outbox below, including after a lost readiness response.
		_, e = s.executor.Readiness(ctx, raw)
	} else if pending.Kind == "retire" {
		kind = "retired"
		_, e = s.executor.(windowsUpdateRetirementClient).Retire(ctx, raw)
	} else {
		e = s.executor.Submit(ctx, raw)
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	if e != nil {
		return "outcome_unknown"
	}
	proof, e := s.executor.Outbox(ctx, kind, pending.JobID, reference)
	if !s.recheck(ctx, g) {
		return "denied"
	}
	if e != nil {
		return "outcome_unknown"
	}
	if !s.report(ctx, g, kind, pending.JobID, reference, pending.Deadline, proof) {
		return "outcome_unknown"
	}
	return "reported"
}

func validWindowsUpdateRelayStatus(s windowsupdatejob.ExecutorStatus, now time.Time) bool {
	if s.ObservedAt <= 0 || s.ObservedAt > now.Unix() || now.Unix()-s.ObservedAt > 60 || s.Attempts == nil || len(s.Attempts) > windowsupdatejob.MaxJobs || (!s.Reusable && (s.InstallCapacityRemaining != windowsupdatejob.MaxJobs-len(s.Attempts) || len(s.Retirements) > 0 || s.RetirementPending) || s.Reusable && (len(s.Attempts) > 1 || s.InstallCapacityRemaining != 1-len(s.Attempts) || len(s.Retirements) > 1 || s.RetirementPending && !s.InterventionRequired)) {
		return false
	}
	seen := map[string]bool{}
	entries := append([]windowsupdatejob.EvidenceStatus{}, s.Attempts...)
	for _, retired := range s.Retirements {
		if retired.Kind != "retired" {
			return false
		}
		entries = append(entries, retired)
	}
	if s.Readiness != nil {
		if s.Readiness.Kind != "readiness" {
			return false
		}
		entries = append(entries, *s.Readiness)
	}
	for i, e := range entries {
		if i < len(s.Attempts) && e.Kind != "result" || !enrollmentcrypto.ValidID(e.JobID, "update_") || !actionpermit.ValidDigest(e.ReferenceDigest) || !windowsupdatejob.ValidSelection(e.Selection) || e.Sequence == 0 || e.ClaimedAt <= 0 || e.Deadline <= e.ClaimedAt || e.ClaimedAt > s.ObservedAt || seen[e.Kind+e.JobID] {
			return false
		}
		seen[e.Kind+e.JobID] = true
		switch e.ReportState {
		case "missing":
			if e.ReportIssuedAt != 0 || e.ReportExpiresAt != 0 {
				return false
			}
		case "available", "expired":
			if e.ReportIssuedAt < e.ClaimedAt || e.ReportIssuedAt > s.ObservedAt || e.ReportExpiresAt <= e.ReportIssuedAt || e.ReportExpiresAt-e.ReportIssuedAt > 300 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (s *windowsUpdateJobSender) reconcile(ctx context.Context, g WindowsUpdateRelayGrant, status windowsupdatejob.ExecutorStatus) string {
	entries := append([]windowsupdatejob.EvidenceStatus{}, status.Retirements...)
	entries = append(entries, status.Attempts...)
	if status.Readiness != nil {
		entries = append(entries, *status.Readiness)
	}
	active := map[string]bool{}
	for _, e := range entries {
		active[e.Kind+e.JobID] = true
	}
	for key := range s.delivered {
		if !active[key] {
			delete(s.delivered, key)
		}
	}
	attempts := 0
	for checked := 0; checked < len(entries) && attempts < windowsUpdateRelayReportsPerPass; checked++ {
		s.cursor %= len(entries)
		item := entries[s.cursor]
		s.cursor++
		if item.ReportState != "available" || s.now().Unix() >= item.ReportExpiresAt || s.delivered[item.Kind+item.JobID] == item.ReferenceDigest {
			continue
		}
		attempts++
		if !s.recheck(ctx, g) {
			return "denied"
		}
		proof, e := s.executor.Outbox(ctx, item.Kind, item.JobID, item.ReferenceDigest)
		if !s.recheck(ctx, g) {
			return "denied"
		}
		if e != nil || !s.report(ctx, g, item.Kind, item.JobID, item.ReferenceDigest, item.Deadline, proof) {
			return "outcome_unknown"
		}
	}
	return ""
}
func (s *windowsUpdateJobSender) report(ctx context.Context, g WindowsUpdateRelayGrant, kind, id, reference string, deadline int64, raw []byte) bool {
	if kind == "retired" {
		return s.reportRetirement(ctx, g, id, reference, raw)
	}
	statement, e := windowsupdatejob.VerifyStatement(raw, g.ExecutorPublicKey)
	if e != nil || statement.Binding != g.Binding || statement.Kind != kind || statement.JobID != id || statement.ReferenceDigest != reference || statement.Deadline != deadline || s.now().Unix() < statement.IssuedAt || s.now().Unix() >= statement.ExpiresAt || !s.recheck(ctx, g) {
		return false
	}
	// Authority reads above may block beyond this evidence's original expiry.
	// Bound the HTTP request too, including its own protected-material reread.
	if n := s.now().Unix(); n < statement.IssuedAt || n >= statement.ExpiresAt {
		return false
	}
	reportContext, cancel := context.WithDeadline(ctx, time.Unix(min(statement.ExpiresAt, g.ExpiresAt), 0))
	defer cancel()
	response, code, e := s.exchange(reportContext, windowsUpdateJobsRelayPrefix+"report", raw)
	if !s.recheck(ctx, g) || e != nil || code != http.StatusOK || !bytes.Equal(response, []byte("{}")) {
		return false
	}
	if s.delivered == nil {
		s.delivered = map[string]string{}
	}
	s.delivered[kind+id] = reference
	return true
}
func (s *windowsUpdateJobSender) reportRetirement(ctx context.Context, g WindowsUpdateRelayGrant, id, reference string, raw []byte) bool {
	r, e := windowsupdatejob.VerifyRetirementReport(raw, g.ExecutorPublicKey)
	if e != nil || r.Binding != g.Binding || r.JobID != id || r.ReferenceDigest != reference || !s.recheck(ctx, g) {
		return false
	}
	if n := s.now().Unix(); n < r.IssuedAt || n >= r.ExpiresAt {
		return false
	}
	reportCtx, cancel := context.WithDeadline(ctx, time.Unix(min(r.ExpiresAt, g.ExpiresAt), 0))
	defer cancel()
	response, code, e := s.exchange(reportCtx, windowsUpdateJobsRelayPrefix+"report", raw)
	if !s.recheck(ctx, g) || e != nil || code != http.StatusOK || !bytes.Equal(response, []byte("{}")) {
		return false
	}
	if s.delivered == nil {
		s.delivered = map[string]string{}
	}
	s.delivered["retired"+id] = reference
	return true
}
func (s *windowsUpdateJobSender) request(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	// Run/report completed their final grant/material/deadline check at this
	// send seam. Do not add a blocking material reload between that check and
	// Do; the original grant/claim/report expiry also bounds request.Context.
	if s.material.config.Profile != "tls" || ctx == nil || ctx.Err() != nil {
		return nil, 0, ErrState
	}
	limit := 0
	switch path {
	case windowsUpdateJobsRelayPrefix + "poll":
		limit = 2
	case windowsUpdateJobsRelayPrefix + "readiness-claim", windowsUpdateJobsRelayPrefix + "install-claim", windowsUpdateJobsRelayPrefix + "download-claim", windowsUpdateJobsRelayPrefix + "retire-claim":
		limit = 128
	case windowsUpdateJobsRelayPrefix + "report":
		limit = windowsupdatejob.MaxRelayBytes
	}
	if limit == 0 || len(body) == 0 || len(body) > limit {
		return nil, 0, ErrConfiguration
	}
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, e
	}
	request.Header.Set("Content-Type", "application/json")
	request.GetBody = nil // No automatic redirect/replay of a consumed claim.
	response, e := s.client.Do(request)
	if e != nil {
		return nil, 0, ErrTransport
	}
	defer response.Body.Close()
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Trailer) != 0 {
		return nil, 0, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, windowsupdatejob.MaxRelayBytes+1))
	if e != nil || len(raw) == 0 || len(raw) > windowsupdatejob.MaxRelayBytes || response.ContentLength >= 0 && response.ContentLength != int64(len(raw)) || len(response.Trailer) != 0 || !s.current(s.material) {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}
func runWindowsUpdateJobLoop(ctx context.Context, s *windowsUpdateJobSender) {
	if s == nil {
		return
	}
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 55*time.Second)
		s.Run(attempt)
		cancel()
		timer := time.NewTimer(15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
