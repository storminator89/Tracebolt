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
	"localrmm/internal/windowssoftwareipc"
	"localrmm/internal/windowssoftwarejob"
)

const windowsSoftwareJobsRelayPrefix = "/v1/windows-software-jobs/"
const windowsSoftwareRelayReportsPerPass = 4

// windowsSoftwareExecutorClient is an injection seam for a separately reviewed
// protected IPC client. The production factory uses its independently checked
// fixed local pipe; a missing or unproven peer never reaches manager claims.
// Each method must verify the fixed live peer and honor its bounded context.
// CheckPeer binds that proof to the exact local grant. Submit forwards original
// permit bytes once; no adapter, private key, broker opcode or elevated handle
// belongs here. Only Status and immutable Outbox may recover lost replies.
type windowsSoftwareExecutorClient interface {
	CheckPeer(context.Context, windowssoftwarejob.Binding) error
	Readiness(context.Context, []byte) ([]byte, error)
	Submit(context.Context, []byte) error
	Status(context.Context) (windowssoftwarejob.ExecutorStatus, error)
	Outbox(context.Context, string, string, string) ([]byte, error)
}
type unavailableWindowsSoftwareExecutorClient struct{}

func (unavailableWindowsSoftwareExecutorClient) CheckPeer(context.Context, windowssoftwarejob.Binding) error {
	return windowssoftwarejob.ErrUnavailable
}
func (unavailableWindowsSoftwareExecutorClient) Readiness(context.Context, []byte) ([]byte, error) {
	return nil, windowssoftwarejob.ErrUnavailable
}
func (unavailableWindowsSoftwareExecutorClient) Submit(context.Context, []byte) error {
	return windowssoftwarejob.ErrUnavailable
}
func (unavailableWindowsSoftwareExecutorClient) Status(context.Context) (windowssoftwarejob.ExecutorStatus, error) {
	return windowssoftwarejob.ExecutorStatus{}, windowssoftwarejob.ErrUnavailable
}
func (unavailableWindowsSoftwareExecutorClient) Outbox(context.Context, string, string, string) ([]byte, error) {
	return nil, windowssoftwarejob.ErrUnavailable
}

type windowsSoftwareJobSender struct {
	material    Material
	client      *http.Client
	executor    windowsSoftwareExecutorClient
	newExecutor func(WindowsSoftwareRelayGrant) (windowsSoftwareExecutorClient, error)
	local       func(Material) (WindowsSoftwareRelayGrant, error)
	current     func(Material) bool
	now         func() time.Time
	exchange    func(context.Context, string, []byte) ([]byte, int, error)
	delivered   map[string]string // Bounded by latest readiness plus MaxJobs; optimization only.
	cursor      int
}

func openWindowsSoftwareJobSender(m Material) *windowsSoftwareJobSender {
	if !m.config.windowsInventory() || m.config.Profile != "tls" {
		return nil
	}
	s := &windowsSoftwareJobSender{material: m, client: newHTTPClient(m.tlsConfig, false), executor: unavailableWindowsSoftwareExecutorClient{}, local: readWindowsSoftwareRelay, current: func(m Material) bool { return currentWindowsSoftwareRelayMaterial(m, Load) }, now: func() time.Time { return time.Now().UTC() }, delivered: map[string]string{}}
	s.newExecutor = func(g WindowsSoftwareRelayGrant) (windowsSoftwareExecutorClient, error) {
		return windowssoftwareipc.NewClient(g.ExecutorPeer)
	}
	s.exchange = s.request
	return s
}
func (s *windowsSoftwareJobSender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *windowsSoftwareJobSender) recheck(ctx context.Context, g WindowsSoftwareRelayGrant) bool {
	if ctx == nil || ctx.Err() != nil || !s.current(s.material) || validateWindowsSoftwareRelayGrant(s.material, g, s.now()) != nil || !g.Enabled {
		return false
	}
	fresh, e := s.local(s.material)
	before, _ := json.Marshal(g)
	after, _ := json.Marshal(fresh)
	// The final protected-material read may itself block. Check finite grant,
	// current-leaf time and cancellation once more after it returns.
	return e == nil && bytes.Equal(before, after) && s.current(s.material) && ctx.Err() == nil && validateWindowsSoftwareRelayGrant(s.material, g, s.now()) == nil
}
func (s *windowsSoftwareJobSender) Run(ctx context.Context) string {
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
	if e != nil || !validWindowsSoftwareRelayStatus(status, s.now()) {
		return "unavailable"
	}
	if result := s.reconcile(ctx, g, status); result != "" {
		return result
	}
	if status.InterventionRequired {
		return "needs_intervention"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	raw, code, e := s.exchange(ctx, windowsSoftwareJobsRelayPrefix+"poll", []byte("{}"))
	if !s.recheck(ctx, g) {
		return "denied"
	}
	if e != nil || code != http.StatusOK {
		return "unavailable"
	}
	var pending *windowssoftwarejob.Pending
	if decodeWindowsSoftwareRelayJSON(raw, &pending, 256) != nil {
		return "denied"
	}
	if pending == nil {
		return "idle"
	}
	if !enrollmentcrypto.ValidID(pending.JobID, "software_") || (pending.Kind != "readiness" && pending.Kind != "install") || pending.Deadline <= s.now().Unix() || pending.Deadline > g.ExpiresAt {
		return "denied"
	}
	if pending.Kind == "install" && status.InstallCapacityRemaining == 0 {
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
	}
	claimContext, stopClaim := context.WithDeadline(ctx, time.Unix(pending.Deadline, 0))
	raw, code, e = s.exchange(claimContext, windowsSoftwareJobsRelayPrefix+path, body)
	stopClaim()
	// Any claim error/response loss is terminal for this delivery. Never cache a
	// permit for resubmit, re-claim here, or turn status into another installation.
	if e != nil || code != http.StatusOK {
		return "outcome_unknown"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	reference := actionpermit.Digest(raw)
	if pending.Kind == "readiness" {
		challenge, err := windowssoftwarejob.VerifyChallenge(raw, g.ManagerPublicKey)
		if err != nil || challenge.Binding != g.Binding || challenge.JobID != pending.JobID || challenge.Deadline != pending.Deadline || s.now().Unix() < challenge.IssuedAt || s.now().Unix() >= challenge.Deadline {
			return "denied"
		}
	} else {
		permit, err := windowssoftwarejob.Verify(raw, g.ManagerPublicKey)
		if err != nil || permit.Preview.Binding != g.Binding || permit.Preview.ID != pending.JobID || permit.Preview.ExpiresAt != pending.Deadline || s.now().Unix() < permit.ApprovedAt || s.now().Unix() >= permit.Preview.ExpiresAt {
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

func validWindowsSoftwareRelayStatus(s windowssoftwarejob.ExecutorStatus, now time.Time) bool {
	if s.ObservedAt <= 0 || s.ObservedAt > now.Unix() || now.Unix()-s.ObservedAt > 60 || s.Attempts == nil || len(s.Attempts) > windowssoftwarejob.MaxJobs || s.InstallCapacityRemaining != windowssoftwarejob.MaxJobs-len(s.Attempts) {
		return false
	}
	seen := map[string]bool{}
	entries := append([]windowssoftwarejob.EvidenceStatus{}, s.Attempts...)
	if s.Readiness != nil {
		if s.Readiness.Kind != "readiness" {
			return false
		}
		entries = append(entries, *s.Readiness)
	}
	for i, e := range entries {
		if i < len(s.Attempts) && e.Kind != "result" || !enrollmentcrypto.ValidID(e.JobID, "software_") || !actionpermit.ValidDigest(e.ReferenceDigest) || !windowssoftwarejob.ValidSelection(e.Selection) || e.Sequence == 0 || e.ClaimedAt <= 0 || e.Deadline <= e.ClaimedAt || e.ClaimedAt > s.ObservedAt || seen[e.Kind+e.JobID] {
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
func (s *windowsSoftwareJobSender) reconcile(ctx context.Context, g WindowsSoftwareRelayGrant, status windowssoftwarejob.ExecutorStatus) string {
	entries := append([]windowssoftwarejob.EvidenceStatus{}, status.Attempts...)
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
	for checked := 0; checked < len(entries) && attempts < windowsSoftwareRelayReportsPerPass; checked++ {
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
func (s *windowsSoftwareJobSender) report(ctx context.Context, g WindowsSoftwareRelayGrant, kind, id, reference string, deadline int64, raw []byte) bool {
	statement, e := windowssoftwarejob.VerifyStatement(raw, g.ExecutorPublicKey)
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
	response, code, e := s.exchange(reportContext, windowsSoftwareJobsRelayPrefix+"report", raw)
	if !s.recheck(ctx, g) || e != nil || code != http.StatusOK || !bytes.Equal(response, []byte("{}")) {
		return false
	}
	if s.delivered == nil {
		s.delivered = map[string]string{}
	}
	s.delivered[kind+id] = reference
	return true
}
func (s *windowsSoftwareJobSender) request(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	// Run/report completed their final grant/material/deadline check at this
	// send seam. Do not add a blocking material reload between that check and
	// Do; the original grant/claim/report expiry also bounds request.Context.
	if s.material.config.Profile != "tls" || ctx == nil || ctx.Err() != nil {
		return nil, 0, ErrState
	}
	limit := 0
	switch path {
	case windowsSoftwareJobsRelayPrefix + "poll":
		limit = 2
	case windowsSoftwareJobsRelayPrefix + "readiness-claim", windowsSoftwareJobsRelayPrefix + "install-claim":
		limit = 128
	case windowsSoftwareJobsRelayPrefix + "report":
		limit = windowssoftwarejob.MaxRelayBytes
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
	raw, e := io.ReadAll(io.LimitReader(response.Body, windowssoftwarejob.MaxRelayBytes+1))
	if e != nil || len(raw) == 0 || len(raw) > windowssoftwarejob.MaxRelayBytes || response.ContentLength >= 0 && response.ContentLength != int64(len(raw)) || len(response.Trailer) != 0 || !s.current(s.material) {
		return nil, 0, ErrTransport
	}
	return raw, response.StatusCode, nil
}
func runWindowsSoftwareJobLoop(ctx context.Context, s *windowsSoftwareJobSender) {
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
