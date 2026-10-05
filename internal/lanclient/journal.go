package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalstate"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
)

// journalSender has one cooperative serialized attempt and at most one bounded
// memory-only result. It never creates durable state or runs a journal source.
// Its private helper dependency is the sole capture boundary.
type journalSender struct {
	material Material
	state    *journalstate.State
	client   *http.Client
	now      func() time.Time
	local    func(Material) (journalLocal, error)
	helper   func(context.Context, journalLocal, journalhelper.Request) (journalhelper.Response, error)
	exchange func(context.Context, string, uint64, []byte) ([]byte, int, error)
	pending  *journalPending
}
type journalPending struct {
	memory         *journalMemory
	timer          *time.Timer
	done           chan struct{}
	grant          journalrequest.Grant
	permit         journalpolicy.Permit
	localRevision  string
	helperRevision string
	digest         string
}

func (journalPending) String() string               { return "journal result (content redacted)" }
func (p journalPending) Format(f fmt.State, _ rune) { io.WriteString(f, p.String()) }
func (journalPending) MarshalJSON() ([]byte, error) { return []byte(`{"contentRedacted":true}`), nil }
func (journalSender) String() string                { return "journal sender (content redacted)" }
func (s journalSender) Format(f fmt.State, _ rune)  { io.WriteString(f, s.String()) }
func (journalSender) MarshalJSON() ([]byte, error)  { return []byte(`{"contentRedacted":true}`), nil }
func openJournalSender(m Material) *journalSender {
	s := &journalSender{material: m, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), now: func() time.Time { return time.Now().UTC() }, local: loadJournalLocal, helper: callJournalHelper}
	s.exchange = s.request
	return s
}
func (s *journalSender) discard() {
	if s.pending != nil {
		p := s.pending
		if p.timer != nil {
			if p.timer.Stop() {
				close(p.done)
			} else {
				<-p.done
			}
		}
		p.memory.mu.Lock()
		clear(p.memory.raw)
		p.memory.raw = nil
		p.memory.expired = true
		p.memory.mu.Unlock()
		s.pending = nil
	}
}
func (s *journalSender) Close() {
	if s == nil {
		return
	}
	s.discard()
	if s.state != nil {
		s.state.Close()
	}
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *journalSender) status(ctx context.Context, id journalrequest.Identity, status string) {
	b, e := journalwire.EncodeStatus(journalwire.StatusInput{Identity: id, LocalStatus: status})
	if e == nil && ctx.Err() == nil {
		_, _, _ = s.exchange(ctx, journalwire.StatusPath, id.Sequence, b)
	}
}
func (s *journalSender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "unavailable"
	}
	if !s.material.config.complete() {
		return "disabled"
	}
	local, e := s.local(s.material)
	if e != nil {
		s.discard()
		if errors.Is(e, errJournalDisabled) {
			return "disabled"
		}
		return "denied"
	}
	disabled := local.policy.SchemaVersion == journalpolicy.VersionV3 && !local.policy.Enabled
	if disabled {
		s.discard()
	}
	if s.state == nil {
		s.state, e = journalstate.Open(ctx, journalStateDirectory(s.material.config), s.material.binding)
		if e != nil {
			return "state_unavailable"
		}
	}
	if local.generation != (journalgeneration.Tuple{}) {
		reportErr := s.reportGeneration(ctx, local)
		if disabled {
			return "disabled"
		}
		if reportErr != nil {
			return "unavailable"
		}
	}
	if disabled {
		return "disabled"
	}
	if s.pending != nil {
		return s.deliver(ctx, local)
	}
	body, _ := journalwire.EncodePeek()
	raw, code, e := s.exchange(ctx, journalwire.PeekPath, 1, body)
	if e != nil {
		return "unavailable"
	}
	if code == http.StatusNotFound || code == http.StatusNoContent {
		return "idle"
	}
	if code == http.StatusConflict {
		if journalErrorCode(raw) == "journal_accepted" {
			return "idle"
		}
		if journalErrorCode(raw) == "journal_expired" {
			return "expired"
		}
		return "result_lost"
	}
	if code != http.StatusOK {
		return "unavailable"
	}
	desc, e := journalwire.DecodeDescription(raw)
	if e != nil || desc.DeviceID != s.material.config.AgentID || desc.CertificateHash != journalLeaf(s.material) {
		return "denied"
	}
	now := s.now().UTC()
	if journalrequest.CheckTime(journalrequest.Record{Description: desc, State: journalrequest.Pending}, now) != nil {
		return "expired"
	}
	floor, e := s.state.SequenceFloor()
	if e != nil {
		return "state_unavailable"
	}
	if desc.Identity.Sequence <= floor {
		s.status(ctx, desc.Identity, "result_lost")
		return "result_lost"
	}
	permit, e := journalpolicy.AuthorizeBound(local.policy, journalContext(s.material, local), desc.Query, desc.PolicyGeneration, now)
	if e != nil {
		s.status(ctx, desc.Identity, "denied")
		return "denied"
	}
	// The policy is checked again immediately before committing the claim. No
	// helper query occurs until both server and local consumed markers commit.
	next, e := s.local(s.material)
	if e != nil || next.revision != local.revision || permit.Recheck(next.policy, journalContext(s.material, next), s.now().UTC()) != nil {
		return "denied"
	}
	claim := journalrequest.Claim{Identity: desc.Identity, PolicyDigest: permit.PolicyDigest()}
	body, e = journalwire.EncodeClaim(claim)
	if e != nil {
		return "denied"
	}
	raw, code, e = s.exchange(ctx, journalwire.ClaimPath, desc.Identity.Sequence, body)
	if e != nil {
		return "result_lost"
	}
	if code == http.StatusConflict {
		s.status(ctx, desc.Identity, "result_lost")
		return "result_lost"
	}
	if code != http.StatusOK {
		return "unavailable"
	}
	grant, e := journalwire.DecodeGrant(raw)
	if e != nil || grant.Description != desc || grant.PolicyDigest != permit.PolicyDigest() {
		return "denied"
	}
	consumed, e := s.state.Consume(ctx, journalCurrent(s.material, permit.PolicyDigest()), grant, s.now().UTC())
	if e != nil {
		if errors.Is(e, journalstate.ErrConsumed) {
			s.status(ctx, desc.Identity, "result_lost")
			return "result_lost"
		}
		if errors.Is(e, journalstate.ErrExpired) {
			return "expired"
		}
		return "state_unavailable"
	}
	next, e = s.local(s.material)
	if e != nil || next.revision != local.revision || permit.Recheck(next.policy, journalContext(s.material, next), s.now().UTC()) != nil {
		return "denied"
	}
	var response journalhelper.Response
	helperDenied := false
	e = s.state.Use(ctx, consumed, journalCurrent(s.material, permit.PolicyDigest()), s.now().UTC(), func(c context.Context, g journalrequest.Grant) error {
		latest, localErr := s.local(s.material)
		if localErr != nil || latest.revision != local.revision || permit.Recheck(latest.policy, journalContext(s.material, latest), s.now().UTC()) != nil {
			return errJournalDenied
		}
		var callErr error
		response, callErr = s.helper(c, latest, journalhelper.Request{Operation: journalhelper.QueryOperation, SenderBinding: s.material.binding, Query: g.Description.Query, PolicyGeneration: g.Description.PolicyGeneration})
		helperDenied = response.Status == journalhelper.StatusDenied
		if callErr != nil || response.Status != journalhelper.StatusSnapshot || response.PolicyDigest != permit.PolicyDigest() {
			return errJournalHelper
		}
		return nil
	})
	if e != nil {
		status := "helper_unavailable"
		if helperDenied {
			status = "denied"
		}
		s.status(ctx, desc.Identity, status)
		return status
	}
	payload := response.Body()
	defer clear(payload)
	var snapshot journalview.Snapshot
	if json.Unmarshal(payload, &snapshot) != nil {
		return "result_lost"
	}
	canonical, e := journalview.Encode(snapshot)
	if e != nil || !bytes.Equal(payload, canonical) || snapshot.Query != desc.Query || snapshot.ObservedAt.Before(grant.ClaimedAt) || snapshot.ObservedAt.After(s.now().UTC()) {
		clear(canonical)
		return "result_lost"
	}
	clear(canonical)
	body, e = journalwire.EncodeResult(journalwire.Result{Claim: claim, Snapshot: snapshot})
	if e != nil {
		return "result_lost"
	}
	digest, e := journalview.SnapshotDigest(snapshot)
	if e != nil {
		clear(body)
		return "result_lost"
	}
	s.pending = &journalPending{memory: &journalMemory{raw: body}, done: make(chan struct{}), grant: grant, permit: permit, localRevision: local.revision, helperRevision: response.Revision, digest: digest}
	s.pending.startExpiry()
	return s.deliver(ctx, next)
}
func (s *journalSender) deliver(ctx context.Context, local journalLocal) string {
	p := s.pending
	if p == nil {
		return "result_lost"
	}
	ctx, cancel := context.WithDeadline(ctx, p.grant.Description.ExpiresAt)
	defer cancel()
	p.memory.mu.Lock()
	expired := p.memory.expired
	p.memory.mu.Unlock()
	now := s.now().UTC()
	if expired || !now.Before(p.grant.Description.ExpiresAt) || now.Before(p.grant.ClaimedAt) {
		s.discard()
		return "expired"
	}
	if local.revision != p.localRevision || p.permit.Recheck(local.policy, journalContext(s.material, local), now) != nil {
		s.discard()
		return "denied"
	}
	response, e := s.helper(ctx, local, journalhelper.Request{Operation: journalhelper.VerifyOperation, SenderBinding: s.material.binding, Query: p.grant.Description.Query, PolicyGeneration: p.grant.Description.PolicyGeneration, PolicyDigest: p.grant.PolicyDigest, Revision: p.helperRevision})
	if e != nil {
		return "pending_retained"
	}
	if response.Status != journalhelper.StatusVerified || response.PolicyDigest != p.grant.PolicyDigest || response.Revision != p.helperRevision {
		s.discard()
		s.status(ctx, p.grant.Description.Identity, "denied")
		return "denied"
	}
	fresh, e := s.local(s.material)
	if e != nil || fresh.revision != p.localRevision || p.permit.Recheck(fresh.policy, journalContext(s.material, fresh), s.now().UTC()) != nil {
		s.discard()
		return "denied"
	}
	if !s.now().UTC().Before(p.grant.Description.ExpiresAt) {
		s.discard()
		return "expired"
	}
	if ctx.Err() != nil {
		return "pending_retained"
	}
	// Original immutable bytes are reused on every retry. Neither capture time nor
	// the fixed15m request expiry is refreshed, including after a lost receipt.
	p.memory.mu.Lock()
	if p.memory.expired || len(p.memory.raw) == 0 {
		p.memory.mu.Unlock()
		s.discard()
		return "expired"
	}
	raw, code, e := s.exchange(ctx, journalwire.ResultPath, p.grant.Description.Identity.Sequence, p.memory.raw)
	p.memory.mu.Unlock()
	if e != nil {
		return "pending_retained"
	}
	if code == http.StatusGone || code == http.StatusConflict {
		s.discard()
		return "result_lost"
	}
	if code != http.StatusOK {
		return "pending_retained"
	}
	receipt, e := journalwire.DecodeReceipt(raw)
	if e != nil || receipt.Identity != p.grant.Description.Identity || receipt.PolicyDigest != p.grant.PolicyDigest || receipt.ResultDigest != p.digest || !receipt.ExpiresAt.Equal(p.grant.Description.ExpiresAt) || receipt.AcceptedAt.Before(p.grant.ClaimedAt) || receipt.AcceptedAt.After(s.now().UTC().Add(30*time.Second)) {
		return "pending_retained"
	}
	s.discard()
	return "acknowledged"
}
func (s *journalSender) request(ctx context.Context, path string, sequence uint64, body []byte) ([]byte, int, error) {
	var req *http.Request
	var e error
	if s.material.config.Profile == "http-test" {
		req, e = journalwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, path, s.material.certificate, sequence, s.now().UTC(), body)
	} else {
		req, e = http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return nil, 0, errJournalDenied
	}
	response, e := s.client.Do(req)
	if e != nil {
		return nil, 0, errJournalHelper
	}
	defer response.Body.Close()
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, 0, errJournalHelper
	}
	limit := int64(4096)
	if path == journalwire.GenerationPath {
		limit = journalgeneration.MaxReportBytes
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if e != nil || int64(len(raw)) > limit {
		return nil, 0, errJournalHelper
	}
	return raw, response.StatusCode, nil
}

// Only exact fixed error enums affect local status; other server text is
// discarded and is never used as a diagnostic.
func journalErrorCode(raw []byte) string {
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if len(raw) > 256 || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	switch v.Error.Code {
	case "journal_accepted", "journal_expired":
		return v.Error.Code
	}
	return ""
}

func runJournalAttempt(ctx context.Context, s *journalSender) string {
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return s.Run(c)
}

// prune runs synchronously at each sender attempt, including metric failures.
// Expired or locally revoked unsent content is dropped without network/helper
// work. Expiry is also rechecked at every delivery boundary.
func (s *journalSender) prune() string {
	if s == nil || s.pending == nil {
		return ""
	}
	p := s.pending
	p.memory.mu.Lock()
	expired := p.memory.expired
	p.memory.mu.Unlock()
	now := s.now().UTC()
	if expired || !now.Before(p.grant.Description.ExpiresAt) || now.Before(p.grant.ClaimedAt) {
		s.discard()
		return "expired"
	}
	local, err := s.local(s.material)
	if err != nil {
		s.discard()
		if errors.Is(err, errJournalDisabled) {
			return "disabled"
		}
		return "denied"
	}
	if local.revision != p.localRevision || p.permit.Recheck(local.policy, journalContext(s.material, local), now) != nil {
		s.discard()
		return "denied"
	}
	return "pending_retained"
}

// Each current result owns at most one expiry callback. The callback touches
// only its private buffer under one lock; it never polls, reads, or transmits.
// An active send holds this lock and is separately bounded by the same expiry
// context. Stop/Close join the callback before replacing or releasing the slot.
// Clearing is best effort, not a guarantee about copies held by transport/GC.
func (p *journalPending) startExpiry() {
	p.timer = time.AfterFunc(time.Until(p.grant.Description.ExpiresAt), func() {
		p.memory.mu.Lock()
		clear(p.memory.raw)
		p.memory.raw = nil
		p.memory.expired = true
		p.memory.mu.Unlock()
		close(p.done)
	})
}

// Mutable content lives behind a pointer so diagnostic formatting can copy the
// immutable pending metadata without racing the expiry callback.
type journalMemory struct {
	mu      sync.Mutex
	raw     []byte
	expired bool
}
