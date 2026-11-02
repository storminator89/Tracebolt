package windowssoftwarejob

import (
	"bytes"
	"context"
	"localrmm/internal/operatorauth"
	"sync"
)

type accountReceipt struct {
	id, actor           string
	epoch               uint64
	absent              bool
	challenge, envelope []byte
}
type accountReceiptKey struct{}

// ConfigureAccountAuthority is trusted startup wiring. Missing callbacks retain
// only legacy static behavior; live-mode startup must require this callback.
func (m *Manager) ConfigureAccountAuthority(admit operatorauth.ActorAdmission) error {
	if m == nil || admit == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accountAuthority != nil {
		return ErrConflict
	}
	m.accountAuthority = admit
	return nil
}
func (r *Registry) ConfigureAccountAuthority(admit operatorauth.ActorAdmission) error {
	if r == nil || admit == nil {
		return ErrInvalid
	}
	for _, m := range r.Managers() {
		if e := m.ConfigureAccountAuthority(admit); e != nil {
			return e
		}
	}
	return nil
}
func addAccountReceipt(ctx context.Context, r accountReceipt) context.Context {
	old, _ := ctx.Value(accountReceiptKey{}).([]accountReceipt)
	next := append(append([]accountReceipt(nil), old...), r)
	return context.WithValue(ctx, accountReceiptKey{}, next)
}
func (m *Manager) checkAccountReceipt(ctx context.Context) error {
	receipts, _ := ctx.Value(accountReceiptKey{}).([]accountReceipt)
	for _, want := range receipts {
		found := false
		for _, j := range m.record.Jobs {
			if j.ID == want.id {
				found = true
				if want.challenge != nil && (!bytes.Equal(want.challenge, j.Challenge) || !bytes.Equal(want.envelope, j.Envelope)) {
					return ErrAuthority
				}
				actor, epoch := j.ActorID, j.AuthorityEpoch

				if actor != want.actor || epoch != want.epoch {
					return ErrAuthority
				}
			}
		}
		if !found && !want.absent {
			return ErrConflict
		}
	}
	return nil
}
func (m *Manager) accountCaps(j Job) []operatorauth.Capability {
	caps := []operatorauth.Capability{operatorauth.WindowsSoftwareInstall}

	return caps
}

// Snapshot the immutable receipt under the job mutex, release it, then acquire
// actor admission. The actual durable transaction rechecks the exact receipt.
func (m *Manager) leaseJob(ctx context.Context, id string) (context.Context, func(), error) {
	if ctx == nil {
		return ctx, nil, ErrInvalid
	}
	m.mu.Lock()
	admit := m.accountAuthority
	if admit == nil {
		m.mu.Unlock()
		return ctx, func() {}, nil
	}
	var job Job
	found := false
	for _, j := range m.record.Jobs {
		if j.ID == id {
			job = j
			found = true
			break
		}
	}
	m.mu.Unlock()
	if !found {
		return ctx, nil, ErrConflict
	}
	actor, epoch := job.ActorID, job.AuthorityEpoch

	next, release, e := admit(ctx, actor, epoch, m.accountCaps(job)...)
	if e != nil {
		return ctx, nil, ErrAuthority
	}
	return addAccountReceipt(next, accountReceipt{id: id, actor: actor, epoch: epoch, challenge: bytes.Clone(job.Challenge), envelope: bytes.Clone(job.Envelope)}), release, nil
}
func (m *Manager) leaseRequest(ctx context.Context, actor, id string) (context.Context, func(), error) {
	if ctx == nil {
		return ctx, nil, ErrInvalid
	}
	m.mu.Lock()
	admit := m.accountAuthority
	m.mu.Unlock()
	if admit == nil {
		return ctx, func() {}, nil
	}
	caps := []operatorauth.Capability{operatorauth.WindowsSoftwareInstall}

	epoch := operatorauth.ApprovalEpochFromContext(ctx)
	next, release, e := admit(ctx, actor, epoch, caps...)
	if e != nil {
		return ctx, nil, ErrAuthority
	}
	if id != "" {
		next = addAccountReceipt(next, accountReceipt{id: id, actor: actor, epoch: epoch, absent: true})
	}
	return next, release, nil
}

// BeginResponseAdmission reacquires exact current authority after claim/encoding
// waits. It does not mint or undo a claim. Hold release through bounded Write.
func (m *Manager) BeginResponseAdmission(ctx context.Context, raw []byte) (func(), error) {
	if len(raw) == 0 {
		return nil, ErrAuthority
	}
	m.mu.Lock()
	admit := m.accountAuthority
	if admit == nil {
		m.mu.Unlock()
		return func() {}, nil
	}
	id := ""
	for _, j := range m.record.Jobs {
		if bytes.Equal(raw, j.Challenge) || bytes.Equal(raw, j.Envelope) {
			id = j.ID
			break
		}

	}
	m.mu.Unlock()
	if id == "" {
		return nil, ErrAuthority
	}
	next, release, e := m.leaseJob(ctx, id)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	e = m.checkAccountReceipt(next)
	exact := false
	for _, j := range m.record.Jobs {
		if j.ID == id && (bytes.Equal(raw, j.Challenge) || bytes.Equal(raw, j.Envelope)) {
			exact = true
		}
	}
	if !exact {
		e = ErrAuthority
	}
	m.mu.Unlock()
	if e != nil {
		release()
		return nil, e
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

func (m *Manager) leaseReadinessReport(ctx context.Context, raw []byte) (context.Context, func(), error) {
	m.mu.Lock()
	configured := m.accountAuthority != nil
	key := bytes.Clone(m.record.ExecutorPublicKey)
	m.mu.Unlock()
	if !configured {
		return ctx, func() {}, nil
	}
	statement, e := VerifyStatement(raw, key)
	if e != nil || statement.Kind != "readiness" {
		return ctx, func() {}, nil
	} // authoritative parser still rejects invalid reports
	return m.leaseJob(ctx, statement.JobID)
}

// CheckAccountTransition prevents a later account grant from rebinding retained
// approval metadata. Compaction remains governed by existing consume/retire floors.
func CheckAccountTransition(before, after Record) error {
	old := map[string]Job{}
	for _, j := range before.Jobs {
		old[j.ID] = j
	}
	for _, j := range after.Jobs {
		prior, exists := old[j.ID]
		if !exists {
			continue
		}
		if j.AuthorityEpoch != prior.AuthorityEpoch {
			return ErrIntegrity
		}

	}
	return nil
}

// AccountAuthorityConfigured reports trusted startup wiring for bounded handoff.
func (m *Manager) AccountAuthorityConfigured() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.accountAuthority != nil
}
