package windowsupdatejob

import (
	"bytes"
	"context"
	"localrmm/internal/operatorauth"
	"sort"
	"sync"
)

type accountReceipt struct {
	id, actor           string
	epoch               uint64
	absent, retirement  bool
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
				if want.retirement {
					p, e := VerifyRetirement(j.RetirePermit, m.record.PublicKey)
					if e != nil {
						return ErrAuthority
					}
					actor, epoch = p.ActorID, j.RetireAuthorityEpoch
				}
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
	caps := []operatorauth.Capability{operatorauth.WindowsUpdateInstall}
	if j.Download() {
		caps[0] = operatorauth.WindowsUpdateDownload
	}
	if j.Schedule != nil {
		caps = append(caps, operatorauth.WindowsUpdateSchedule)
	}
	return caps
}

// Snapshot the immutable receipt under the job mutex, release it, then acquire
// actor admission. The actual durable transaction rechecks the exact receipt.
func (m *Manager) leaseJob(ctx context.Context, id string, retirement bool) (context.Context, func(), error) {
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
	if retirement {
		p, e := VerifyRetirement(job.RetirePermit, m.PublicKey())
		if e != nil {
			return ctx, nil, ErrAuthority
		}
		actor, epoch = p.ActorID, job.RetireAuthorityEpoch
	}
	caps := m.accountCaps(job)
	if retirement {
		caps = caps[:1]
	}
	next, release, e := admit(ctx, actor, epoch, caps...)
	if e != nil {
		return ctx, nil, ErrAuthority
	}
	return addAccountReceipt(next, accountReceipt{id: id, actor: actor, epoch: epoch, retirement: retirement, challenge: bytes.Clone(job.Challenge), envelope: bytes.Clone(job.Envelope)}), release, nil
}
func (m *Manager) leaseRequest(ctx context.Context, actor, id string, scheduled bool) (context.Context, func(), error) {
	if ctx == nil {
		return ctx, nil, ErrInvalid
	}
	m.mu.Lock()
	admit := m.accountAuthority
	m.mu.Unlock()
	if admit == nil {
		return ctx, func() {}, nil
	}
	caps := []operatorauth.Capability{operatorauth.WindowsUpdateInstall}
	if downloadRequest(ctx) {
		caps[0] = operatorauth.WindowsUpdateDownload
	}
	if scheduled {
		caps = append(caps, operatorauth.WindowsUpdateSchedule)
	}
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
	retirement := false
	for _, j := range m.record.Jobs {
		if bytes.Equal(raw, j.Challenge) || bytes.Equal(raw, j.Envelope) {
			id = j.ID
			break
		}
		if len(j.RetirePermit) > 0 && bytes.Equal(raw, j.RetirePermit) {
			id = j.ID
			retirement = true
			break
		}
	}
	m.mu.Unlock()
	if id == "" {
		return nil, ErrAuthority
	}
	next, release, e := m.leaseJob(ctx, id, retirement)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	e = m.checkAccountReceipt(next)
	exact := false
	for _, j := range m.record.Jobs {
		if j.ID == id && (bytes.Equal(raw, j.Challenge) || bytes.Equal(raw, j.Envelope) || bytes.Equal(raw, j.RetirePermit)) {
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
	return m.leaseJob(ctx, statement.JobID, false)
}

type deniedAccountSchedulesKey struct{}

func (m *Manager) leaseSchedules(ctx context.Context) (context.Context, func(), error) {
	m.mu.Lock()
	configured := m.accountAuthority != nil
	jobs := []Job{}
	if configured {
		for _, j := range m.record.Jobs {
			if j.Schedule != nil && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
				jobs = append(jobs, j)
			}
		}
	}
	m.mu.Unlock()
	releases := []func(){}
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	denied := map[string]bool{}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].ActorID == jobs[j].ActorID {
			return jobs[i].ID < jobs[j].ID
		}
		return jobs[i].ActorID < jobs[j].ActorID
	})
	for _, job := range jobs {
		id := job.ID
		if ctx.Err() != nil {
			releaseAll()
			return ctx, nil, ctx.Err()
		}
		next, release, e := m.leaseJob(ctx, id, false)
		if e != nil {
			if ctx.Err() != nil {
				releaseAll()
				return ctx, nil, ctx.Err()
			}
			denied[id] = true
			continue
		}
		ctx = next
		releases = append(releases, release)
	}
	return context.WithValue(ctx, deniedAccountSchedulesKey{}, denied), releaseAll, nil
}
func (m *Manager) blockDeniedAccountSchedules(ctx context.Context, n int64) error {
	denied, _ := ctx.Value(deniedAccountSchedulesKey{}).(map[string]bool)
	changed := false
	// A scheduler may have appeared while admission waited outside m.mu. Never
	// trigger an occurrence not covered by this invocation's authority snapshot.
	if m.accountAuthority != nil {
		receipts, _ := ctx.Value(accountReceiptKey{}).([]accountReceipt)
		admitted := map[string]bool{}
		for _, r := range receipts {
			admitted[r.id] = true
		}
		for _, j := range m.record.Jobs {
			if j.Schedule != nil && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") && !denied[j.ID] && !admitted[j.ID] {
				return ErrConflict
			}
		}
	}
	for i := range m.record.Jobs {
		j := &m.record.Jobs[i]
		if denied[j.ID] && j.Schedule != nil && (j.State == "scheduled" || j.State == "requested" || j.State == "approved") {
			j.State = "schedule_blocked"
			j.Reason = "schedule_authority_revoked"
			j.Schedule.OutcomeAt = n
			changed = true
		}
	}
	if changed {
		return m.save(n)
	}
	return nil
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
		if (len(prior.RetirePermit) > 0 || len(j.RetirePermit) == 0) && j.RetireAuthorityEpoch != prior.RetireAuthorityEpoch {
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
