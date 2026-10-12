package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	fence "localrmm/internal/windowsmutationfence"
)

// Storage must provide protected, exclusively locked, atomic durable writes.
// A failed/uncertain Write must permanently poison that storage session. It
// must not recreate missing used files or restore a previous valid snapshot.
// windowsstate.Store satisfies the endpoint method shape. Manager Open is a
// fixture seam only; production must use the enrollment-owned transaction store.
type Storage interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Verify() error
}

// Current is obtained from the live activated credential, never the request.
type Current struct {
	Binding        Binding
	LeafDigest     string
	LeafGeneration uint64
	LeafNotBefore  int64
	LeafNotAfter   int64
	Revoked        bool
	Enabled        bool
}

// Authority is the endpoint-local protected identity/credential/consent fence.
// It rejects locally known revocation and disabled/replaced grants, and never
// calls fn after returning. It cannot guarantee immediate manager revocation
// after a permit has been delivered. Manager persistence uses TransactionStore,
// never a file write wrapped in this interface. Renewal preserves job ages.
type Authority interface {
	WithCurrent(context.Context, Binding, func(Current) error) error
}

// ReadinessSource is an authenticated already-received readiness report lookup.
// It performs no host/network I/O while the short operator approval lease is held.
// Ordinary cached update telemetry cannot implement this interface by inference.
type ReadinessSource interface {
	Readiness(context.Context, Binding, Selection) (Readiness, error)
}

type Result struct {
	JobID          string `json:"jobId"`
	EnvelopeDigest string `json:"envelopeDigest"`
	Attempted      bool   `json:"attempted"`
	Outcome        string `json:"outcome"`
	// WUA OperationResultCode and HRESULT, not arbitrary error prose.
	OperationResult uint32 `json:"operationResult"`
	HResult         int32  `json:"hresult"`
	RebootRequired  Fact   `json:"rebootRequired"`
	CompletedAt     int64  `json:"completedAt"`
}

func (r Result) Validate() error {
	if !enrollmentcrypto.ValidID(r.JobID, "update_") || !actionpermit.ValidDigest(r.EnvelopeDigest) || !validTime(r.CompletedAt) || !fact(r.RebootRequired) {
		return ErrInvalid
	}
	switch r.Outcome {
	case "not_attempted":
		if r.Attempted || r.OperationResult != 0 || r.HResult != 0 || r.RebootRequired != Unknown {
			return ErrInvalid
		}
	case "succeeded":
		if !r.Attempted || r.OperationResult != 2 || r.HResult < 0 || r.RebootRequired == Unknown {
			return ErrInvalid
		}
	case "failed":
		if !r.Attempted || r.OperationResult != 4 && r.OperationResult != 5 {
			return ErrInvalid
		}
	case "uncertain":
		if !r.Attempted || r.OperationResult > 5 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Job struct {
	Occurrence         uint64           `json:"occurrence,string,omitempty"`
	RetirePermit       []byte           `json:"retirePermit,omitempty"`
	RetireClaimedAt    int64            `json:"retireClaimedAt,omitempty"`
	RetireReport       []byte           `json:"retireReport,omitempty"`
	Challenge          []byte           `json:"challenge"`
	ReadinessClaimedAt int64            `json:"readinessClaimedAt"`
	ReadinessReport    []byte           `json:"readinessReport"`
	ResultReport       []byte           `json:"resultReport"`
	ID                 string           `json:"id"`
	ActorID            string           `json:"actorId"`
	Selection          Selection        `json:"selection"`
	RequestedAt        int64            `json:"requestedAt"`
	State              string           `json:"state"`
	Reason             string           `json:"reason"`
	Preview            *Preview         `json:"preview"`
	ApprovedAt         int64            `json:"approvedAt"`
	Envelope           []byte           `json:"envelope"`
	ClaimedAt          int64            `json:"claimedAt"`
	Result             *Result          `json:"result"`
	Schedule           *ScheduledIntent `json:"schedule,omitempty"`
}
type Record struct {
	RetiredBaseFloor    uint64       `json:"retiredBaseFloor,string,omitempty"`
	RetiredBaseChain    string       `json:"retiredBaseChain,omitempty"`
	RetiredFloor        uint64       `json:"retiredFloor,string,omitempty"`
	RetiredChain        string       `json:"retiredChain,omitempty"`
	Recent              []RetiredJob `json:"recent,omitempty"`
	MutationReport      []byte       `json:"mutationReport,omitempty"`
	Version             string       `json:"version"`
	Consent             Consent      `json:"consent"`
	PublicKey           []byte       `json:"publicKey"`
	ExecutorPublicKey   []byte       `json:"executorPublicKey"`
	ClockFloor          int64        `json:"clockFloor"`
	Sequence            uint64       `json:"sequence,string"`
	ReadinessSequence   uint64       `json:"readinessSequence,string"`
	Jobs                []Job        `json:"jobs"`
	ScheduleGeneration  uint64       `json:"scheduleGeneration,string,omitempty"`
	ScheduleRevokedAt   int64        `json:"scheduleRevokedAt,omitempty"`
	SchedulePolicyFloor int64        `json:"schedulePolicyFloor,omitempty"`
}

// NewRecord only prepares bytes for a future separately authorized create-only
// provisioner. It writes nothing and is never called by Open, API or recovery.
func NewRecordWithExecutor(c Consent, key, executorKey ed25519.PublicKey, now int64) (Record, error) {
	r := Record{Version: Version, Consent: c, PublicKey: bytes.Clone(key), ExecutorPublicKey: bytes.Clone(executorKey), ClockFloor: now, Jobs: []Job{}}
	if c.Reusable() {
		r.Version = ReusableRecordVersion
	}
	if c.ScheduleAcknowledged {
		r.ScheduleGeneration = 1
	}
	return r, r.Validate()
}
func (r Record) Validate() error {
	if r.validateMutationReport() != nil {
		return ErrIntegrity
	}
	if (r.Consent.Reusable() && r.Version != ReusableRecordVersion || !r.Consent.Reusable() && r.Version != Version) || r.Consent.Validate() != nil || !keyvalidation.Ed25519(r.PublicKey) || !keyvalidation.Ed25519(r.ExecutorPublicKey) || actionpermit.Digest(r.ExecutorPublicKey) != r.Consent.Binding.ExecutorKeyID || actionpermit.Digest(r.PublicKey) != r.Consent.Binding.KeyID || !validTime(r.ClockFloor) || r.Jobs == nil || len(r.Jobs) > MaxJobs+1 {
		return ErrIntegrity
	}
	if r.validateReusable() != nil {
		return ErrIntegrity
	}
	if r.validateScheduleAuthority() != nil {
		return ErrIntegrity
	}
	ids := map[string]bool{}
	var seq, readinessSeq uint64
	for _, j := range r.Jobs {
		if !enrollmentcrypto.ValidID(j.ID, "update_") || !enrollmentcrypto.ValidID(j.ActorID, "operator_") || !ValidSelection(j.Selection) || !validTime(j.RequestedAt) || j.RequestedAt > r.ClockFloor || ids[j.ID] {
			return ErrIntegrity
		}
		ids[j.ID] = true
		challenge, err := VerifyChallenge(j.Challenge, r.PublicKey)
		if err != nil || challenge.Binding != r.Consent.Binding || challenge.JobID != j.ID || challenge.Selection != j.Selection || challenge.IssuedAt != j.RequestedAt || challenge.Sequence <= readinessSeq || challenge.Sequence > r.ReadinessSequence {
			return ErrIntegrity
		}
		readinessSeq = challenge.Sequence
		if j.ReadinessClaimedAt != 0 && (j.ReadinessClaimedAt < j.RequestedAt || j.ReadinessClaimedAt >= challenge.Deadline || j.ReadinessClaimedAt > r.ClockFloor) {
			return ErrIntegrity
		}
		if len(j.ReadinessReport) > 0 {
			statement, err := VerifyStatement(j.ReadinessReport, r.ExecutorPublicKey)
			if err != nil || statement.Kind != "readiness" || statement.Binding != r.Consent.Binding || statement.JobID != j.ID || statement.ReferenceDigest != actionpermit.Digest(j.Challenge) || j.Preview == nil || statement.Readiness == nil || *statement.Readiness != j.Preview.Readiness || statement.Deadline != challenge.Deadline {
				return ErrIntegrity
			}
		}
		if len(j.ResultReport) > 0 {
			statement, err := VerifyStatement(j.ResultReport, r.ExecutorPublicKey)
			if err != nil || statement.Kind != "result" || statement.Binding != r.Consent.Binding || statement.JobID != j.ID || j.Result == nil || statement.Result == nil || *statement.Result != *j.Result || statement.ReferenceDigest != actionpermit.Digest(j.Envelope) || j.Preview == nil || statement.Deadline != j.Preview.ExpiresAt {
				return ErrIntegrity
			}
		}

		if j.Preview != nil && (j.Preview.Validate() != nil || j.Preview.ID != j.ID || j.Preview.ActorID != j.ActorID || j.Preview.Binding != r.Consent.Binding || j.Preview.Readiness.Selection != j.Selection || j.Preview.CreatedAt < j.RequestedAt || j.Preview.CreatedAt > r.ClockFloor) {
			return ErrIntegrity
		}
		if j.Schedule != nil && r.validateScheduledJob(j) != nil {
			return ErrIntegrity
		}
		switch j.State {
		case "scheduled", "schedule_canceled", "schedule_blocked", "schedule_expired":
			if j.Schedule == nil || j.ClaimedAt != 0 || j.Result != nil {
				return ErrIntegrity
			}
		case "requested":
			if len(j.Envelope) != 0 || j.Preview != nil || j.Reason != "readiness_pending" {
				return ErrIntegrity
			}
		case "blocked":
			if len(j.Envelope) != 0 || j.Reason == "" || j.Reason == "ready" {
				return ErrIntegrity
			}
		case "preview":
			if len(j.Envelope) != 0 || j.Preview == nil || j.Preview.Readiness.Reason() != "ready" || j.Reason != "ready" {
				return ErrIntegrity
			}
		case "approved", "claimed", "complete":
			if j.Reason != "ready" || j.Preview == nil || len(j.Envelope) == 0 {
				return ErrIntegrity
			}
		default:
			return ErrIntegrity
		}
		if len(j.Envelope) > 0 {
			p, e := Verify(j.Envelope, r.PublicKey)
			if e != nil || p.Preview != *j.Preview || p.Sequence <= seq || p.ApprovedAt != j.ApprovedAt || j.ApprovedAt > r.ClockFloor {
				return ErrIntegrity
			}
			seq = p.Sequence
		} else if j.ApprovedAt != 0 || j.ClaimedAt != 0 || j.Result != nil {
			return ErrIntegrity
		}
		if j.State == "claimed" || j.State == "complete" {
			if j.ClaimedAt < j.ApprovedAt || j.ClaimedAt >= j.Preview.ExpiresAt || j.ClaimedAt > r.ClockFloor {
				return ErrIntegrity
			}
		} else if j.ClaimedAt != 0 {
			return ErrIntegrity
		}
		if j.State == "complete" {
			if j.Result == nil || j.Result.Validate() != nil || j.Result.JobID != j.ID || j.Result.EnvelopeDigest != actionpermit.Digest(j.Envelope) || j.Result.CompletedAt < j.ClaimedAt || j.Result.CompletedAt > r.ClockFloor {
				return ErrIntegrity
			}
		} else if j.Result != nil {
			return ErrIntegrity
		}
	}
	if (!r.Consent.Reusable() && (seq != r.Sequence || seq > MaxJobs || reservedOperations(r) > MaxJobs)) || readinessSeq != r.ReadinessSequence {
		return ErrIntegrity
	}
	return nil
}
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if canonical(raw, &r, MaxBytes) != nil || r.Validate() != nil {
		return Record{}, ErrIntegrity
	}
	return r, nil
}
func EncodeRecord(r Record) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrIntegrity
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxBytes {
		return nil, ErrIntegrity
	}
	return raw, nil
}

type Manager struct {
	transactionStore   TransactionStore
	configurationCheck func() error
	operatorAllowed    func(string) bool
	scheduleAllowed    func(string) bool
	binding            Binding
	mu                 sync.Mutex
	store              Storage
	authority          Authority
	source             ReadinessSource
	key                ed25519.PrivateKey
	now                func() time.Time
	record             Record
	raw                []byte
	failed             bool
}

func (*Manager) String() string   { return "<selected Windows update source manager>" }
func (*Manager) GoString() string { return "<selected Windows update source manager>" }
func (*Manager) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "<selected Windows update source manager>")
}
func (*Manager) MarshalJSON() ([]byte, error) { return []byte(`{"secretsRedacted":true}`), nil }

// Open never creates or repairs state. started.json and receipt.json bind the
// exact fresh consent; jobs.json is mandatory even when it has zero jobs.
func Open(store Storage, authority Authority, source ReadinessSource, key ed25519.PrivateKey, now func() time.Time) (*Manager, error) {
	if store == nil || authority == nil || source == nil || now == nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	raw, e := store.Read("jobs.json")
	r, e2 := DecodeRecord(raw)
	if e != nil || e2 != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), r.PublicKey) || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
		return nil, ErrIntegrity
	}
	m := &Manager{binding: r.Consent.Binding, store: store, authority: authority, source: source, key: bytes.Clone(key), now: now, record: r, raw: bytes.Clone(raw)}
	if e = m.check(); e != nil {
		return nil, e
	}
	return m, nil
}
func (m *Manager) Binding() Binding { return m.binding }
func (m *Manager) check() error {
	if m.failed || m.store.Verify() != nil {
		m.failed = true
		return ErrIntegrity
	}
	raw, e := m.store.Read("jobs.json")
	if e != nil || !bytes.Equal(raw, m.raw) {
		m.failed = true
		return ErrIntegrity
	}
	want, _ := json.Marshal(m.record.Consent)
	for _, name := range []string{"started.json", "receipt.json"} {
		raw, e = m.store.Read(name)
		if e != nil || !bytes.Equal(raw, want) {
			m.failed = true
			return ErrIntegrity
		}
	}
	return nil
}
func (m *Manager) current(c Current, n int64) error {
	if c.Binding != m.Binding() || !c.Enabled || c.Revoked || !actionpermit.ValidDigest(c.LeafDigest) || c.LeafGeneration == 0 || !m.record.Consent.Enabled || !m.record.Consent.Acknowledged {
		return ErrAuthority
	}
	if !validTime(n) || n < max(m.record.ClockFloor, m.record.SchedulePolicyFloor) || c.LeafNotBefore > n || n >= c.LeafNotAfter || n >= m.record.Consent.ExpiresAt {
		return ErrExpired
	}
	return nil
}
func (m *Manager) save(n int64) error {
	m.record.ClockFloor = n
	raw, e := EncodeRecord(m.record)
	if e != nil || m.transactionStore == nil && m.store.Write("jobs.json", raw) != nil {
		m.failed = true
		return ErrUncertain
	}
	m.raw = bytes.Clone(raw)
	return nil
}

// observeTime is durable even for reads and rejected/expired attempts. An
// expired request must not revive after a clock rollback or process restart.
func (m *Manager) observeTime() (int64, error) {
	n := m.now().UTC().Unix()
	if !validTime(n) || n < max(m.record.ClockFloor, m.record.SchedulePolicyFloor) {
		return n, ErrExpired
	}
	if n > m.record.ClockFloor {
		if e := m.save(n); e != nil {
			return n, e
		}
	}
	return n, nil
}
func (m *Manager) transaction(ctx context.Context, fn func(Current, int64) error) error {
	if ctx == nil {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if m.configurationCheck != nil {
		if e := m.configurationCheck(); e != nil {
			return e
		}
	}
	if m.transactionStore != nil {
		return m.enrollmentTransaction(ctx, fn)
	}
	if e := m.check(); e != nil {
		return e
	}
	if _, e := m.observeTime(); e != nil {
		return e
	}
	e := m.authority.WithCurrent(ctx, m.Binding(), func(c Current) error {
		n, e := m.observeTime()
		if e != nil {
			return e
		}
		if e := m.current(c, n); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		return fn(c, n)
	})
	if e != nil && !m.failed {
		saved, err := DecodeRecord(m.raw)
		if err != nil {
			m.failed = true
			return ErrIntegrity
		}
		m.record = saved
	}
	return e
}
func (m *Manager) blocked(n int64, except string) bool {
	if !m.record.Consent.Reusable() && reservedOperations(m.record) >= MaxJobs {
		return true
	}
	for _, j := range m.record.Jobs {
		if j.ID == except {
			continue
		}
		if m.record.Consent.Reusable() && j.Occurrence != 0 {
			if len(j.RetireReport) == 0 {
				return true
			}
			continue
		}
		if j.Schedule != nil && scheduleActive(j, n) {
			return true
		}
		if j.Schedule != nil && (j.State == "scheduled" || j.State == "schedule_canceled" || j.State == "schedule_blocked" || j.State == "schedule_expired") {
			continue
		}
		if j.State == "requested" {
			challenge, e := VerifyChallenge(j.Challenge, m.record.PublicKey)
			if e != nil || n < challenge.Deadline {
				return true
			}
			continue
		}
		if j.State == "preview" && n < j.Preview.ExpiresAt || j.State == "claimed" || j.State == "approved" && n < j.Preview.ExpiresAt || j.Result != nil && (j.Result.Outcome == "uncertain" || j.Result.Outcome == "failed") {
			return true
		}
	}
	return false
}
func (m *Manager) Request(ctx context.Context, device, actor, id string, s Selection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !enrollmentcrypto.ValidID(actor, "operator_") || !enrollmentcrypto.ValidID(id, "update_") || !ValidSelection(s) {
		return ErrInvalid
	}
	return m.transaction(ctx, func(c Current, n int64) error {
		for _, j := range m.record.Jobs {
			if j.ID == id {
				if j.ActorID == actor && j.Selection == s {
					return nil
				}
				return ErrConflict
			}
		}
		for _, old := range m.record.Recent {
			if old.JobID == id {
				return ErrConsumed
			}
		}
		if m.blocked(n, "") || m.record.ReadinessSequence == ^uint64(0) {
			return ErrConflict
		}
		// One replaceable unsigned readiness slot; approved/claimed/result records
		// are never pruned. A discarded unsigned preview can no longer approve.
		kept := make([]Job, 0, len(m.record.Jobs)+1)
		for _, old := range m.record.Jobs {
			if (len(old.Envelope) > 0 || old.Schedule != nil) && len(old.RetireReport) == 0 {
				kept = append(kept, old)
			}
		}
		m.record.Jobs = kept
		m.record.ReadinessSequence++
		challenge, err := SignChallenge(Challenge{Sequence: m.record.ReadinessSequence, Version: RelayVersion, Binding: m.Binding(), JobID: id, Selection: s, IssuedAt: n, Deadline: min(n+120, c.LeafNotAfter, m.record.Consent.ExpiresAt)}, m.key)
		if err != nil {
			return err
		}
		m.record.Jobs = append(m.record.Jobs, Job{Challenge: challenge, ID: id, ActorID: actor, Selection: s, RequestedAt: n, State: "requested", Reason: "readiness_pending"})
		if e := m.save(n); e != nil {
			return e
		}
		if m.source == nil {
			return nil
		}
		// Fixture-only source: production uses signed on-demand readiness reports.
		readiness, sourceErr := m.source.Readiness(ctx, m.Binding(), s)
		j := &m.record.Jobs[len(m.record.Jobs)-1]
		j.State = "blocked"
		j.Reason = "readiness_unavailable"
		observed, observeErr := m.observeTime()
		if observeErr != nil {
			return observeErr
		}
		n = observed
		if err := m.current(c, n); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if sourceErr == nil && readiness.Validate() == nil && readiness.Selection == s && readiness.CapturedAt <= n && n-readiness.CapturedAt <= 60 {
			deadline := min(n+60, c.LeafNotAfter, m.record.Consent.ExpiresAt, readiness.CapturedAt+60)
			if deadline > n {
				p := Preview{ID: id, ActorID: actor, Binding: m.Binding(), Readiness: readiness, CreatedAt: n, ExpiresAt: deadline}
				p.Digest = previewDigest(p)
				j.Preview = &p
				j.Reason = readiness.Reason()
				if j.Reason == "ready" {
					j.State = "preview"
				}
			}
		}
		return m.save(n)
	})
}
func (m *Manager) Approve(ctx context.Context, device, actor, id, d string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID || !ack || !enrollmentcrypto.ValidID(actor, "operator_") || !actionpermit.ValidDigest(d) {
		return ErrInvalid
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if j.Schedule != nil || j.ActorID != actor || j.Preview == nil || j.Preview.Digest != d {
				return ErrConflict
			}
			if len(j.Envelope) > 0 {
				return nil
			} // Exact saved approval; no re-sign or re-age.
			if j.State != "preview" || n >= j.Preview.ExpiresAt || m.blocked(n, j.ID) {
				return ErrExpired
			}
			// This observation protects the one-use approval from a known busy
			// peer; only the durable endpoint fence can admit native execution.
			if m.record.Consent.MutationPlanDigest != "" {
				shared, err := VerifyStatement(m.record.MutationReport, m.record.ExecutorPublicKey)
				if err != nil || shared.Kind != "mutation" || shared.Mutation == nil || !shared.Mutation.Active || shared.Mutation.Blocked || shared.Mutation.Phase != "idle" || shared.IssuedAt > n || n-shared.IssuedAt >= 60 || n >= shared.ExpiresAt {
					return ErrUnavailable
				}
			}
			if m.record.Sequence == ^uint64(0) {
				return ErrConflict
			}
			m.record.Sequence++
			p := Permit{Version: Version, Preview: *j.Preview, Sequence: m.record.Sequence, ApprovedAt: n}
			if m.record.Consent.Reusable() {
				j.Occurrence = m.record.Sequence
				p.Version = ReusablePermitVersion
			}
			raw, e := Sign(p, m.key)
			if e != nil {
				return e
			}
			j.Envelope = raw
			j.ApprovedAt = n
			j.State = "approved"
			return m.save(n)
		}
		return ErrConflict
	})
}

// Claim consumes delivery before returning bytes. Neither a repeated claim nor
// a lost response may re-deliver the envelope. TLS relay ingress is the only
// production delivery surface.
func (m *Manager) Claim(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var raw []byte
	e := m.transaction(ctx, func(_ Current, n int64) error {
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if m.transactionStore != nil && (m.operatorAllowed == nil || !m.operatorAllowed(j.ActorID)) {
				return ErrAuthority
			}
			if j.Schedule != nil && !m.scheduleAuthorized(j) {
				return ErrAuthority
			}
			if j.State != "approved" {
				return ErrConsumed
			}
			if n >= j.Preview.ExpiresAt {
				return ErrExpired
			}
			j.State = "claimed"
			j.ClaimedAt = n
			if e := m.save(n); e != nil {
				return e
			}
			raw = bytes.Clone(j.Envelope)
			return nil
		}
		return ErrConflict
	})
	if e != nil {
		return nil, e
	}
	return raw, nil
}

// Submit is a fixture-only unsigned metadata helper. Enrollment-owned managers
// reject it; production ingress must use the pinned executor-signature Report.
func (m *Manager) Submit(ctx context.Context, r Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transactionStore != nil {
		return ErrAuthority
	}
	if r.Validate() != nil {
		return ErrInvalid
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != r.JobID {
				continue
			}
			if j.Result != nil {
				if *j.Result == r {
					return nil
				}
				return ErrConflict
			}
			if j.State != "claimed" || r.EnvelopeDigest != actionpermit.Digest(j.Envelope) || r.CompletedAt < j.ClaimedAt || r.CompletedAt > n {
				return ErrConflict
			}
			j.Result = &r
			j.State = "complete"
			return m.save(n)
		}
		return ErrConflict
	})
}

type View struct {
	ReusableJobs         bool          `json:"reusableJobs,omitempty"`
	GrantExpiresAt       int64         `json:"grantExpiresAt,omitempty"`
	RetiredFloor         uint64        `json:"retiredFloor,string,omitempty"`
	BackgroundScheduling bool          `json:"backgroundScheduling,omitempty"`
	BackgroundExecutor   bool          `json:"backgroundExecutor,omitempty"`
	ExecutorAvailability string        `json:"executorAvailability,omitempty"`
	ExecutorObservedAt   int64         `json:"executorObservedAt,omitempty"`
	Coordinated          bool          `json:"coordinated,omitempty"`
	Mutation             *fence.Status `json:"mutation,omitempty"`
	MutationCapturedAt   int64         `json:"mutationCapturedAt,omitempty"`
	Version              string        `json:"version"`
	DeviceID             string        `json:"deviceId"`
	ServerNow            int64         `json:"serverNow"`
	Available            bool          `json:"available"`
	Reason               string        `json:"reason"`
	Job                  *PublicJob    `json:"job"`
	SchedulingAvailable  bool          `json:"schedulingAvailable,omitempty"`
	SchedulingRevoked    bool          `json:"schedulingRevoked,omitempty"`
}
type PublicJob struct {
	Occurrence   uint64          `json:"occurrence,string,omitempty"`
	ResultDigest string          `json:"resultDigest,omitempty"`
	Retirement   *RetirementView `json:"retirement,omitempty"`
	ID           string          `json:"id"`
	Selection    Selection       `json:"selection"`
	State        string          `json:"state"`
	Reason       string          `json:"reason"`
	Preview      *Preview        `json:"preview"`
	Result       *Result         `json:"result"`
	Schedule     *ScheduleView   `json:"schedule,omitempty"`
}

func (m *Manager) View(ctx context.Context, device, actor string, ids ...string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := View{Version: Version, DeviceID: device}
	if device != m.Binding().DeviceID || len(ids) > 1 || len(ids) == 1 && !enrollmentcrypto.ValidID(ids[0], "update_") {
		return v, ErrInvalid
	}
	e := m.transaction(ctx, func(_ Current, n int64) error {
		v.ServerNow = n
		if m.record.Consent.Reusable() {
			v.ReusableJobs = true
			v.GrantExpiresAt = m.record.Consent.ExpiresAt
			v.RetiredFloor = m.record.RetiredFloor
		}
		v.Coordinated = m.record.Consent.MutationPlanDigest != ""
		if m.record.Consent.Background() {
			v.BackgroundScheduling = m.record.Consent.ScheduleAcknowledged
			v.BackgroundExecutor = true
			v.ExecutorAvailability = "unknown"
		}
		if len(m.record.MutationReport) > 0 {
			report, _ := VerifyStatement(m.record.MutationReport, m.record.ExecutorPublicKey)
			v.Mutation = report.Mutation
			v.MutationCapturedAt = report.IssuedAt
			if v.BackgroundExecutor && report.Kind == "mutation" && report.Mutation != nil && report.Mutation.Active && report.IssuedAt <= n && n-report.IssuedAt < 60 && n < report.ExpiresAt {
				v.ExecutorAvailability = "verified_recent"
				v.ExecutorObservedAt = report.IssuedAt
			}
		}
		v.SchedulingAvailable = m.schedulingAvailable(actor)
		v.SchedulingRevoked = m.record.ScheduleRevokedAt != 0
		v.Available = !m.blocked(n, "")
		v.Reason = "ready"
		if !v.Available {
			v.Reason = "job_pending_or_intervention"
			if !m.record.Consent.Reusable() && reservedOperations(m.record) >= MaxJobs {
				v.Reason = "capacity_exhausted"
			}
		}
		if len(ids) == 1 && len(m.record.Jobs) == 0 {
			return ErrConflict
		}
		if len(m.record.Jobs) > 0 {
			j := m.record.Jobs[len(m.record.Jobs)-1]
			if len(ids) == 1 {
				found := false
				for _, candidate := range m.record.Jobs {
					if candidate.ID == ids[0] {
						j = candidate
						found = true
						break
					}
				}
				if !found {
					for _, old := range m.record.Recent {
						if old.JobID == ids[0] {
							p := retiredPublicJob(old)
							v.Job = &p
							return nil
						}
					}
					return ErrConflict
				}
			}
			public := publicJob(j, n, m.record.PublicKey)
			v.Job = &public
			if j.Schedule == nil && j.State == "requested" {
				challenge, _ := VerifyChallenge(j.Challenge, m.record.PublicKey)
				if n >= challenge.Deadline {
					v.Job.State = "expired"
				}
			}
			if j.Schedule == nil && j.Preview != nil && (j.State == "approved" || j.State == "preview") && n >= j.Preview.ExpiresAt {
				v.Job.State = "expired"
			}
			if j.Schedule == nil && j.ActorID == actor && j.State == "preview" && n < j.Preview.ExpiresAt {
				v.Job.Preview = j.Preview
			}
		}
		return nil
	})
	if e != nil {
		return View{}, e
	}
	raw, _ := json.Marshal(v)
	var copy View
	_ = json.Unmarshal(raw, &copy)
	return copy, nil
}
