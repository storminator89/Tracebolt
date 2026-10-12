package windowsaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowspath"
)

const PolicyVersion = "tracebolt.windows-service-action-policy.v1"
const LedgerVersion = "tracebolt.windows-service-action-ledger.v1"
const MaxJobs = 64

// Policy is protected LOCAL installation input. None of its private target
// configuration is accepted in remote requests or exposed in capabilities.
type Policy struct {
	Version             string  `json:"version"`
	Enabled             bool    `json:"enabled"`
	Binding             Binding `json:"binding"`
	PublicKey           []byte  `json:"publicKey"`
	BrokerSID           string  `json:"brokerSid"`
	AgentSID            string  `json:"agentSid"`
	Target              Target  `json:"target"`
	ReviewDigest        string  `json:"reviewDigest"`
	ProvisioningVersion string  `json:"provisioningVersion,omitempty"`
}
type Target struct {
	Name                string `json:"name"`
	Executable          string `json:"executable"`
	ExecutableDigest    string `json:"executableDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
	// A local reviewer explicitly classifies this as a standalone application,
	// excluding OS/security/connectivity agents. Name denylisting is supplementary.
	Classification string `json:"classification"`
}

func TargetDigest(t Target) string { b, _ := json.Marshal(t); return Digest(b) }
func GrantDigest(p Policy) string {
	p.Enabled = false
	p.Binding.GrantDigest = ""
	b, _ := json.Marshal(p)
	return Digest(b)
}
func ValidatePolicy(p Policy) error {
	if p.Version != PolicyVersion || (p.ProvisioningVersion != "" && p.ProvisioningVersion != ProvisionVersion) || !ValidBinding(p.Binding) || !keyvalidation.Ed25519(p.PublicKey) || p.Binding.KeyID != Digest(p.PublicKey) || !validSID(p.BrokerSID) || !validSID(p.AgentSID) || p.BrokerSID == p.AgentSID || !ValidDigest(p.ReviewDigest) || p.Target.Name != p.Binding.Target || p.Target.Classification != "reviewed-standalone-application" || !windowspath.Canonical(p.Target.Executable) || len(p.Target.Executable) < 7 || !ValidDigest(p.Target.ExecutableDigest) || !ValidDigest(p.Target.ConfigurationDigest) || TargetDigest(p.Target) != p.Binding.TargetDigest || GrantDigest(p) != p.Binding.GrantDigest {
		return ErrInvalid
	}
	return nil
}
func validSID(s string) bool { // Exact service SID, not LocalService/account SID.
	var n [5]uint64
	var end int
	// Reuse JSON's decimal parsing only after strict character and segment checks.
	const prefix = "S-1-5-80-"
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	parts := bytes.Split([]byte(s[len(prefix):]), []byte("-"))
	if len(parts) != 5 {
		return false
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 10 || len(p) > 1 && p[0] == '0' {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n[i] = n[i]*10 + uint64(c-'0')
		}
		if n[i] > 1<<32-1 {
			return false
		}
		if n[i] > 0 {
			end++
		}
	}
	return end > 0
}

type Storage interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Verify() error
}
type record struct {
	Envelope []byte `json:"envelope"`
	Result   Result `json:"result"`
}
type ledger struct {
	Version    string   `json:"version"`
	Binding    Binding  `json:"binding"`
	ClockFloor int64    `json:"clockFloor"`
	Sequence   uint64   `json:"sequence,string"`
	Jobs       []record `json:"jobs"`
}
type Snapshot struct {
	State       uint32
	AcceptsStop bool
	ProcessID   uint32
}

// Service owns a single held SCM handle and the pinned executable chain. Inspect
// rechecks exact config, ACL, file hashes and active dependents on that handle.
type Service interface {
	Inspect() (Snapshot, error)
	Start() error
	Stop() error
	Close() error
}
type Backend interface {
	Open(Target, string, string) (Service, error)
}
type peerCheckKey struct{}
type Broker struct {
	mu        sync.Mutex
	policy    Policy
	authority Storage
	state     Storage
	native    Backend
	now       func() time.Time
	wait      func(context.Context, time.Duration) error
	ledger    ledger
	poisoned  bool
}

func NewBroker(authority, state Storage, native Backend, now func() time.Time) (*Broker, error) {
	if authority == nil || state == nil || native == nil || now == nil {
		return nil, ErrInvalid
	}
	raw, e := authority.Read("policy.json")
	var p Policy
	if e != nil || DecodeCanonical(raw, &p, MaxMessageBytes) != nil || ValidatePolicy(p) != nil {
		return nil, ErrIntegrity
	}
	fence, e := authority.Read("started.json")
	want, _ := json.Marshal(p.Binding)
	if e != nil || !bytes.Equal(fence, want) {
		return nil, ErrIntegrity
	}
	receipt, e := authority.Read("receipt.json")
	if e != nil || !bytes.Equal(receipt, want) {
		return nil, ErrIntegrity
	}
	raw, e = state.Read("ledger.json")
	var l ledger
	if e != nil || DecodeCanonical(raw, &l, 512<<10) != nil || validateLedger(l, p) != nil {
		return nil, ErrIntegrity
	}
	b := &Broker{policy: p, authority: authority, state: state, native: native, now: now, ledger: l, wait: waitContext}
	if e = b.check(); e != nil {
		return nil, e
	}
	// Reopened admission/dispatch is never executed. Crash state is permanent,
	// status-only and blocks later actions until separately reviewed intervention.
	for i := range b.ledger.Jobs {
		r := &b.ledger.Jobs[i].Result
		if r.Phase != "complete" {
			r.Phase = "complete"
			r.Outcome = "intervention-required"
		}
	}
	if e = b.save(); e != nil {
		return nil, e
	}
	return b, nil
}
func waitContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func validateLedger(l ledger, p Policy) error {
	if l.Version != LedgerVersion || l.Binding != p.Binding || l.ClockFloor <= 0 || l.ClockFloor > 253402300799 || l.Jobs == nil || len(l.Jobs) > MaxJobs || (len(l.Jobs) == 0 && l.Sequence != 0 || len(l.Jobs) > 0 && l.Sequence != l.Jobs[len(l.Jobs)-1].Result.Identity.Sequence) {
		return ErrIntegrity
	}
	ids := map[string]bool{}
	var previous uint64
	for _, j := range l.Jobs {
		permit, e := CheckSignature(j.Envelope, ed25519.PublicKey(p.PublicKey))
		id, _ := IdentityFor(j.Envelope)
		if e != nil || permit.Binding != p.Binding || permit.Sequence <= previous || ids[permit.JobID] || ValidateResult(j.Result) != nil || j.Result.Identity != id || j.Result.Operation != permit.Operation || j.Result.Target != permit.Binding.Target || j.Result.Deadline != permit.Deadline {
			return ErrIntegrity
		}
		ids[permit.JobID] = true
		previous = permit.Sequence
	}
	return nil
}
func (b *Broker) check() error {
	if guard, ok := b.native.(interface{ ValidateRuntime(Policy) error }); ok {
		if e := guard.ValidateRuntime(b.policy); e != nil {
			return e
		}
	}
	if b.poisoned || b.authority.Verify() != nil || b.state.Verify() != nil {
		return ErrIntegrity
	}
	raw, e := b.authority.Read("policy.json")
	expected, _ := json.Marshal(b.policy)
	if e != nil || !bytes.Equal(raw, expected) {
		return ErrBinding
	}
	now := b.now().UTC().Unix()
	if now < b.ledger.ClockFloor || now <= 0 || now > 253402300799 {
		return ErrExpired
	}
	return nil
}
func (b *Broker) save() error { return b.saveAt(b.now().UTC()) }

// saveAt commits the exact time used for an admission/expiry decision.
func (b *Broker) saveAt(observed time.Time) error {
	if b.poisoned {
		return ErrIntegrity
	}
	n := observed.Unix()
	if n <= 0 || n > 253402300799 || n < b.ledger.ClockFloor {
		return ErrExpired
	}
	b.ledger.ClockFloor = n
	raw, e := json.Marshal(b.ledger)
	if e != nil || validateLedger(b.ledger, b.policy) != nil || b.state.Write("ledger.json", raw) != nil {
		b.poisoned = true
		return ErrIntegrity
	}
	return nil
}
func (b *Broker) blocked() bool {
	for _, j := range b.ledger.Jobs {
		if j.Result.Phase != "complete" || j.Result.Outcome == "intervention-required" {
			return true
		}
	}
	return len(b.ledger.Jobs) >= MaxJobs
}
func (b *Broker) Capabilities() (Capabilities, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.check(); e != nil {
		return Capabilities{}, e
	}
	if e := b.save(); e != nil {
		return Capabilities{}, e
	}
	return Capabilities{CapabilitiesVersion, b.policy.Binding, b.ledger.ClockFloor, b.policy.Enabled, b.blocked()}, nil
}
func (b *Broker) Status(id Identity) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !ValidIdentity(id) {
		return Result{}, ErrInvalid
	}
	if e := b.check(); e != nil {
		return Result{}, e
	}
	for _, j := range b.ledger.Jobs {
		if j.Result.Identity == id {
			if e := b.save(); e != nil {
				return Result{}, e
			}
			return j.Result, nil
		}
	}
	return Result{}, ErrUnavailable
}
func (b *Broker) Submit(ctx context.Context, raw []byte) (out Result, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return out, ErrExpired
	}
	if e := b.check(); e != nil {
		return out, e
	}
	checkedAt := b.now().UTC()
	p, e := Verify(raw, ed25519.PublicKey(b.policy.PublicKey), b.policy.Binding, checkedAt)
	if saveErr := b.saveAt(checkedAt); saveErr != nil {
		return out, saveErr
	}
	if e != nil {
		return out, e
	}
	if !b.policy.Enabled {
		return out, ErrUnavailable
	}
	if b.blocked() {
		return out, ErrBusy
	}
	if p.Sequence <= b.ledger.Sequence {
		return out, ErrConsumed
	}
	for _, j := range b.ledger.Jobs {
		if j.Result.Identity.JobID == p.JobID {
			return out, ErrConsumed
		}
	}
	id, _ := IdentityFor(raw)
	out = Result{Version: ResultVersion, Identity: id, Operation: p.Operation, Target: p.Binding.Target, Deadline: p.Deadline, Phase: "admitted", Outcome: "not-requested"}
	b.ledger.Jobs = append(b.ledger.Jobs, record{bytes.Clone(raw), out})
	b.ledger.Sequence = p.Sequence
	update := func() error { b.ledger.Jobs[len(b.ledger.Jobs)-1].Result = out; return b.save() }
	if e = update(); e != nil {
		return out, e
	}
	started := b.now().UTC()
	deadline := time.Unix(p.Deadline, 0).UTC()
	if limit := started.Add(45 * time.Second); limit.Before(deadline) {
		deadline = limit
	}
	check := func() error {
		if checkPeer, ok := ctx.Value(peerCheckKey{}).(func() error); ok {
			if e := checkPeer(); e != nil {
				return e
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := b.check(); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Sample only AFTER synchronous authority checks. A valid decision is
		// never carried across a slow store call into an expired native effect.
		now := b.now().UTC()
		if now.Before(started) || !now.Before(deadline) {
			if !now.Before(started) {
				if e := b.saveAt(now); e != nil {
					return e
				}
			}
			return ErrExpired
		}
		_, e := Verify(raw, ed25519.PublicKey(b.policy.PublicKey), b.policy.Binding, now)
		if e != nil {
			if saveErr := b.saveAt(now); saveErr != nil {
				return saveErr
			}
		}
		return e
	}
	defer func() {
		out.Phase = "complete"
		if err != nil && (out.StartAttempted || out.StopAttempted) {
			out.Outcome = "intervention-required"
		}
		if e := update(); e != nil {
			err = e
			out.Outcome = "intervention-required"
		}
	}()
	if err = check(); err != nil {
		return out, err
	}
	s, e := b.native.Open(b.policy.Target, b.policy.BrokerSID, b.policy.AgentSID)
	if s != nil {
		defer func() {
			if e := s.Close(); e != nil {
				err = ErrUnavailable
			}
			if e := check(); e != nil {
				err = e
			}
		}()
	}
	if e != nil || s == nil {
		return out, ErrUnavailable
	}
	observe := func() (Snapshot, error) {
		if e := check(); e != nil {
			return Snapshot{}, e
		}
		if out.Observations >= 184 {
			return Snapshot{}, ErrExpired
		}
		v, e := s.Inspect()
		out.Observations++
		if e != nil {
			return Snapshot{}, e
		}
		if e = check(); e != nil {
			return Snapshot{}, e
		}
		if v.State < 1 || v.State > 7 {
			return Snapshot{}, ErrUnavailable
		}
		out.LastObservedState = v.State
		if v.State == 1 && out.StopRequested {
			out.StoppedObserved = true
		}
		if v.State == 4 && v.ProcessID > 0 && out.StartRequested {
			out.RunningObserved = true
		}
		return v, nil
	}
	v, e := observe()
	if e != nil {
		return out, e
	}
	initial := uint32(4)
	if p.Operation == Start {
		initial = 1
	}
	if v.State != initial || initial == 4 && (v.ProcessID == 0 || !v.AcceptsStop) {
		return out, ErrUnavailable
	}
	// Initial observations are historical, but completion flags describe the
	// requested transition. Reset these before persist-before-effect dispatch.
	out.RunningObserved = false
	out.StoppedObserved = false
	out.Phase = "dispatching"
	if err = update(); err != nil {
		return out, err
	}
	poll := func(want, previous, pending uint32) error {
		for {
			v, e := observe()
			if e != nil {
				return e
			}
			if v.State == want && (want != 4 || v.ProcessID > 0) {
				return nil
			}
			if v.State != previous && v.State != pending {
				return ErrUnavailable
			}
			if e = b.wait(ctx, 250*time.Millisecond); e != nil {
				return e
			}
		}
	}
	control := func(start bool) error {
		// Recheck grant, original deadline, exact held configuration and required
		// prestate directly before each single control. No reopen by target name.
		v, e := observe()
		if e != nil {
			return e
		}
		want := uint32(4)
		if start {
			want = 1
		}
		if v.State != want || !start && (!v.AcceptsStop || v.ProcessID == 0) {
			return ErrUnavailable
		}
		if e = check(); e != nil {
			return e
		}
		out.Outcome = "intervention-required"
		if start {
			out.StartAttempted = true
		} else {
			out.StopAttempted = true
		}
		if e = update(); e != nil {
			return e
		}
		// Storage calls are synchronous. Reinspect after the durable dispatch
		// write so slow persistence cannot separate config/state verification
		// from the control by an unbounded interval.
		v, e = observe()
		if e != nil {
			return e
		}
		if v.State != want || !start && (!v.AcceptsStop || v.ProcessID == 0) {
			return ErrUnavailable
		}
		if e = check(); e != nil {
			return e
		}
		if start {
			e = s.Start()
			if e == nil {
				out.StartRequested = true
			}
		} else {
			e = s.Stop()
			if e == nil {
				out.StopRequested = true
			}
		}
		if saveErr := update(); saveErr != nil {
			return saveErr
		}
		if e != nil {
			return ErrUnavailable
		}
		return check()
	}
	if p.Operation == Stop || p.Operation == Restart {
		if err = control(false); err != nil {
			return out, err
		}
		if err = poll(1, 4, 3); err != nil {
			return out, err
		}
	}
	if p.Operation == Start || p.Operation == Restart {
		if err = control(true); err != nil {
			return out, err
		}
		if err = poll(4, 1, 2); err != nil {
			return out, err
		}
	}
	v, err = observe()
	if err != nil {
		return out, err
	}
	wantFinal := uint32(4)
	if p.Operation == Stop {
		wantFinal = 1
	}
	if v.State != wantFinal || wantFinal == 4 && v.ProcessID == 0 {
		return out, ErrUnavailable
	}
	if err = check(); err != nil {
		return out, err
	}
	out.Outcome = "running-observed"
	if p.Operation == Stop {
		out.Outcome = "stopped-observed"
	}
	return out, nil
}
