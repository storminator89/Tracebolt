package operatorauth

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
)

// Capability is an explicit server-configured grant. No capability implies
// another; privileged routes must admit their own specific grant.
type Capability string

const (
	Read                    Capability = "read"
	PlanUpdates             Capability = "plan_updates"
	ExecuteUpdates          Capability = "execute_updates"
	RestartService          Capability = "restart_service"
	ManageAlarms            Capability = "manage_alarms"
	ManageApplicationChecks Capability = "manage_application_checks"
	MaxOperators                       = 32
)

// Operator is trusted startup configuration, never request-supplied identity.
// Provisioning this record is a separate, explicit administrator operation.
type Operator struct {
	ID           string
	Username     string
	PasswordHash string `json:"-"`
	Capabilities []Capability
}

func (Operator) String() string   { return "operatorauth.Operator{secrets:redacted}" }
func (Operator) GoString() string { return "operatorauth.Operator{secrets:redacted}" }

type principal struct {
	id       string
	username string
	grants   uint8
	verifier verifier
}

func capabilityBit(c Capability) uint8 {
	switch c {
	case Read:
		return 1
	case PlanUpdates:
		return 2
	case ExecuteUpdates:
		return 4
	case RestartService:
		return 8
	case ManageAlarms:
		return 16
	case ManageApplicationChecks:
		return 32
	default:
		return 0
	}
}

func validUsername(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-' || c == '.') {
			continue
		}
		return false
	}
	return true
}

func namedPrincipals(operators []Operator) (map[string]principal, error) {
	if len(operators) < 1 || len(operators) > MaxOperators {
		return nil, ErrConfiguration
	}
	out := make(map[string]principal, len(operators))
	ids := make(map[string]bool, len(operators))
	var work verifier
	for i, op := range operators {
		if !enrollmentcrypto.ValidID(op.ID, "operator_") || !validUsername(op.Username) || ids[op.ID] {
			return nil, ErrConfiguration
		}
		if _, exists := out[op.Username]; exists {
			return nil, ErrConfiguration
		}
		v, err := parseHash(op.PasswordHash)
		if err != nil {
			return nil, ErrConfiguration
		}
		// Match work factors so an unknown username receives the same bounded
		// password-hash workload as any configured account.
		if i > 0 && (v.memory != work.memory || v.iterations != work.iterations || v.parallelism != work.parallelism) {
			return nil, ErrConfiguration
		}
		work = v
		var grants uint8
		for _, c := range op.Capabilities {
			bit := capabilityBit(c)
			if bit == 0 || grants&bit != 0 {
				return nil, ErrConfiguration
			}
			grants |= bit
		}
		// Every account must explicitly include read; no mutation grant adds it.
		if grants&capabilityBit(Read) == 0 {
			return nil, ErrConfiguration
		}
		out[op.Username] = principal{id: op.ID, username: op.Username, verifier: v, grants: grants}
		ids[op.ID] = true
	}
	return out, nil
}

// Named reports the configured login mode without disclosing account names.
func (m *Manager) Named() bool { return len(m.operators) != 0 }

// ActorID comes only from the authenticated server-side configuration. Legacy
// shared sessions deliberately have no named human actor.
func (s Session) ActorID() string { return s.actor.id }
func (s Session) Named() bool     { return s.actor.id != "" }

// Capabilities returns a defensive display snapshot, not a mutation permit.
// Call BeginCapability immediately before short privileged dispatch work.
func (s Session) Capabilities() []Capability {
	out := make([]Capability, 0, 6)
	for _, c := range []Capability{Read, PlanUpdates, ExecuteUpdates, RestartService, ManageAlarms, ManageApplicationChecks} {
		if s.actor.grants&capabilityBit(c) != 0 {
			out = append(out, c)
		}
	}
	return out
}

// BeginCapability rechecks the session's revocation/expiry gate and explicit
// server-derived grant. Release before network/provider I/O. A copied Session
// or caller-modified display capability list cannot manufacture new authority.
func (s Session) BeginCapability(ctx context.Context, capability Capability) (func(), error) {
	release, err := s.BeginMutation(ctx)
	if err != nil {
		return nil, err
	}
	bit := capabilityBit(capability)
	if bit == 0 || s.actor.grants&bit == 0 || capability != Read && !s.Named() {
		release()
		return nil, ErrForbidden
	}
	return release, nil
}

// LoginNamed never falls back to a legacy shared password or another account.
// Unknown usernames consume the same rate and password-hashing budget.
func (m *Manager) LoginNamed(ctx context.Context, peer, username, password string) (Session, error) {
	return m.login(ctx, peer, username, password, true)
}

// ActorHasCapability is the current immutable named-account grant used before
// dispatching a previously explicit approval. Account changes require restart;
// approval never manufactures a grant after that restart.
func (m *Manager) ActorHasCapability(actor string, cap Capability) bool {
	if m == nil || actor == "" || cap == Read {
		return false
	}
	bit := capabilityBit(cap)
	if bit == 0 {
		return false
	}
	for _, p := range m.operators {
		if p.id == actor {
			return p.grants&bit != 0
		}
	}
	return false
}
