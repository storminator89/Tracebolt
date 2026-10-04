package lanclient

import (
	"localrmm/internal/inventorystate"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/systemstate"
)

func openSenderState(m Material) (*lanclientstate.State, error) {
	if m.config.guided() {
		return lanclientstate.OpenExisting(m.config.StateDirectory, m.binding)
	}
	return lanclientstate.Open(m.config.StateDirectory, m.binding)
}

// InitializeGuidedState is the one-time, no-network enrollment handoff step.
// Key/certificate/CA files already exist privately; agent.json need not exist.
// It never overwrites an incompatible ledger or changes an existing sequence.
// Call only before the durable HandoffPrepared/ready publication, never as a
// recovery fallback for a previously prepared identity.
func InitializeGuidedState(c Config) error {
	if !c.guided() {
		return ErrConfiguration
	}
	m, e := loadConfig(c)
	if e != nil {
		return e
	}
	var state *lanclientstate.State
	if c.complete() {
		state, e = lanclientstate.InitializeNew(c.StateDirectory, m.binding)
	} else {
		state, e = lanclientstate.Open(c.StateDirectory, m.binding)
	}
	if e != nil {
		return ErrState
	}
	if state.Close() != nil {
		return ErrState
	}
	if c.complete() {
		inventory, e := inventorystate.InitializeNew(inventoryStateDirectory(c), m.binding, c.AgentID)
		if e != nil {
			return ErrState
		}
		if inventory.Close() != nil {
			return ErrState
		}
		system, e := systemstate.InitializeNew(systemStateDirectory(c), systemStateBinding(m))
		if e != nil {
			return ErrState
		}
		if system.Close() != nil {
			return ErrState
		}
	}
	return nil
}

// ValidateGuidedState does not create missing paths, locks or sequence records.
// It respects the same exclusive lifetime lock held by the foreground sender.
func ValidateGuidedState(c Config) error {
	if !c.guided() {
		return ErrConfiguration
	}
	m, e := loadConfig(c)
	if e != nil {
		return e
	}
	if lanclientstate.ValidateExisting(c.StateDirectory, m.binding) != nil {
		return ErrState
	}
	if c.complete() && inventorystate.ValidateExisting(inventoryStateDirectory(c), m.binding, c.AgentID) != nil {
		return ErrState
	}
	if c.complete() && systemstate.ValidateExisting(systemStateDirectory(c), systemStateBinding(m)) != nil {
		return ErrState
	}
	return nil
}
