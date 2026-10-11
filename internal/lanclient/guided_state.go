package lanclient

import (
	"crypto/x509"
	"encoding/hex"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/inventorystate"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/systemstate"
	"runtime"
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
	if c.complete() || c.windowsInventory() || c.automaticRenewal() {
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
	return validateExistingGuidedState(c, m.binding)
}

// ValidateRenewalSenderState checks continuity while a renewable sender is fully
// quiesced, including reconciliation after its previous transport leaf expired.
// The caller must first authenticate anchorDER against the original protected
// enrollment ledger. This is a read-only state check, never transport authority:
// it does not load or accept a current credential, initialize paths, repair a
// missing used ledger, or transmit. Existing exclusive lifetime locks apply.
func ValidateRenewalSenderState(c Config, anchorDER []byte) error {
	if !c.automaticRenewal() || c.Validate() != nil || !c.platformAllowed(runtime.GOOS) || len(anchorDER) == 0 || len(anchorDER) > enrollmentcrypto.MaxCertificateBytes {
		return ErrConfiguration
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil || anchor.IsCA || anchor.Subject.CommonName != c.AgentID || anchor.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(anchor.ExtKeyUsage) != 1 || anchor.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(anchor.UnknownExtKeyUsage) != 0 {
		return ErrConfiguration
	}
	binding := senderBinding(c, anchor)
	return validateExistingGuidedState(c, hex.EncodeToString(binding[:]))
}

func validateExistingGuidedState(c Config, binding string) error {
	if lanclientstate.ValidateExisting(c.StateDirectory, binding) != nil {
		return ErrState
	}
	if c.complete() && inventorystate.ValidateExisting(inventoryStateDirectory(c), binding, c.AgentID) != nil {
		return ErrState
	}
	if c.complete() && systemstate.ValidateExisting(systemStateDirectory(c), systemStateBinding(Material{binding: binding})) != nil {
		return ErrState
	}
	return nil
}
