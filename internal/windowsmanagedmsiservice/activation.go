package windowsmanagedmsiservice

import (
	"encoding/json"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	job "localrmm/internal/windowsupdatejob"
)

const BackgroundActivationVersion = "tracebolt.windows-managed-msi-background-activation.v1"

// BackgroundRegistrationProof is entirely public. The MSI service never opens
// the WUA key, ledger or state directory to establish reciprocal registration.
type BackgroundRegistrationProof struct {
	Registration job.SetupRegistration    `json:"registration"`
	Manager      job.BackgroundActivation `json:"manager"`
}

func (p BackgroundRegistrationProof) Validate(c windowsmanagedmsiipc.Config) error {
	if c.Validate() != nil || c.Mutation == nil || !c.Mutation.BackgroundWUA() || p.Registration.Version != job.BackgroundRegistrationVersion || p.Registration.Validate() != nil || !job.ValidMutationRoster(c.Mutation, p.Registration.Consent) || p.Manager.Verify(p.Registration) != nil {
		return managed.ErrAuthority
	}
	return nil
}

// Omitting Background preserves the original three-field activation JSON.
// Only the fresh background roster accepts this new version and signed proof.
type Activation struct {
	Version      string                       `json:"version"`
	ConfigDigest string                       `json:"configDigest"`
	Acknowledged bool                         `json:"acknowledged"`
	Background   *BackgroundRegistrationProof `json:"background,omitempty"`
}

func (a Activation) Validate(c windowsmanagedmsiipc.Config) error {
	raw, _ := json.Marshal(c)
	if c.Validate() != nil || !a.Acknowledged || a.ConfigDigest != managed.Digest(raw) {
		return managed.ErrAuthority
	}
	background := c.Mutation != nil && c.Mutation.BackgroundWUA()
	if !background {
		if a.Version != managed.Version || a.Background != nil {
			return managed.ErrAuthority
		}
		return nil
	}
	if a.Version != BackgroundActivationVersion || a.Background == nil || a.Background.Validate(c) != nil {
		return managed.ErrAuthority
	}
	return nil
}
