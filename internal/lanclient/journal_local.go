package lanclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalstate"
	"localrmm/internal/lanclientstate"
)

const JournalClientPolicyPath = "/etc/tracebolt/journal-client-policy.json"

var errJournalDisabled = errors.New("journal_disabled")
var errJournalDenied = errors.New("journal_denied")
var errJournalHelper = errors.New("journal_helper_unavailable")

type journalLocal struct {
	policy          journalpolicy.Policy
	revision        string
	deployment      journalhelper.Deployment
	generation      journalgeneration.Tuple
	activationPhase string
}

func journalStateDirectory(c Config) string { return filepath.Join(c.StateDirectory, "journal") }
func journalLeaf(m Material) string {
	if len(m.certificate.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(m.certificate.Certificate[0])
	return hex.EncodeToString(sum[:])
}
func journalContext(m Material, local journalLocal) journalpolicy.Context {
	return journalpolicy.Context{SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: m.config.Profile, CollectionProfile: m.config.CollectionProfile, AgentUID: local.policy.AgentUID, HelperUID: local.policy.HelperUID, PeerUID: local.policy.AgentUID}
}
func journalCurrent(m Material, digest string) journalstate.Current {
	return journalstate.Current{SenderBinding: m.binding, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), PolicyDigest: digest}
}

// JournalConsentResult is a local setup description. It contains no journal
// data, key, credential, or enrollment invitation. It is never sent remotely.
type JournalConsentResult struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Mode                   string                  `json:"mode"`
	Scope                  string                  `json:"scope"`
	SenderBinding          string                  `json:"senderBinding"`
	ManagerOrigin          string                  `json:"managerOrigin"`
	TransportProfile       string                  `json:"transportProfile"`
	CollectionProfile      string                  `json:"collectionProfile"`
	DeviceID               string                  `json:"deviceId"`
	CertificateHash        string                  `json:"certificateHash"`
	AgentUID               uint32                  `json:"agentUid"`
	AgentGID               uint32                  `json:"agentGid"`
	Initialized            bool                    `json:"initialized"`
	ExistingStatePreserved bool                    `json:"existingStatePreserved"`
	PolicyGeneration       journalgeneration.Tuple `json:"policyGeneration,omitzero"`
}

// ConfigureJournalContent runs only as the existing non-root service owner.
// Existing handoff and all three ledgers are validated, then the sender lock is
// held across the create-only initialization. Root policy is never written.
// Preview does not require a helper or policy and performs no socket/network I/O.
// Fresh broad v3 setup requires pending revision 1 authority and creates both
// private floors before the administrator can commit that activation.
func ConfigureJournalContent(path, mode string, acknowledged, plaintext bool) (JournalConsentResult, error) {
	return configureJournalContent(path, mode, acknowledged, plaintext, journalAgentIdentity, loadJournalInitialLocal)
}

func configureJournalContent(path, mode string, acknowledged, plaintext bool, identity func() (uint32, uint32, bool), local func(Material) (journalLocal, error)) (JournalConsentResult, error) {
	var out JournalConsentResult
	if mode != "preview" && mode != "initialize" || acknowledged != (mode == "initialize") || mode == "preview" && plaintext {
		return out, ErrConfiguration
	}
	uid, gid, ok := identity()
	if !ok {
		return out, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return out, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.complete() {
		return out, ErrConfiguration
	}
	lease, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return out, ErrState
	}
	defer lease.Close()
	out = JournalConsentResult{SchemaVersion: "tracebolt.journal-consent-result.v1", Mode: mode, Scope: journalpolicy.Scope, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: m.config.Profile, CollectionProfile: m.config.CollectionProfile, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), AgentUID: uid, AgentGID: gid, ExistingStatePreserved: true}
	if mode == "preview" {
		return out, nil
	}
	if plaintext != (m.config.Profile == "http-test") {
		return JournalConsentResult{}, ErrConfiguration
	}
	current, e := local(m)
	if e != nil || journalpolicy.Validate(current.policy) != nil || current.policy.SenderBinding != m.binding || current.policy.ManagerOrigin != m.config.ManagerOrigin || current.policy.TransportProfile != m.config.Profile || current.policy.CollectionProfile != m.config.CollectionProfile || current.policy.AgentUID != uid {
		return JournalConsentResult{}, ErrConfiguration
	}
	generation, e := journalpolicy.PolicyGeneration(current.policy)
	if e != nil || generation != current.generation {
		return JournalConsentResult{}, ErrConfiguration
	}
	broad := current.policy.SchemaVersion == journalpolicy.VersionV3
	if broad {
		if current.policy.ServiceAuthorization != journalpolicy.AllSystemServices || current.generation.Revision != 1 || current.activationPhase != "pending" || !current.policy.Enabled || current.deployment.SchemaVersion != journalhelper.DeploymentVersionV2 || !current.deployment.PolicyGenerationRequired {
			return JournalConsentResult{}, ErrConfiguration
		}
	} else if current.policy.SchemaVersion != journalpolicy.Version || current.activationPhase != "" {
		return JournalConsentResult{}, ErrConfiguration
	}
	if broad {
		// Both private domains are create-only. Even one surviving domain is
		// evidence of an earlier attempt, never permission to reconstruct the other.
		for _, directory := range []string{journalStateDirectory(m.config), journalGenerationDirectory(m.config)} {
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				return JournalConsentResult{}, ErrState
			}
		}
	}
	state, e := journalstate.Initialize(context.Background(), journalStateDirectory(m.config), m.binding)
	if e != nil {
		return JournalConsentResult{}, ErrState
	}
	defer state.Close()
	if broad {
		expected := journalgenerationstate.Record{SchemaVersion: journalgenerationstate.Version, SenderBinding: m.binding, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), PolicyGeneration: current.generation}
		generationState, err := journalgenerationstate.Initialize(context.Background(), journalGenerationDirectory(m.config), expected)
		if err != nil {
			return JournalConsentResult{}, ErrState
		}
		record, err := generationState.Record()
		closeErr := generationState.Close()
		if err != nil || closeErr != nil || record != expected {
			return JournalConsentResult{}, ErrState
		}
		// Pending activation remains the only root authority throughout creation.
		// A changed policy or activation leaves retained floors and no success DTO.
		fresh, err := local(m)
		if err != nil || fresh.revision != current.revision || fresh.generation != current.generation || fresh.activationPhase != "pending" {
			return JournalConsentResult{}, ErrState
		}
		out.Scope = current.policy.Scope
		out.PolicyGeneration = current.generation
	}
	if state.Close() != nil || lease.Close() != nil {
		return JournalConsentResult{}, ErrState
	}
	out.Initialized = true
	return out, nil
}
