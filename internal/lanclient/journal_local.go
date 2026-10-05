package lanclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"

	"localrmm/internal/journalgeneration"
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
	SchemaVersion          string `json:"schemaVersion"`
	Mode                   string `json:"mode"`
	Scope                  string `json:"scope"`
	SenderBinding          string `json:"senderBinding"`
	ManagerOrigin          string `json:"managerOrigin"`
	TransportProfile       string `json:"transportProfile"`
	CollectionProfile      string `json:"collectionProfile"`
	DeviceID               string `json:"deviceId"`
	CertificateHash        string `json:"certificateHash"`
	AgentUID               uint32 `json:"agentUid"`
	AgentGID               uint32 `json:"agentGid"`
	Initialized            bool   `json:"initialized"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureJournalContent runs only as the existing non-root service owner.
// Existing handoff and all three ledgers are validated, then the sender lock is
// held across the create-only initialization. Root policy is never written.
// Preview does not require a helper or policy and performs no socket/network I/O.
func ConfigureJournalContent(path, mode string, acknowledged, plaintext bool) (JournalConsentResult, error) {
	return configureJournalContent(path, mode, acknowledged, plaintext, journalAgentIdentity, loadJournalLocal)
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
	if _, e = local(m); e != nil {
		return JournalConsentResult{}, ErrConfiguration
	}
	state, e := journalstate.Initialize(context.Background(), journalStateDirectory(m.config), m.binding)
	if e != nil {
		return JournalConsentResult{}, ErrState
	}
	if state.Close() != nil || lease.Close() != nil {
		return JournalConsentResult{}, ErrState
	}
	out.Initialized = true
	return out, nil
}
