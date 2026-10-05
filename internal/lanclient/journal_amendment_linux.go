//go:build linux

package lanclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalstate"
	"localrmm/internal/lanclientstate"
)

func ConfigureJournalAmendment(path, mode string, ack, plain bool) (JournalAmendmentResult, error) {
	return configureJournalAmendment(path, mode, ack, plain, journalAgentIdentity, readJournalLocalMode)
}
func configureJournalAmendment(path, mode string, ack, plain bool, identity func() (uint32, uint32, bool), local func(Material, uint32, uint32, bool) (journalLocal, error)) (JournalAmendmentResult, error) {
	var out JournalAmendmentResult
	if mode != "preview" && mode != "accept" || ack != (mode == "accept") || mode == "preview" && plain {
		return out, ErrConfiguration
	}
	uid, gid, ok := identity()
	if !ok || ValidateGuidedHandoff(path) != nil {
		return out, ErrConfiguration
	}
	m, e := Load(path)
	if e != nil || !m.config.complete() {
		return out, ErrConfiguration
	}
	// Acquire again for every invocation: an earlier preview has released its lease.
	lease, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return out, ErrState
	}
	defer lease.Close()
	consumed, e := journalstate.Open(context.Background(), journalStateDirectory(m.config), m.binding)
	if e != nil {
		return out, ErrState
	}
	defer consumed.Close()
	if _, e = consumed.SequenceFloor(); e != nil {
		return out, ErrState
	}
	current, e := local(m, uid, gid, mode == "accept")
	if e != nil {
		return out, ErrConfiguration
	}
	if mode == "accept" && current.activationPhase != "pending" {
		return out, ErrConfiguration
	}
	raw, e := journalpolicy.Encode(current.policy)
	if e != nil {
		return out, ErrConfiguration
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	out = JournalAmendmentResult{SchemaVersion: "tracebolt.journal-amendment-result.v1", Mode: mode, Scope: current.policy.Scope, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: m.config.Profile, CollectionProfile: m.config.CollectionProfile, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), AgentUID: uid, AgentGID: gid, PolicyDigest: digest, PolicyGeneration: current.generation, ExistingStatePreserved: true}
	if mode == "preview" {
		return out, nil
	}
	if plain != (m.config.Profile == "http-test") || current.generation == (journalgeneration.Tuple{}) {
		return JournalAmendmentResult{}, ErrConfiguration
	}
	expected := journalgenerationstate.Record{SchemaVersion: journalgenerationstate.Version, SenderBinding: m.binding, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m), PolicyGeneration: current.generation}
	var st *journalgenerationstate.State
	if current.generation.Revision == 1 {
		st, e = journalgenerationstate.Initialize(context.Background(), journalGenerationDirectory(m.config), expected)
	} else {
		st, e = journalgenerationstate.Open(context.Background(), journalGenerationDirectory(m.config))
		if e == nil {
			old, err := st.Record()
			if err != nil || old.SenderBinding != m.binding || old.DeviceID != m.config.AgentID || old.CertificateHash != journalLeaf(m) {
				_ = st.Close()
				return JournalAmendmentResult{}, ErrState
			}
			e = st.Advance(context.Background(), old, current.generation)
		}
	}
	if e != nil {
		if st != nil {
			_ = st.Close()
		}
		return JournalAmendmentResult{}, ErrState
	}
	record, e := st.Record()
	closeErr := st.Close()
	if e != nil || closeErr != nil || record.PolicyGeneration != current.generation {
		return JournalAmendmentResult{}, ErrState
	}
	// Recheck pending root authority after durability, without collecting/network.
	fresh, e := local(m, uid, gid, true)
	if e != nil || fresh.revision != current.revision || fresh.generation != current.generation {
		return JournalAmendmentResult{}, ErrState
	}
	if consumed.Close() != nil || lease.Close() != nil {
		return JournalAmendmentResult{}, ErrState
	}
	out.Accepted = true
	return out, nil
}
