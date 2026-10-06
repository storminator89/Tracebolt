package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/socketowner"
	"localrmm/internal/systemstate"
	"localrmm/internal/systemwire"
)

const SocketOwnerSetupConfigPath = "/var/lib/tracebolt-agent/enrollment/agent.json"
const SocketOwnerSetupIdentityVersion = "tracebolt.socket-owner-setup-identity.v1"
const SocketOwnerSetupResultVersion = "tracebolt.socket-owner-setup-result.v1"

// Incomplete errors contain public lifecycle status only. Callers must not
// automatically replay a failed mutation or infer successful pending disposal.
var ErrSocketOwnerSetupIncomplete = errors.New("socket-owner consent mutation incomplete")
var ErrSocketOwnerSetupDisableIncomplete = errors.New("socket-owner consent disabled; pending disposal incomplete")

// SocketOwnerSetupResult is public metadata only. Neither consent nor this
// projection is an identity authority; each operation rereads activated material.
type SocketOwnerSetupResult struct {
	SchemaVersion          string              `json:"schemaVersion"`
	Mode                   string              `json:"mode"`
	Identity               ActionSetupIdentity `json:"identity"`
	State                  string              `json:"state"`
	Policy                 *socketowner.Policy `json:"policy"`
	TaggedPendingDiscarded bool                `json:"taggedPendingDiscarded"`
}

type SocketOwnerSetupAcknowledgements struct{ Metadata, PtraceRisk, HTTPPlaintext bool }

type socketSetupPending struct {
	sequence uint64
	digest   string
	body     []byte
}
type socketSetupState interface {
	pending() (*socketSetupPending, error)
	next() (uint64, error)
	discard(string) error
	Close() error
}
type socketSetupNativeState struct{ *systemstate.State }

func (s socketSetupNativeState) pending() (*socketSetupPending, error) {
	p, err := s.Pending()
	if err != nil || p == nil {
		return nil, err
	}
	return &socketSetupPending{p.Sequence, p.Digest, p.Body()}, nil
}
func (s socketSetupNativeState) next() (uint64, error)  { return s.NextSequence() }
func (s socketSetupNativeState) discard(d string) error { return s.Discard(d) }

type socketSetupHooks struct {
	material activatedMaterialReader
	inspect  func(Material) (*SocketOwnerConsent, error)
	lease    func(Material) (io.Closer, error)
	state    func(Material) (socketSetupState, error)
	write    func(Material, *SocketOwnerConsent, SocketOwnerConsent, func() error) error
}

func defaultSocketSetupHooks() socketSetupHooks {
	return socketSetupHooks{material: readActivatedMaterial, inspect: inspectSocketSetupConsent,
		lease: func(m Material) (io.Closer, error) {
			return lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
		},
		state: openSocketSetupState, write: writeSocketSetupConsent}
}

// ConfigureSocketOwners is an offline, stopped-owner lifecycle. The only path
// is the installed enrollment config. No helper, manager or collector is used.
// Failed mutations can have persisted a tombstone: callers must report them as
// incomplete, never infer that pending bytes were discarded or retry setup.
func ConfigureSocketOwners(ctx context.Context, mode string, policy []byte, ack SocketOwnerSetupAcknowledgements) (SocketOwnerSetupResult, error) {
	return configureSocketOwners(ctx, mode, policy, ack, defaultSocketSetupHooks())
}

func projectSocketSetupIdentity(m Material, uid, gid uint32) ActionSetupIdentity {
	identity := projectActionSetupIdentity(m, uid, gid)
	identity.SchemaVersion = SocketOwnerSetupIdentityVersion
	identity.TransportProfile = m.config.Profile
	return identity
}
func socketSetupConsentValid(c SocketOwnerConsent, m Material, uid, gid uint32) bool {
	// Disabled tombstones retain every original declaration and acknowledgement.
	c.Policy.Enabled = true
	return validateSocketOwnerConsent(c, m, uid, gid)
}
func socketSetupSameMaterial(a, b Material, uid, gid, otherUID, otherGID uint32) bool {
	return a.valid() && b.valid() && a.config.complete() && b.config.complete() &&
		a.configPath == SocketOwnerSetupConfigPath && b.configPath == a.configPath &&
		a.config == b.config && a.binding == b.binding && journalLeaf(a) == journalLeaf(b) && uid == otherUID && gid == otherGID
}
func socketSetupPendingEqual(a, b *socketSetupPending) bool {
	return a == nil && b == nil || a != nil && b != nil && a.sequence == b.sequence && a.digest == b.digest && bytes.Equal(a.body, b.body)
}
func socketSetupFloor(s socketSetupState) (uint64, bool, error) {
	n, err := s.next()
	if errors.Is(err, systemstate.ErrSequence) {
		return 0, true, nil
	}
	return n, false, err
}
func socketSetupValidatePending(p *socketSetupPending, m Material) (bool, error) {
	if p == nil {
		return false, nil
	}
	sum := sha256.Sum256(p.body)
	if p.digest != hex.EncodeToString(sum[:]) {
		return false, ErrState
	}
	frame, err := systemwire.Decode(p.body)
	expected, generationErr := systemwire.GenerationID(m.config.AgentID, p.sequence)
	if err != nil || generationErr != nil || frame.Sequence != p.sequence || frame.Snapshot.GenerationID != expected {
		return false, ErrState
	}
	return frame.SocketOwnerProvenance != nil, nil
}

func configureSocketOwners(ctx context.Context, mode string, raw []byte, ack SocketOwnerSetupAcknowledgements, h socketSetupHooks) (result SocketOwnerSetupResult, resultErr error) {
	mutationStarted, disabledPersisted := false, false
	defer func() {
		if resultErr != nil && mutationStarted {
			resultErr = ErrSocketOwnerSetupIncomplete
			if disabledPersisted {
				resultErr = ErrSocketOwnerSetupDisableIncomplete
			}
		}
	}()
	zero := SocketOwnerSetupResult{}
	if ctx == nil || ctx.Err() != nil || h.material == nil || h.inspect == nil {
		return zero, ErrConfiguration
	}
	var target socketowner.Policy
	switch mode {
	case "identity", "preview":
		if len(raw) != 0 || ack != (SocketOwnerSetupAcknowledgements{}) {
			return zero, ErrConfiguration
		}
	case "initialize", "disable":
		var err error
		target, err = socketowner.DecodePolicy(raw)
		if err != nil || target.Enabled != (mode == "initialize") {
			return zero, ErrConfiguration
		}
		expected := SocketOwnerSetupAcknowledgements{}
		if mode == "initialize" {
			expected = SocketOwnerSetupAcknowledgements{true, true, target.TransportProfile == "http-test"}
		}
		if ack != expected || h.lease == nil || h.state == nil || h.write == nil {
			return zero, ErrConfiguration
		}
	default:
		return zero, ErrConfiguration
	}
	m, uid, gid, err := h.material(SocketOwnerSetupConfigPath)
	if err != nil || !socketSetupSameMaterial(m, m, uid, gid, uid, gid) {
		return zero, ErrState
	}
	current := func() error {
		if ctx.Err() != nil {
			return ErrState
		}
		fresh, freshUID, freshGID, err := h.material(SocketOwnerSetupConfigPath)
		if err != nil || !socketSetupSameMaterial(m, fresh, uid, gid, freshUID, freshGID) {
			return ErrState
		}
		return nil
	}
	var state socketSetupState
	var lease io.Closer
	if mode == "initialize" || mode == "disable" {
		proposed := SocketOwnerConsent{SocketOwnerConsentVersion, m.config.AgentID, "sha256:" + journalLeaf(m), target}
		if !socketSetupConsentValid(proposed, m, uid, gid) {
			return zero, ErrConfiguration
		}
		lease, err = h.lease(m)
		if err != nil || lease == nil {
			return zero, ErrState
		}
		defer lease.Close()
		state, err = h.state(m)
		if err != nil || state == nil {
			return zero, ErrState
		}
		defer state.Close()
		if current() != nil {
			return zero, ErrState
		}
	}
	existing, err := h.inspect(m)
	if err != nil || existing != nil && !socketSetupConsentValid(*existing, m, uid, gid) {
		return zero, ErrState
	}
	discarded := false
	if state != nil {
		pending, err := state.pending()
		if err != nil {
			return zero, ErrState
		}
		tagged, err := socketSetupValidatePending(pending, m)
		if err != nil {
			return zero, ErrState
		}
		floor, exhausted, err := socketSetupFloor(state)
		if err != nil {
			return zero, ErrState
		}
		nextConsent := SocketOwnerConsent{SocketOwnerConsentVersion, m.config.AgentID, "sha256:" + journalLeaf(m), target}
		if mode == "initialize" {
			if existing != nil || tagged {
				return zero, ErrState
			}
		} else {
			if existing == nil || !existing.Policy.Enabled {
				return zero, ErrState
			}
			expected := *existing
			expected.Policy.Enabled = false
			if nextConsent != expected {
				return zero, ErrState
			}
		}
		unchanged := func() error {
			if current() != nil {
				return ErrState
			}
			nowPending, err := state.pending()
			nowFloor, nowExhausted, floorErr := socketSetupFloor(state)
			if err != nil || floorErr != nil || !socketSetupPendingEqual(pending, nowPending) || floor != nowFloor || exhausted != nowExhausted {
				return ErrState
			}
			return nil
		}
		if unchanged() != nil {
			return zero, ErrState
		}
		mutationStarted = true
		if h.write(m, existing, nextConsent, unchanged) != nil {
			return zero, ErrState
		}
		if mode == "disable" {
			disabledPersisted = true
		}
		// The tombstone is durable and verified before any pending body is removed.
		readback, err := h.inspect(m)
		if err != nil || readback == nil || *readback != nextConsent || unchanged() != nil {
			return zero, ErrState
		}
		if mode == "disable" && tagged {
			if state.discard(pending.digest) != nil {
				return zero, ErrState
			}
			pending = nil
			discarded = true
		}
		nowPending, err := state.pending()
		nowFloor, nowExhausted, floorErr := socketSetupFloor(state)
		if err != nil || floorErr != nil || !socketSetupPendingEqual(pending, nowPending) || floor != nowFloor || exhausted != nowExhausted {
			return zero, ErrState
		}
		existing = readback
	}
	if current() != nil {
		return zero, ErrState
	}
	// Final protected readback rejects concurrent consent changes, including a
	// changed declaration that could otherwise be presented as a completed setup.
	readback, err := h.inspect(m)
	if err != nil || (existing == nil) != (readback == nil) || existing != nil && *readback != *existing {
		return zero, ErrState
	}
	if state != nil && state.Close() != nil {
		return zero, ErrState
	}
	if lease != nil && lease.Close() != nil {
		return zero, ErrState
	}
	result = SocketOwnerSetupResult{SchemaVersion: SocketOwnerSetupResultVersion, Mode: mode,
		Identity: projectSocketSetupIdentity(m, uid, gid), State: "absent", TaggedPendingDiscarded: discarded}
	if existing != nil {
		policy := existing.Policy
		result.Policy = &policy
		result.State = "disabled"
		if policy.Enabled {
			result.State = "enabled"
		}
	}
	return result, nil
}
