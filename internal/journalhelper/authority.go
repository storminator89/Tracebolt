package journalhelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalpolicy"
)

const DeploymentVersion = "tracebolt.journal-helper-deployment.v1"
const DeploymentVersionV2 = "tracebolt.journal-helper-deployment.v2"
const MaxDeploymentBytes = 1024

// Deployment is root-protected numeric metadata, not an account-provisioner.
// The dedicated non-login UID must not be the agent. Its only supplementary
// group is the exact journal GID declared here; the existing agent is unchanged.
type Deployment struct {
	SchemaVersion            string `json:"schemaVersion"`
	HelperUID                uint32 `json:"helperUid"`
	HelperGID                uint32 `json:"helperGid"`
	JournalGID               uint32 `json:"journalGid"`
	AgentUID                 uint32 `json:"agentUid"`
	AgentGID                 uint32 `json:"agentGid"`
	PolicyGenerationRequired bool   `json:"policyGenerationRequired,omitempty"`
}

type Identity struct {
	RealUID, EffectiveUID, SavedUID uint32
	RealGID, EffectiveGID, SavedGID uint32
	Groups                          []uint32
	NoCapabilities                  bool
}
type Peer struct {
	UID, GID uint32
	PID      int32
}

// State is not trusted merely because it has this Go type. Production state
// comes only from the fixed protected loader. Synthetic tests inject it.
type State struct {
	Policy     journalpolicy.Policy
	Deployment Deployment
	Revision   string
	// PolicyGeneration comes only from an exact committed protected activation.
	PolicyGeneration journalgeneration.Tuple
}

func validID(id uint32) bool { return id != 0 && id != ^uint32(0) }
func validateDeployment(d Deployment) error {
	if d.SchemaVersion != DeploymentVersion && d.SchemaVersion != DeploymentVersionV2 || d.PolicyGenerationRequired != (d.SchemaVersion == DeploymentVersionV2) || !validID(d.HelperUID) || !validID(d.HelperGID) || !validID(d.JournalGID) || !validID(d.AgentUID) || !validID(d.AgentGID) || d.HelperUID == d.AgentUID || d.HelperGID == d.AgentGID || d.HelperGID == d.JournalGID || d.AgentGID == d.JournalGID {
		return ErrRejected
	}
	return nil
}
func decodeDeployment(raw []byte) (Deployment, error) {
	if len(raw) == 0 || len(raw) > MaxDeploymentBytes {
		return Deployment{}, ErrRejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var d Deployment
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil {
		return Deployment{}, ErrRejected
	}
	if _, e := dec.Token(); e != io.EOF {
		return Deployment{}, ErrRejected
	}
	// Only canonical encoding is accepted: rejects duplicate keys, null, missing
	// members, non-integer numbers and all alternative spellings without a second
	// permissive parser. A single final newline is allowed for admin text editors.
	encoded, e := json.Marshal(d)
	if e != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), encoded) || validateDeployment(d) != nil {
		return Deployment{}, ErrRejected
	}
	return d, nil
}
func validateIdentity(d Deployment, i Identity) error {
	if validateDeployment(d) != nil || i.RealUID != d.HelperUID || i.EffectiveUID != d.HelperUID || i.SavedUID != d.HelperUID || i.RealGID != d.HelperGID || i.EffectiveGID != d.HelperGID || i.SavedGID != d.HelperGID || !i.NoCapabilities {
		return ErrRejected
	}
	groups := slices.Clone(i.Groups)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	// Linux may include the primary GID in getgroups or leave it separate.
	if !slices.Equal(groups, []uint32{d.JournalGID}) {
		expected := []uint32{d.HelperGID, d.JournalGID}
		slices.Sort(expected)
		if !slices.Equal(groups, expected) {
			return ErrRejected
		}
	}
	return nil
}
func validateState(s State, i Identity) error {
	generation, err := journalpolicy.PolicyGeneration(s.Policy)
	if err != nil || generation != s.PolicyGeneration || s.Deployment.PolicyGenerationRequired != journalpolicy.IsGenerationPolicy(s.Policy.SchemaVersion) {
		return ErrRejected
	}
	_, ok := taggedDigest(s.Revision)
	if !ok || journalpolicy.Validate(s.Policy) != nil || validateIdentity(s.Deployment, i) != nil || s.Policy.HelperUID != s.Deployment.HelperUID || s.Policy.AgentUID != s.Deployment.AgentUID {
		return ErrRejected
	}
	return nil
}
func authorityContext(s State, i Identity, p Peer, binding string) (journalpolicy.Context, error) {
	if validateState(s, i) != nil || p.PID <= 0 || p.UID != s.Deployment.AgentUID || p.GID != s.Deployment.AgentGID || binding != s.Policy.SenderBinding {
		return journalpolicy.Context{}, ErrRejected
	}
	// The origin/profile/UID declarations come from root-protected policy. Only
	// the binding is supplied by the already-validated calling agent. Peer and
	// helper process identity are independent kernel facts, never request JSON.
	return journalpolicy.Context{SenderBinding: binding, ManagerOrigin: s.Policy.ManagerOrigin, TransportProfile: s.Policy.TransportProfile, CollectionProfile: s.Policy.CollectionProfile, AgentUID: s.Policy.AgentUID, HelperUID: i.EffectiveUID, PeerUID: p.UID}, nil
}
func revision(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
