package lanclient

import (
	"bytes"
	"encoding/json"
	"errors"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

const ActionClientPolicyPath = "/etc/tracebolt/action-client.json"
const ActionClientPolicyVersionV2 = "tracebolt.action-client-policy.v2"
const ActionClientPolicyVersion = "tracebolt.action-client-policy.v1"
const maxActionClientPolicyBytes = 4096

var errActionDisabled = errors.New("service_action_disabled")
var errActionDenied = errors.New("service_action_denied")

// ActionClientPolicy is an existing root-provisioned local-machine grant, not
// remote metadata or a field silently added by a manager upgrade. No runtime
// creates it. RootPolicyDigest selects exactly one helper scope/configuration.
type ActionClientPolicy struct {
	Version              string `json:"version"`
	Enabled              bool   `json:"enabled"`
	SenderBinding        string `json:"senderBinding"`
	ManagerOrigin        string `json:"managerOrigin"`
	ManagerID            string `json:"managerId"`
	EndpointID           string `json:"endpointId"`
	IncarnationDigest    string `json:"incarnationDigest"`
	KeyID                string `json:"keyId"`
	RootPolicyDigest     string `json:"rootPolicyDigest"`
	TransportProfile     string `json:"transportProfile"`
	HTTPTestAcknowledged bool   `json:"httpTestAcknowledged"`
	AgentUID             uint32 `json:"agentUid"`
	AgentGID             uint32 `json:"agentGid"`
	Scope                string `json:"scope,omitempty"`
}
type actionLocal struct {
	policy   ActionClientPolicy
	revision string
}

func actionProfile(m Material) string {
	if m.config.Profile == "tls" {
		return actionhelper.ProductionTLS
	}
	if m.config.Profile == "http-test" {
		return actionhelper.DisposableHTTPTest
	}
	return ""
}
func validateActionLocal(p ActionClientPolicy, m Material, uid, gid uint32) error {
	if !m.config.complete() || ((p.Version != ActionClientPolicyVersion || p.Scope != "") && (p.Version != ActionClientPolicyVersionV2 || p.Scope != actionhelper.FullAdminServiceScope)) || !enrollmentcrypto.ValidHash(p.SenderBinding) || p.SenderBinding != m.binding || p.ManagerOrigin != m.config.ManagerOrigin || !enrollmentcrypto.ValidID(p.ManagerID, "manager_") || p.EndpointID != m.config.AgentID || p.IncarnationDigest != "sha256:"+journalLeaf(m) || !actionpermit.ValidDigest(p.KeyID) || !actionpermit.ValidDigest(p.RootPolicyDigest) || uid == 0 || gid == 0 || p.AgentUID != uid || p.AgentGID != gid || p.TransportProfile != actionProfile(m) {
		return errActionDenied
	}
	if p.TransportProfile == actionhelper.DisposableHTTPTest {
		if !p.HTTPTestAcknowledged || !m.config.InsecureHTTPAcknowledged {
			return errActionDenied
		}
	} else if p.TransportProfile != actionhelper.ProductionTLS || p.HTTPTestAcknowledged {
		return errActionDenied
	}
	if !p.Enabled {
		return errActionDisabled
	}
	return nil
}
func decodeActionLocal(raw []byte, m Material, uid, gid uint32) (ActionClientPolicy, error) {
	var p ActionClientPolicy
	if len(raw) == 0 || len(raw) > maxActionClientPolicyBytes || json.Unmarshal(raw, &p) != nil {
		return p, errActionDenied
	}
	b, e := json.Marshal(p)
	if e != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), b) {
		return ActionClientPolicy{}, errActionDenied
	}
	if e = validateActionLocal(p, m, uid, gid); e != nil {
		return ActionClientPolicy{}, e
	}
	return p, nil
}
func matchActionCapabilities(c actionhelper.Capabilities, l actionLocal, m Material) error {
	p := l.policy
	if (p.Version == ActionClientPolicyVersion) != (c.Version == actionhelper.CapabilitiesVersion) || p.Scope != c.Scope || actionhelper.ValidateCapabilities(c) != nil || c.ManagerID != p.ManagerID || c.KeyID != p.KeyID || c.EndpointID != p.EndpointID || c.IncarnationDigest != p.IncarnationDigest || c.RootPolicyDigest != p.RootPolicyDigest || c.TransportProfile != p.TransportProfile || c.HTTPTestAcknowledged != p.HTTPTestAcknowledged || c.EndpointID != m.config.AgentID {
		return errActionDenied
	}
	return nil
}
