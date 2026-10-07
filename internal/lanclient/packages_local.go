package lanclient

import (
	"bytes"
	"encoding/json"
	"errors"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/packagehelper"
)

const PackageClientPolicyPath = "/etc/tracebolt/package-client.json"
const PackageClientPolicyVersion = "tracebolt.package-client-policy.v1"
const maxPackageClientPolicyBytes = 4096

var errPackageDisabled = errors.New("package_action_disabled")
var errPackageDenied = errors.New("package_action_denied")

// PackageClientPolicy is an existing root-provisioned local-machine grant, not
// remote metadata or a field silently added by a manager upgrade. No runtime
// creates it. RootPolicyDigest selects exactly one helper scope/configuration.
type PackageClientPolicy struct {
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
}
type packageLocal struct {
	policy   PackageClientPolicy
	revision string
}

func packageProfile(m Material) string {
	if m.config.Profile == "tls" {
		return "production-tls"
	}
	if m.config.Profile == "http-test" {
		return "disposable-http-test"
	}
	return ""
}
func validatePackageLocal(p PackageClientPolicy, m Material, uid, gid uint32) error {
	if !m.config.complete() || p.Version != PackageClientPolicyVersion || !enrollmentcrypto.ValidHash(p.SenderBinding) || p.SenderBinding != m.binding || p.ManagerOrigin != m.config.ManagerOrigin || !enrollmentcrypto.ValidID(p.ManagerID, "manager_") || p.EndpointID != m.config.AgentID || p.IncarnationDigest != "sha256:"+journalLeaf(m) || !actionpermit.ValidDigest(p.KeyID) || !actionpermit.ValidDigest(p.RootPolicyDigest) || uid == 0 || gid == 0 || p.AgentUID != uid || p.AgentGID != gid || p.TransportProfile != packageProfile(m) {
		return errPackageDenied
	}
	if p.TransportProfile == "disposable-http-test" {
		if !p.HTTPTestAcknowledged || !m.config.InsecureHTTPAcknowledged {
			return errPackageDenied
		}
	} else if p.TransportProfile != "production-tls" || p.HTTPTestAcknowledged {
		return errPackageDenied
	}
	if !p.Enabled {
		return errPackageDisabled
	}
	return nil
}
func decodePackageLocal(raw []byte, m Material, uid, gid uint32) (PackageClientPolicy, error) {
	var p PackageClientPolicy
	if len(raw) == 0 || len(raw) > maxPackageClientPolicyBytes || json.Unmarshal(raw, &p) != nil {
		return p, errPackageDenied
	}
	b, e := json.Marshal(p)
	if e != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), b) {
		return PackageClientPolicy{}, errPackageDenied
	}
	if e = validatePackageLocal(p, m, uid, gid); e != nil {
		return PackageClientPolicy{}, e
	}
	return p, nil
}
func matchPackageCapabilities(c packagehelper.Capabilities, l packageLocal, m Material) error {
	p := l.policy
	if packagehelper.ValidateCapabilities(c) != nil || c.ManagerID != p.ManagerID || c.KeyID != p.KeyID || c.EndpointID != p.EndpointID || c.IncarnationDigest != p.IncarnationDigest || c.RootPolicyDigest != p.RootPolicyDigest || c.TransportProfile != p.TransportProfile || c.HTTPTestAcknowledged != p.HTTPTestAcknowledged || c.EndpointID != m.config.AgentID {
		return errPackageDenied
	}
	return nil
}
