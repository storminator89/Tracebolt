package packagehelper

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/nativeapt"
	"localrmm/internal/packagepermit"
	"strings"
)

const (
	RunnerUnitPath          = "/etc/systemd/system/tracebolt-package-runner@.service"
	PolicyPath              = "/etc/tracebolt/package-actions.json"
	PublicKeyPath           = "/etc/tracebolt/package-actions/command.pub"
	PolicyVersion           = "tracebolt.package-helper-policy.v1"
	RunnerExecutable        = "/usr/libexec/tracebolt-package-runner"
	HelperExecutable        = "/usr/libexec/tracebolt-package-helper"
	ServiceHelperExecutable = "/opt/tracebolt-agent/lan-agent"
	SystemctlExecutable     = "/usr/bin/systemctl"
	StateVersion            = "tracebolt.package-helper-state.v1"
)

type ToolPin struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type Policy struct {
	Version                  string                    `json:"version"`
	Enabled                  bool                      `json:"enabled"`
	NativeAcceptanceDigest   string                    `json:"nativeAcceptanceDigest"`
	ServiceFenceReviewDigest string                    `json:"serviceFenceReviewDigest"`
	ManagerID                string                    `json:"managerId"`
	EndpointID               string                    `json:"endpointId"`
	IncarnationDigest        string                    `json:"incarnationDigest"`
	KeyID                    string                    `json:"keyId"`
	TransportProfile         string                    `json:"transportProfile"`
	HTTPTestAcknowledged     bool                      `json:"httpTestAcknowledged"`
	AgentUID                 uint32                    `json:"agentUid"`
	AgentGID                 uint32                    `json:"agentGid"`
	Allowed                  []packagepermit.Selection `json:"allowed"`
	Tools                    []ToolPin                 `json:"tools"`
}
type authority struct {
	policy Policy
	raw    []byte
	key    ed25519.PublicKey
	digest string
}

// Every executable has a fixed path; local policy can pin bytes, never add a command.
var requiredTools = []string{ServiceHelperExecutable, "/usr/bin/apt-get", "/usr/bin/dpkg", SystemctlExecutable, nativeapt.NativeExecutable, nativeapt.GuardExecutable, HelperExecutable, RunnerExecutable, RunnerUnitPath}

func DecodePolicy(raw, key []byte) (Policy, error) {
	var p Policy
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal(raw, &p) != nil || !canonical(raw, p) || !keyvalidation.Ed25519(ed25519.PublicKey(key)) {
		return p, ErrRejected
	}
	if p.Version != PolicyVersion || !enrollmentcrypto.ValidID(p.ManagerID, "manager_") || !enrollmentcrypto.ValidID(p.EndpointID, "agent_") || p.KeyID != actionpermit.Digest(key) || p.AgentUID == 0 || p.AgentGID == 0 || p.AgentUID == ^uint32(0) || p.AgentGID == ^uint32(0) {
		return Policy{}, ErrRejected
	}
	for _, d := range []string{p.IncarnationDigest, p.NativeAcceptanceDigest, p.ServiceFenceReviewDigest} {
		if !actionpermit.ValidDigest(d) {
			return Policy{}, ErrRejected
		}
	}
	if p.TransportProfile != "production-tls" && p.TransportProfile != "disposable-http-test" || p.HTTPTestAcknowledged != (p.TransportProfile == "disposable-http-test") {
		return Policy{}, ErrRejected
	}
	ss := make([]nativeapt.Selection, len(p.Allowed))
	for i, s := range p.Allowed {
		if protectedPackage(s.Name) {
			return Policy{}, ErrRejected
		}
		ss[i] = nativeapt.Selection{Name: s.Name, Architecture: s.Architecture}
	}
	if _, e := nativeapt.SelectionBytes(ss); e != nil {
		return Policy{}, ErrRejected
	}
	if len(p.Tools) != len(requiredTools) {
		return Policy{}, ErrRejected
	}
	for i, pin := range p.Tools {
		if pin.Path != requiredTools[i] || !actionpermit.ValidDigest(pin.Digest) {
			return Policy{}, ErrRejected
		}
	}
	return p, nil
}
func PolicyDigest(p Policy) (string, error) {
	b, e := json.Marshal(p)
	if e != nil {
		return "", ErrRejected
	}
	return actionpermit.Digest(b), nil
}
func (a authority) pins() packagepermit.Pins {
	return packagepermit.Pins{ManagerID: a.policy.ManagerID, EndpointID: a.policy.EndpointID, IncarnationDigest: a.policy.IncarnationDigest, RootPolicyDigest: a.digest, PublicKey: a.key, Allowed: a.policy.Allowed}
}
func (a authority) same(b authority) bool { return a.digest == b.digest && bytes.Equal(a.key, b.key) }

// The first native pilot excludes the package manager, runtime, boot, network,
// remote access and Tracebolt foundations. This is not a maintainer-script sandbox.
func protectedPackage(name string) bool {
	switch name {
	case "apt", "apt-utils", "dpkg", "libc6", "libc-bin", "iproute2", "network-manager":
		return true
	}
	for _, prefix := range []string{"libapt-pkg", "libc6-", "systemd", "linux-", "kernel", "grub", "openssh", "tracebolt", "localrmm"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

//go:embed runner.service
var runnerUnitTemplate []byte
