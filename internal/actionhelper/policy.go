// Package actionhelper is the default-off, fixed-purpose Linux action-helper
// boundary. Its runtime only consumes separately provisioned local authority.
package actionhelper

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"localrmm/internal/actionpermit"
)

const (
	PolicyVersion      = "tracebolt.action-helper-policy.v1"
	ProductionTLS      = "production-tls"
	DisposableHTTPTest = "disposable-http-test"
	PolicyPath         = "/etc/tracebolt/action-helper.json"
	PublicKeyPath      = "/etc/tracebolt/action-command.pub"
	StateDirectory     = "/var/lib/tracebolt-action-helper"
	SocketPath         = "/run/tracebolt-action-helper/action.sock"
	MaxPolicyBytes     = 64 << 10
)

var (
	ErrRejected    = errors.New("action_helper_rejected")
	ErrBusy        = errors.New("action_helper_busy")
	ErrUnavailable = errors.New("action_helper_unavailable")
)

// Policy is a separately provisioned root-local grant. Its canonical bytes are
// exactly what the permit's RootPolicyDigest commits to, including transport.
// HTTPTestAcknowledged declares acceptance that stolen plaintext operator
// sessions can authorize actions within this disposable scope. No transport is
// implemented here; the manager independently enforces TLS/profile admission.
type Policy struct {
	Version              string   `json:"version"`
	Enabled              bool     `json:"enabled"`
	ManagerID            string   `json:"managerId"`
	KeyID                string   `json:"keyId"`
	EndpointID           string   `json:"endpointId"`
	IncarnationDigest    string   `json:"incarnationDigest"`
	TransportProfile     string   `json:"transportProfile"`
	HTTPTestAcknowledged bool     `json:"httpTestAcknowledged"`
	AgentUID             uint32   `json:"agentUid"`
	AgentGID             uint32   `json:"agentGid"`
	MaxLifetimeSeconds   int64    `json:"maxLifetimeSeconds"`
	MaxFutureSkewSeconds int64    `json:"maxFutureSkewSeconds"`
	Targets              []Target `json:"targets"`
	Scope                string   `json:"scope,omitempty"`
}

// Target is the bounded result of an independent local administrator review.
// The reviewer asserts that these pins cover relevant stop/restart effects and
// execution inputs. This library checks the pins; it cannot prove that assertion
// or analyze arbitrary scripts. Only simple, locally reviewed services fit.
type Target struct {
	Unit         string    `json:"unit"`
	ReviewDigest string    `json:"reviewDigest"`
	Units        []UnitPin `json:"units"`
	Inputs       []FilePin `json:"inputs"`
	// V2-only live dispatch input; legacy reviewed target policies reject it.
	AffectedServicesDigest string `json:"affectedServicesDigest,omitempty"`
}
type UnitPin struct {
	Unit                string `json:"unit"`
	ConfigurationDigest string `json:"configurationDigest"`
}
type FilePin struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// Authority is a trusted loader snapshot. Revision includes protected-file
// identity, not just contents. Neither this type nor an injected fixture loader
// proves root protection; production only uses the fixed protected loader.
type Authority struct {
	Policy    Policy
	PublicKey ed25519.PublicKey
	Revision  string
}
type Peer struct {
	UID, GID uint32
	PID      int32
}

func canonicalUnit(unit string) bool {
	_, err := actionpermit.PlanDigest(actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: unit, UnitPolicyDigest: actionpermit.Digest(nil)})
	return err == nil
}
func protectedUnit(unit string) bool {
	n := strings.ToLower(strings.TrimSuffix(unit, ".service"))
	for _, fragment := range []string{"tracebolt", "localrmm", "ssh", "network", "networking", "firewall", "nftables", "iptables", "ufw", "firewalld", "connman", "wicked", "dhcp", "dhclient", "resolved", "dnsmasq", "tailscale", "wireguard", "openvpn", "strongswan", "ipsec"} {
		if strings.Contains(n, fragment) {
			return true
		}
	}
	return strings.HasPrefix(n, "systemd-") || n == "dbus" || n == "dbus-broker"
}
func safeInputPath(p string) bool {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || len(p) > 512 || strings.ContainsAny(p, "\x00\r\n\t ") {
		return false
	}
	// Limit the first support profile to administrator-owned persistent material.
	return strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/opt/")
}
func targetDigest(t Target) (string, error) {
	if t.AffectedServicesDigest != "" || !canonicalUnit(t.Unit) || protectedUnit(t.Unit) || !actionpermit.ValidDigest(t.ReviewDigest) || len(t.Units) < 1 || len(t.Units) > 16 || len(t.Inputs) < 1 || len(t.Inputs) > 32 {
		return "", ErrRejected
	}
	last := ""
	found := false
	for _, u := range t.Units {
		if !canonicalUnit(u.Unit) || protectedUnit(u.Unit) || u.Unit <= last || !actionpermit.ValidDigest(u.ConfigurationDigest) {
			return "", ErrRejected
		}
		last = u.Unit
		found = found || u.Unit == t.Unit
	}
	if !found {
		return "", ErrRejected
	}
	last = ""
	for _, f := range t.Inputs {
		if !safeInputPath(f.Path) || f.Path <= last || !actionpermit.ValidDigest(f.Digest) {
			return "", ErrRejected
		}
		last = f.Path
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", ErrRejected
	}
	return actionpermit.Digest(b), nil
}
func policyVerifier(p Policy, key ed25519.PublicKey) (actionpermit.Verifier, error) {
	if (p.Version != PolicyVersion && p.Version != PolicyVersionV2) || p.KeyID != actionpermit.Digest(key) || p.AgentUID == 0 || p.AgentGID == 0 || p.AgentUID == ^uint32(0) || p.AgentGID == ^uint32(0) || (p.Version == PolicyVersion && (p.Scope != "" || len(p.Targets) < 1 || len(p.Targets) > 16)) || (p.Version == PolicyVersionV2 && (p.Scope != FullAdminServiceScope || p.Targets == nil || len(p.Targets) != 0)) {
		return actionpermit.Verifier{}, ErrRejected
	}
	switch p.TransportProfile {
	case ProductionTLS:
		if p.HTTPTestAcknowledged {
			return actionpermit.Verifier{}, ErrRejected
		}
	case DisposableHTTPTest:
		if !p.HTTPTestAcknowledged {
			return actionpermit.Verifier{}, ErrRejected
		}
	default:
		return actionpermit.Verifier{}, ErrRejected
	}
	rules := make([]actionpermit.ServiceRule, 0, len(p.Targets))
	last := ""
	for _, t := range p.Targets {
		d, e := targetDigest(t)
		if e != nil || t.Unit <= last {
			return actionpermit.Verifier{}, ErrRejected
		}
		last = t.Unit
		rules = append(rules, actionpermit.ServiceRule{Unit: t.Unit, UnitPolicyDigest: d})
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxPolicyBytes {
		return actionpermit.Verifier{}, ErrRejected
	}
	return actionpermit.NewVerifier(actionpermit.LocalPins{Enabled: p.Enabled, ManagerID: p.ManagerID, PublicKey: key, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: actionpermit.Digest(raw), MaxLifetimeSeconds: p.MaxLifetimeSeconds, MaxFutureSkewSeconds: p.MaxFutureSkewSeconds, Services: rules, Scope: p.Scope})
}
func decodePolicy(raw []byte, key ed25519.PublicKey) (Policy, error) {
	var p Policy
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || json.Unmarshal(raw, &p) != nil {
		return p, ErrRejected
	}
	b, e := json.Marshal(p)
	if e != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), b) {
		return Policy{}, ErrRejected
	}
	if _, e = policyVerifier(p, key); e != nil {
		return Policy{}, ErrRejected
	}
	return p, nil
}
func (a Authority) verifier() (actionpermit.Verifier, error) {
	if !actionpermit.ValidDigest(a.Revision) {
		return actionpermit.Verifier{}, ErrRejected
	}
	return policyVerifier(a.Policy, a.PublicKey)
}
func (a Authority) target(unit string) (Target, error) {
	for _, t := range a.Policy.Targets {
		if t.Unit == unit {
			return t, nil
		}
	}
	return Target{}, ErrRejected
}
func (a Authority) permitsPeer(p Peer) bool {
	return p.PID > 0 && p.UID == a.Policy.AgentUID && p.GID == a.Policy.AgentGID
}
