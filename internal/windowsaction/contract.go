// Package windowsaction is the separate, default-off selected Windows service
// action contract and restricted broker. Linux permit bytes are never admitted.
package windowsaction

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const (
	Version             = "tracebolt.windows-service-action.v1"
	CapabilitiesVersion = "tracebolt.windows-service-action-capabilities.v1"
	ResultVersion       = "tracebolt.windows-service-action-result.v1"
	Start               = "start"
	Stop                = "stop"
	Restart             = "restart"
	MaxEnvelopeBytes    = 4096
	MaxMessageBytes     = 16384
	MaxLifetime         = 120 * time.Second
	BrokerName          = "TraceboltWindowsActionBroker"
	AgentName           = "TraceboltWindowsAgent"
	PipeName            = `\\.\pipe\Tracebolt.WindowsActionBroker.v1`
)

const BrokerAccount = `NT SERVICE\TraceboltWindowsActionBroker`

var (
	ErrInvalid     = errors.New("windows_action_invalid")
	ErrUnavailable = errors.New("windows_action_unavailable")
	ErrBinding     = errors.New("windows_action_binding")
	ErrExpired     = errors.New("windows_action_expired")
	ErrConsumed    = errors.New("windows_action_consumed")
	ErrIntegrity   = errors.New("windows_action_integrity")
	ErrBusy        = errors.New("windows_action_busy")
)

// Binding is public authority metadata. It never contains a path, account,
// executable command, private enrollment material, or a request-selected key.
type Binding struct {
	ManagerID         string `json:"managerId"`
	KeyID             string `json:"keyId"`
	EndpointID        string `json:"endpointId"`
	IncarnationDigest string `json:"incarnationDigest"`
	InstallationID    string `json:"installationId"`
	GrantDigest       string `json:"grantDigest"`
	Target            string `json:"target"`
	TargetDigest      string `json:"targetDigest"`
}
type Permit struct {
	Version        string  `json:"version"`
	Binding        Binding `json:"binding"`
	Operation      string  `json:"operation"`
	JobID          string  `json:"jobId"`
	Sequence       uint64  `json:"sequence,string"`
	OperatorID     string  `json:"operatorId"`
	ApprovalDigest string  `json:"approvalDigest"`
	IssuedAt       int64   `json:"issuedAt"`
	NotBefore      int64   `json:"notBefore"`
	Deadline       int64   `json:"deadline"`
}
type Identity struct {
	JobID          string `json:"jobId"`
	Sequence       uint64 `json:"sequence,string"`
	EnvelopeDigest string `json:"envelopeDigest"`
}
type Capabilities struct {
	Version    string  `json:"version"`
	Binding    Binding `json:"binding"`
	CapturedAt int64   `json:"capturedAt"`
	Enabled    bool    `json:"enabled"`
	Busy       bool    `json:"busy"`
}
type Result struct {
	Version           string   `json:"version"`
	Identity          Identity `json:"identity"`
	Operation         string   `json:"operation"`
	Target            string   `json:"target"`
	Deadline          int64    `json:"deadline"`
	Phase             string   `json:"phase"`
	Outcome           string   `json:"outcome"`
	StopAttempted     bool     `json:"stopAttempted"`
	StopRequested     bool     `json:"stopRequested"`
	StoppedObserved   bool     `json:"stoppedObserved"`
	StartAttempted    bool     `json:"startAttempted"`
	StartRequested    bool     `json:"startRequested"`
	RunningObserved   bool     `json:"runningObserved"`
	LastObservedState uint32   `json:"lastObservedState"`
	Observations      uint32   `json:"observations"`
}
type envelope struct {
	Permit    Permit `json:"permit"`
	Signature string `json:"signature"`
}

func Digest(b []byte) string       { return actionpermit.Digest(b) }
func ValidDigest(s string) bool    { return actionpermit.ValidDigest(s) }
func ValidOperation(s string) bool { return s == Start || s == Stop || s == Restart }
func ValidTarget(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	lower := strings.ToLower(s)
	for _, prefix := range []string{"tracebolt", "windefend", "sense", "mpssvc", "bfe", "dhcp", "dnscache", "nlasvc", "netlogon", "rpcss", "dcomlaunch", "eventlog", "lanman", "winrm", "sshd", "termservice", "wuauserv", "trustedinstaller", "cryptsvc", "samss", "keyiso", "gpsvc", "lsm", "schedule", "w32time", "plugplay", "power"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}
func ValidBinding(b Binding) bool {
	return enrollmentcrypto.ValidID(b.ManagerID, "manager_") && enrollmentcrypto.ValidID(b.EndpointID, "agent_") && enrollmentcrypto.ValidID(b.InstallationID, "broker_") && ValidDigest(b.KeyID) && ValidDigest(b.IncarnationDigest) && ValidDigest(b.GrantDigest) && ValidTarget(b.Target) && ValidDigest(b.TargetDigest)
}
func ValidIdentity(i Identity) bool {
	return enrollmentcrypto.ValidID(i.JobID, "action_") && i.Sequence > 0 && ValidDigest(i.EnvelopeDigest)
}
func ValidatePermit(p Permit) error {
	if p.Version != Version || !ValidBinding(p.Binding) || !ValidOperation(p.Operation) || !enrollmentcrypto.ValidID(p.JobID, "action_") || p.Sequence == 0 || !enrollmentcrypto.ValidID(p.OperatorID, "operator_") || !ValidDigest(p.ApprovalDigest) || p.IssuedAt <= 0 || p.IssuedAt > p.NotBefore || p.NotBefore >= p.Deadline || p.Deadline > 253402300799 || p.Deadline-p.IssuedAt > int64(MaxLifetime/time.Second) {
		return ErrInvalid
	}
	return nil
}
func SigningMessage(p Permit) ([]byte, error) {
	if e := ValidatePermit(p); e != nil {
		return nil, e
	}
	b, e := json.Marshal(p)
	if e != nil {
		return nil, ErrInvalid
	}
	return append([]byte("Tracebolt selected Windows service action v1\x00"), b...), nil
}
func Encode(p Permit, signature []byte) ([]byte, error) {
	if ValidatePermit(p) != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(envelope{p, base64.RawStdEncoding.EncodeToString(signature)})
	if e != nil || len(b) > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

// DecodeCanonical rejects duplicate/unknown keys, alternate number/base64 forms,
// trailing bytes and changed field order by requiring exact re-encoding.
func DecodeCanonical(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func Decode(raw []byte) (Permit, error) {
	var x envelope
	if DecodeCanonical(raw, &x, MaxEnvelopeBytes) != nil || ValidatePermit(x.Permit) != nil {
		return Permit{}, ErrInvalid
	}
	sig, e := base64.RawStdEncoding.DecodeString(x.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return Permit{}, ErrInvalid
	}
	return x.Permit, nil
}
func CheckSignature(raw []byte, key ed25519.PublicKey) (Permit, error) {
	var x envelope
	if !keyvalidation.Ed25519(key) || DecodeCanonical(raw, &x, MaxEnvelopeBytes) != nil || ValidatePermit(x.Permit) != nil || x.Permit.Binding.KeyID != Digest(key) {
		return Permit{}, ErrInvalid
	}
	sig, e := base64.RawStdEncoding.DecodeString(x.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return Permit{}, ErrInvalid
	}
	m, _ := SigningMessage(x.Permit)
	if !ed25519.Verify(key, m, sig) {
		return Permit{}, ErrBinding
	}
	return x.Permit, nil
}
func Verify(raw []byte, key ed25519.PublicKey, b Binding, now time.Time) (Permit, error) {
	p, e := CheckSignature(raw, key)
	if e != nil {
		return Permit{}, e
	}
	if p.Binding != b {
		return Permit{}, ErrBinding
	}
	if now.Unix() < p.NotBefore || now.Unix() >= p.Deadline {
		return Permit{}, ErrExpired
	}
	return p, nil
}
func IdentityFor(raw []byte) (Identity, error) {
	p, e := Decode(raw)
	if e != nil {
		return Identity{}, e
	}
	return Identity{p.JobID, p.Sequence, Digest(raw)}, nil
}
func ValidateCapabilities(c Capabilities) error {
	if c.Version != CapabilitiesVersion || !ValidBinding(c.Binding) || c.CapturedAt <= 0 || c.CapturedAt > 253402300799 {
		return ErrInvalid
	}
	return nil
}
func ValidateResult(r Result) error {
	if r.Version != ResultVersion || !ValidIdentity(r.Identity) || !ValidOperation(r.Operation) || !ValidTarget(r.Target) || r.Deadline <= 0 || r.Deadline > 253402300799 || r.Observations > 184 || r.LastObservedState > 7 || r.StopRequested && !r.StopAttempted || r.StartRequested && !r.StartAttempted || r.StartAttempted && r.Operation == Stop || r.StopAttempted && r.Operation == Start {
		return ErrInvalid
	}
	switch r.Phase {
	case "admitted", "dispatching", "complete":
	default:
		return ErrInvalid
	}
	switch r.Outcome {
	case "not-requested", "intervention-required", "running-observed", "stopped-observed":
	default:
		return ErrInvalid
	}
	if r.Phase != "complete" && r.Outcome != "not-requested" && r.Outcome != "intervention-required" {
		return ErrInvalid
	}
	if r.Outcome == "not-requested" && (r.StartAttempted || r.StopAttempted) {
		return ErrInvalid
	}
	if r.Outcome == "running-observed" && (r.Phase != "complete" || !r.StartRequested || !r.RunningObserved || r.Operation == Stop || r.Operation == Restart && (!r.StopRequested || !r.StoppedObserved)) {
		return ErrInvalid
	}
	if r.Outcome == "stopped-observed" && (r.Phase != "complete" || r.Operation != Stop || !r.StopRequested || !r.StoppedObserved) {
		return ErrInvalid
	}
	return nil
}
