// Package socketowner defines a fixed socket-owner helper and authenticated
// client source candidate. Provisioning and native acceptance remain separate
// gates; the client must be used with the authoritative activated-identity path.
package socketowner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"localrmm/internal/systeminventory"
)

const (
	PolicyVersion            = "tracebolt.socket-owner-policy.v1"
	ProtocolVersion          = "tracebolt.socket-owner-ipc.v1"
	Scope                    = "systemd-pid1-local-tcp-udp-socket-owners"
	CaptureOperation         = "capture"
	VerifyOperation          = "verify"
	StatusCaptured           = "captured"
	StatusVerified           = "verified"
	StatusDenied             = "denied"
	StatusInvalid            = "invalid"
	StatusBusy               = "busy"
	StatusRateLimited        = "rate_limited"
	StatusUnavailable        = "unavailable"
	MaxPolicyBytes           = 4096
	MaxRequestBytes          = 2048
	MaxResponseBytes         = systeminventory.MaxSectionBytes + 1024
	MaxConnections           = 2
	CaptureTimeout           = 5 * time.Second
	ConnectionTimeout        = 6 * time.Second
	CaptureInterval          = 30 * time.Second
	PtraceCapability  uint64 = 1 << 19
)

var ErrRejected = errors.New("socket_owner_rejected")
var ErrChanged = errors.New("socket_owner_authority_changed")
var generation = regexp.MustCompile(`^sample_[0-9a-f]{32}$`)

// Policy is supplied only by the fixed protected local loader, never IPC.
// SenderBinding deliberately retains today's exact identity binding. Renewal
// must fail closed until a separately reviewed transition contract exists.
type Policy struct {
	Version                string `json:"version"`
	Scope                  string `json:"scope"`
	SenderBinding          string `json:"senderBinding"`
	ManagerOrigin          string `json:"managerOrigin"`
	TransportProfile       string `json:"transportProfile"`
	CollectionProfile      string `json:"collectionProfile"`
	AgentUID               uint32 `json:"agentUid"`
	AgentGID               uint32 `json:"agentGid"`
	HelperUID              uint32 `json:"helperUid"`
	HelperGID              uint32 `json:"helperGid"`
	Epoch                  string `json:"epoch"`
	Enabled                bool   `json:"enabled"`
	MetadataAcknowledged   bool   `json:"metadataAcknowledged"`
	PtraceRiskAcknowledged bool   `json:"ptraceRiskAcknowledged"`
	HTTPAcknowledged       bool   `json:"httpAcknowledged"`
}

func validID(n uint32) bool { return n != 0 && n != ^uint32(0) }

// systemd initgroups may repeat the already-bound primary GID once. This grants
// no additional group: foreign IDs, duplicates and multiple entries still fail.
// The int form is used for Getgroups, without narrowing a signed/wide value.
func primaryOnlyGroups[T ~int | ~uint32](groups []T, gid uint32) bool {
	return validID(gid) && (len(groups) == 0 || len(groups) == 1 && uint64(groups[0]) == uint64(gid))
}
func hash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s && strings.Trim(s, "0") != ""
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func validatePolicy(p Policy) error {
	u, e := url.Parse(p.ManagerOrigin)
	if p.Version != PolicyVersion || p.Scope != Scope || !hash(p.SenderBinding) || !hash(p.Epoch) || p.CollectionProfile != "managed-operations-v3" || !p.MetadataAcknowledged || !p.PtraceRiskAcknowledged || !validID(p.AgentUID) || !validID(p.AgentGID) || !validID(p.HelperUID) || !validID(p.HelperGID) || p.AgentUID == p.HelperUID || p.AgentGID == p.HelperGID {
		return ErrRejected
	}
	if e != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Host != strings.ToLower(u.Host) || len(p.ManagerOrigin) > 512 || strings.ContainsAny(p.ManagerOrigin, "\\%\r\n\t ") || p.ManagerOrigin != u.Scheme+"://"+u.Host {
		return ErrRejected
	}
	if !(p.TransportProfile == "tls" && u.Scheme == "https" && !p.HTTPAcknowledged || p.TransportProfile == "http-test" && u.Scheme == "http" && p.HTTPAcknowledged) {
		return ErrRejected
	}
	return nil
}
func EncodePolicy(p Policy) ([]byte, error) {
	if validatePolicy(p) != nil {
		return nil, ErrRejected
	}
	b, e := json.Marshal(p)
	if e != nil || len(b) > MaxPolicyBytes {
		return nil, ErrRejected
	}
	return b, nil
}
func DecodePolicy(b []byte) (Policy, error) {
	var p Policy
	if canonical(b, MaxPolicyBytes, &p) != nil || validatePolicy(p) != nil {
		return Policy{}, ErrRejected
	}
	return p, nil
}
func PolicyDigest(p Policy) string {
	b, e := EncodePolicy(p)
	if e != nil {
		return ""
	}
	return digest(b)
}

// Authority.Revision binds protected file/object metadata, not just policy bytes.
// ProtectedPolicyVerified covers root ownership/modes and object rechecks.
// ProtectedGrantBindingVerified covers the administrator grant and v2 deployment
// contract bound to the approved agent artifact. Together with native Facts and
// the exact request comparison, this proves grant/principal binding, NOT current
// enrollment identity. The approved client checks authoritative identity before
// and after capture, before staging, and before every send/retry/restart.
// Both booleans are false-by-default proof-result seams, never IPC claims.
type Authority struct {
	Policy                        Policy
	Revision                      string
	ProtectedPolicyVerified       bool
	ProtectedGrantBindingVerified bool
}
type NamespaceID struct{ Device, Inode uint64 }
type NamespaceSet struct{ PID, Net, User NamespaceID }

// Facts are independently supplied by a native credential/pidfd/nsfs adapter.
// Booleans here are explicit injection seams, never request flags or OS proof.
// Capabilities are effective, permitted, inheritable, ambient, bounding sets.
type Facts struct {
	// These gates require exact owned artifact/unit/no-namespace-override,
	// fixed procfs PID1, and inherited-listener/sockfs witness verification.
	OwnedDeploymentVerified, ProcViewVerified, SocketWitnessVerified      bool
	PeerUIDs, PeerGIDs                                                    [3]uint32
	PeerGroups                                                            []uint32
	PeerCapabilities                                                      [5]uint64
	HelperUIDs, HelperGIDs                                                [3]uint32
	Groups                                                                []uint32
	Capabilities                                                          [5]uint64
	PeerUID, PeerGID                                                      uint32
	PeerPID, WriterPID                                                    int32
	PeerPIDFDSupported, PeerAlive, WriterVerified, NamespaceTypesVerified bool
	// ManagerNamespaces must come from pinned local systemd PID 1 nsfs handles.
	HelperNamespaces, PeerNamespaces, ManagerNamespaces NamespaceSet
	ProcPIDView                                         NamespaceID
	RuntimeID                                           string
}

func validNamespace(n NamespaceID) bool { return n.Device != 0 && n.Inode != 0 }
func reference(a Authority, f Facts) (Reference, error) {
	p := a.Policy
	if validatePolicy(p) != nil || !a.ProtectedPolicyVerified || !a.ProtectedGrantBindingVerified || !p.Enabled || !hash(a.Revision) || !hash(f.RuntimeID) || f.HelperUIDs != [3]uint32{p.HelperUID, p.HelperUID, p.HelperUID} || f.HelperGIDs != [3]uint32{p.HelperGID, p.HelperGID, p.HelperGID} || f.PeerUID != p.AgentUID || f.PeerGID != p.AgentGID || f.PeerPID <= 0 || f.WriterPID != f.PeerPID || !f.PeerPIDFDSupported || !f.PeerAlive || !f.WriterVerified || !f.NamespaceTypesVerified {
		return Reference{}, ErrRejected
	}
	if !primaryOnlyGroups(f.Groups, p.HelperGID) || !primaryOnlyGroups(f.PeerGroups, p.AgentGID) || f.PeerUIDs != [3]uint32{p.AgentUID, p.AgentUID, p.AgentUID} || f.PeerGIDs != [3]uint32{p.AgentGID, p.AgentGID, p.AgentGID} || f.PeerCapabilities != [5]uint64{} || !f.OwnedDeploymentVerified || !f.ProcViewVerified || !f.SocketWitnessVerified {
		return Reference{}, ErrRejected
	}
	for _, set := range f.Capabilities {
		if set != PtraceCapability {
			return Reference{}, ErrRejected
		}
	}
	n := f.HelperNamespaces
	if !validNamespace(n.PID) || !validNamespace(n.Net) || !validNamespace(n.User) || n != f.PeerNamespaces || n != f.ManagerNamespaces || f.ProcPIDView != n.PID {
		return Reference{}, ErrRejected
	}
	b, _ := json.Marshal(struct {
		Domain, Runtime string
		Namespaces      NamespaceSet
	}{Scope, f.RuntimeID, n})
	return Reference{p.Epoch, PolicyDigest(p), a.Revision, digest(b)}, nil
}

// Reference is public correlation metadata, never bearer authorization. A new
// runtime invalidates old references without authorizing a new namespace scope.
type Reference struct {
	GrantEpoch        string `json:"grantEpoch"`
	PolicyDigest      string `json:"policyDigest"`
	AuthorityRevision string `json:"authorityRevision"`
	ContextID         string `json:"contextId"`
}

func validReference(r Reference) bool {
	return hash(r.GrantEpoch) && hash(r.PolicyDigest) && hash(r.AuthorityRevision) && hash(r.ContextID)
}

type Request struct {
	Version       string     `json:"version"`
	Operation     string     `json:"operation"`
	SenderBinding string     `json:"senderBinding"`
	GrantEpoch    string     `json:"grantEpoch"`
	PolicyDigest  string     `json:"policyDigest"`
	GenerationID  string     `json:"generationId"`
	Reference     *Reference `json:"reference"`
}

func validateRequest(r Request) error {
	if r.Version != ProtocolVersion || !hash(r.SenderBinding) || !hash(r.GrantEpoch) || !hash(r.PolicyDigest) {
		return ErrRejected
	}
	switch r.Operation {
	case CaptureOperation:
		if !generation.MatchString(r.GenerationID) || r.Reference != nil {
			return ErrRejected
		}
	case VerifyOperation:
		if r.GenerationID != "" || r.Reference != nil && (!validReference(*r.Reference) || r.Reference.GrantEpoch != r.GrantEpoch || r.Reference.PolicyDigest != r.PolicyDigest) {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	return nil
}

// Observation carries helper-owned times, not a caller-supplied freshness label.
// Callers must preserve this interval in durable systemwire provenance.
type Observation struct {
	GenerationID string                   `json:"generationId"`
	StartedAt    time.Time                `json:"startedAt"`
	FinishedAt   time.Time                `json:"finishedAt"`
	Sockets      []systeminventory.Socket `json:"sockets"`
}

func (Observation) String() string               { return "socketowner.Observation{rows redacted}" }
func (o Observation) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, o.String()) }
func validateObservation(o Observation) error {
	if !generation.MatchString(o.GenerationID) || !validTime(o.StartedAt) || !validTime(o.FinishedAt) || o.FinishedAt.Before(o.StartedAt) || o.FinishedAt.Sub(o.StartedAt) > CaptureTimeout {
		return ErrRejected
	}
	s := systeminventory.Empty(o.GenerationID, o.StartedAt, systeminventory.ReasonNotCollected)
	n := uint64(len(o.Sockets))
	s.Sockets = systeminventory.SocketSection{Meta: systeminventory.SectionMeta{GenerationID: o.GenerationID, ObservedAt: o.StartedAt, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &n, CountExact: true}, Items: o.Sockets}
	if systeminventory.Validate(s) != nil {
		return ErrRejected
	}
	return nil
}

type Response struct {
	Version     string       `json:"version"`
	Status      string       `json:"status"`
	Reference   *Reference   `json:"reference"`
	Observation *Observation `json:"observation"`
}

func (Response) String() string               { return "socketowner.Response{rows redacted}" }
func (r Response) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func validateResponse(r Response) error {
	if r.Version != ProtocolVersion {
		return ErrRejected
	}
	switch r.Status {
	case StatusCaptured:
		if r.Reference == nil || !validReference(*r.Reference) || r.Observation == nil || validateObservation(*r.Observation) != nil {
			return ErrRejected
		}
	case StatusVerified:
		if r.Reference == nil || !validReference(*r.Reference) || r.Observation != nil {
			return ErrRejected
		}
	case StatusDenied, StatusInvalid, StatusBusy, StatusRateLimited, StatusUnavailable:
		if r.Reference != nil || r.Observation != nil {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	return nil
}
func canonical(b []byte, max int, out any) error {
	if len(b) == 0 || len(b) > max {
		return ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRejected
	}
	again, e := json.Marshal(out)
	if e != nil || !bytes.Equal(b, again) {
		return ErrRejected
	}
	return nil
}
