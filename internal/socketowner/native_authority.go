package socketowner

import "encoding/json"

const (
	SocketPath        = "/run/tracebolt-socket-owner-reader/reader.sock"
	deploymentVersion = "tracebolt.socket-owner-deployment.v2"
	deploymentProfile = "systemd-pid1-local-ptrace-activated-client-v2"
	maxRecordBytes    = 4096
)

// ClientContract identifies the reviewed unprivileged activated-identity producer
// and authenticated socket client path. A v2 deployment explicitly binds that
// contract to the exact approved AgentSHA256; the string alone is not proof that
// an arbitrary binary implements it. Provisioning must verify that artifact.
const ClientContract = "tracebolt.socket-owner-activated-identity-client.v1"

type Deployment struct {
	Version          string `json:"version"`
	Profile          string `json:"profile"`
	ClientContract   string `json:"clientContract"`
	PolicyDigest     string `json:"policyDigest"`
	HelperSHA256     string `json:"helperSha256"`
	AgentSHA256      string `json:"agentSha256"`
	HelperUnitSHA256 string `json:"helperUnitSha256"`
	AgentUnitSHA256  string `json:"agentUnitSha256"`
	SocketUnitSHA256 string `json:"socketUnitSha256"`
}

type fixedObject uint8

const (
	policyObject fixedObject = iota
	deploymentObject
	helperObject
	agentObject
	helperUnitObject
	agentUnitObject
	socketUnitObject
	objectCount
)

// A protectedObject is created only by the no-follow root-owned native loader.
// Revision covers inode, ownership, mode, link count, size and mtime/ctime, not
// atime. The fixture seam supplies invented objects, never proof from IPC.
type protectedObject struct {
	Body             []byte
	Digest, Revision string
	GID              uint32
}
type protectedReader interface {
	Read(fixedObject) (protectedObject, error)
	Recheck(fixedObject, protectedObject) error
	NoOverrides() error
}
type nativeAuthority struct {
	Authority
	Deployment Deployment
	Objects    [objectCount]protectedObject
}

func loadNativeAuthority(r protectedReader) (nativeAuthority, error) {
	var state nativeAuthority
	if r == nil {
		return state, ErrRejected
	}
	for i := fixedObject(0); i < objectCount; i++ {
		obj, err := r.Read(i)
		if err != nil || !hash(obj.Digest) || !hash(obj.Revision) {
			return nativeAuthority{}, ErrRejected
		}
		state.Objects[i] = obj
	}
	p, err := DecodePolicy(state.Objects[policyObject].Body)
	var d Deployment
	if err != nil || !p.Enabled || canonical(state.Objects[deploymentObject].Body, maxRecordBytes, &d) != nil {
		return nativeAuthority{}, ErrRejected
	}
	if d.Version != deploymentVersion || d.Profile != deploymentProfile || d.ClientContract != ClientContract || d.PolicyDigest != PolicyDigest(p) {
		return nativeAuthority{}, ErrRejected
	}
	for i := policyObject; i <= deploymentObject; i++ {
		if state.Objects[i].GID != p.HelperGID {
			return nativeAuthority{}, ErrRejected
		}
	}
	hashes := []string{d.HelperSHA256, d.AgentSHA256, d.HelperUnitSHA256, d.AgentUnitSHA256, d.SocketUnitSHA256}
	for i, expected := range hashes {
		obj := state.Objects[int(helperObject)+i]
		if !hash(expected) || expected != obj.Digest || obj.GID != 0 {
			return nativeAuthority{}, ErrRejected
		}
	}
	if r.NoOverrides() != nil {
		return nativeAuthority{}, ErrRejected
	}
	for i := fixedObject(0); i < objectCount; i++ {
		if r.Recheck(i, state.Objects[i]) != nil {
			return nativeAuthority{}, ErrChanged
		}
	}
	revisions := make([]string, 0, int(objectCount)*2)
	for _, obj := range state.Objects {
		revisions = append(revisions, obj.Digest, obj.Revision)
	}
	raw, _ := json.Marshal(revisions)
	state.Authority = Authority{Policy: p, Revision: digest(raw), ProtectedPolicyVerified: true, ProtectedGrantBindingVerified: true}
	state.Deployment = d
	return state, nil
}
