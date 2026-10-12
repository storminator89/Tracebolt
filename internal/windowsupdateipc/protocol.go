// Package windowsupdateipc is the selected-update-only local transport. It has
// no observation collection or service-control opcodes and creates no grants.
package windowsupdateipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowspath"
	job "localrmm/internal/windowsupdatejob"
)

const Version = "tracebolt.windows-selected-update-ipc.v1"
const PeerVersion = "tracebolt.windows-update-executor-peer.v1"
const PipeName = `\\.\pipe\Tracebolt.Windows.SelectedUpdate.v1`
const MaxMessageBytes = 64 << 10
const RequestLimit = 40 * time.Second
const proofDomain = "tracebolt.windows-selected-update-ipc-server-proof.v1\x00"

var ErrPeer = errors.New("windows_update_ipc_peer_unproven")

// PeerConfig is public but must arrive from separately consented protected local
// state. The digest pins the exact foreground configuration including consent.
// A key pin alone is insufficient; image and config identity are also bound.
type PeerConfig struct {
	Version             string      `json:"version"`
	Binding             job.Binding `json:"binding"`
	ExecutorPublicKey   []byte      `json:"executorPublicKey"`
	Executable          string      `json:"executable"`
	ExecutableDigest    string      `json:"executableDigest"`
	ConfigurationDigest string      `json:"configurationDigest"`
}

func (p PeerConfig) Validate() error {
	if p.Version != PeerVersion || !job.ValidBinding(p.Binding) || !keyvalidation.Ed25519(p.ExecutorPublicKey) || actionpermit.Digest(p.ExecutorPublicKey) != p.Binding.ExecutorKeyID || !windowspath.Canonical(p.Executable) || !strings.HasSuffix(strings.ToLower(p.Executable), ".exe") || !actionpermit.ValidDigest(p.ExecutableDigest) || !actionpermit.ValidDigest(p.ConfigurationDigest) {
		return ErrPeer
	}
	return nil
}

type hello struct {
	Version string      `json:"version"`
	Nonce   []byte      `json:"nonce"`
	Binding job.Binding `json:"binding"`
}
type proof struct {
	Version             string      `json:"version"`
	Nonce               []byte      `json:"nonce"`
	Binding             job.Binding `json:"binding"`
	ProcessID           uint32      `json:"processId"`
	Created             uint64      `json:"created,string"`
	ExecutableDigest    string      `json:"executableDigest"`
	ConfigurationDigest string      `json:"configurationDigest"`
}
type signedProof struct {
	Proof     proof  `json:"proof"`
	Signature []byte `json:"signature"`
}

func signProof(h hello, c PeerConfig, pid uint32, created uint64, key ed25519.PrivateKey) ([]byte, error) {
	if h.Version != Version || len(h.Nonce) != 32 || h.Binding != c.Binding || c.Validate() != nil || pid == 0 || created == 0 || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), c.ExecutorPublicKey) {
		return nil, ErrPeer
	}
	p := proof{Version, h.Nonce, c.Binding, pid, created, c.ExecutableDigest, c.ConfigurationDigest}
	raw, _ := json.Marshal(p)
	return json.Marshal(signedProof{p, ed25519.Sign(key, append([]byte(proofDomain), raw...))})
}
func verifyProof(raw []byte, h hello, c PeerConfig, pid uint32, created uint64) error {
	var s signedProof
	if h.Version != Version || h.Binding != c.Binding || c.Validate() != nil || decode(raw, &s) != nil || s.Proof.Version != Version || !bytes.Equal(s.Proof.Nonce, h.Nonce) || len(h.Nonce) != 32 || s.Proof.Binding != c.Binding || s.Proof.ProcessID != pid || pid == 0 || s.Proof.Created != created || created == 0 || s.Proof.ExecutableDigest != c.ExecutableDigest || s.Proof.ConfigurationDigest != c.ConfigurationDigest {
		return ErrPeer
	}
	b, _ := json.Marshal(s.Proof)
	if !ed25519.Verify(c.ExecutorPublicKey, append([]byte(proofDomain), b...), s.Signature) {
		return ErrPeer
	}
	return nil
}

type request struct {
	Version         string `json:"version"`
	Operation       string `json:"operation"`
	Envelope        []byte `json:"envelope,omitempty"`
	Kind            string `json:"kind,omitempty"`
	JobID           string `json:"jobId,omitempty"`
	ReferenceDigest string `json:"referenceDigest,omitempty"`
}

func (r request) validate() error {
	if r.Version != Version {
		return job.ErrInvalid
	}
	switch r.Operation {
	case "peer", "status":
		if r.Envelope != nil || r.Kind != "" || r.JobID != "" || r.ReferenceDigest != "" {
			return job.ErrInvalid
		}
	case "readiness", "submit":
		if len(r.Envelope) == 0 || len(r.Envelope) > job.MaxRelayBytes || r.Kind != "" || r.JobID != "" || r.ReferenceDigest != "" {
			return job.ErrInvalid
		}
	case "outbox":
		if r.Envelope != nil || (r.Kind != "readiness" && r.Kind != "result") || !enrollmentcrypto.ValidID(r.JobID, "update_") || !actionpermit.ValidDigest(r.ReferenceDigest) {
			return job.ErrInvalid
		}
	default:
		return job.ErrInvalid
	}
	return nil
}

type response struct {
	Version string              `json:"version"`
	Error   string              `json:"error,omitempty"`
	Report  []byte              `json:"report,omitempty"`
	Status  *job.ExecutorStatus `json:"status,omitempty"`
}

func decode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return job.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return job.ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return job.ErrInvalid
	}
	return nil
}

// Client performs a new held-process + nonce proof on EVERY call. No method
// retries a connected write, including Submit. A lost response is status-only.
type Client struct {
	config PeerConfig
	call   func(context.Context, PeerConfig, request) (response, error)
}

func NewClient(c PeerConfig) (*Client, error) {
	if c.Validate() != nil {
		return nil, ErrPeer
	}
	c.ExecutorPublicKey = bytes.Clone(c.ExecutorPublicKey)
	return &Client{c, callNative}, nil
}
func (c *Client) request(ctx context.Context, r request) (response, error) {
	if c == nil || c.call == nil || ctx == nil || r.validate() != nil {
		return response{}, job.ErrInvalid
	}
	out, e := c.call(ctx, c.config, r)
	if e != nil {
		return response{}, e
	}
	if out.Version != Version || out.Error != "" {
		return response{}, job.ErrUnavailable
	}
	return out, nil
}
func (c *Client) CheckPeer(ctx context.Context, b job.Binding) error {
	if c == nil || b != c.config.Binding {
		return ErrPeer
	}
	r, e := c.request(ctx, request{Version: Version, Operation: "peer"})
	if e != nil {
		return e
	}
	if r.Status != nil || r.Report != nil {
		return job.ErrInvalid
	}
	return nil
}
func (c *Client) Readiness(ctx context.Context, raw []byte) ([]byte, error) {
	r, e := c.request(ctx, request{Version: Version, Operation: "readiness", Envelope: raw})
	if e != nil {
		return nil, e
	}
	if r.Status != nil || len(r.Report) == 0 || len(r.Report) > job.MaxRelayBytes {
		return nil, job.ErrInvalid
	}
	return r.Report, nil
}
func (c *Client) Submit(ctx context.Context, raw []byte) error {
	r, e := c.request(ctx, request{Version: Version, Operation: "submit", Envelope: raw})
	if e != nil {
		return e
	}
	if r.Status != nil || r.Report != nil {
		return job.ErrInvalid
	}
	return nil
}
func (c *Client) Status(ctx context.Context) (job.ExecutorStatus, error) {
	r, e := c.request(ctx, request{Version: Version, Operation: "status"})
	if e != nil {
		return job.ExecutorStatus{}, e
	}
	if r.Status == nil || r.Report != nil {
		return job.ExecutorStatus{}, job.ErrInvalid
	}
	return *r.Status, nil
}
func (c *Client) Outbox(ctx context.Context, kind, id, digest string) ([]byte, error) {
	r, e := c.request(ctx, request{Version: Version, Operation: "outbox", Kind: kind, JobID: id, ReferenceDigest: digest})
	if e != nil {
		return nil, e
	}
	if r.Status != nil || len(r.Report) == 0 || len(r.Report) > job.MaxRelayBytes {
		return nil, job.ErrInvalid
	}
	return r.Report, nil
}
func newHello(c PeerConfig) (hello, error) {
	h := hello{Version: Version, Nonce: make([]byte, 32), Binding: c.Binding}
	_, e := rand.Read(h.Nonce)
	return h, e
}
