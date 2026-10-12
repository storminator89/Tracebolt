package windowsupdateipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowsupdatejob"
	"strings"
	"testing"
)

func testPeer() (PeerConfig, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32))
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	binding := job.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("identity")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("4", 32), KeyID: actionpermit.Digest(manager.Public().(ed25519.PublicKey))}
	return PeerConfig{PeerVersion, binding, key.Public().(ed25519.PublicKey), `C:\Program Files\Tracebolt\tracebolt-windows-update-executor.exe`, actionpermit.Digest([]byte("image")), actionpermit.Digest([]byte("public config"))}, key
}
func TestFreshProofBindsHeldProcessCreationImageConfigAndDomain(t *testing.T) {
	c, key := testPeer()
	h := hello{Version, bytes.Repeat([]byte{7}, 32), c.Binding}
	raw, e := signProof(h, c, 23, 6789, key)
	if e != nil || verifyProof(raw, h, c, 23, 6789) != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"nonce", "pid", "created", "image", "config", "binding", "key", "domain", "unknown"} {
		t.Run(change, func(t *testing.T) {
			p := c
			p.ExecutorPublicKey = bytes.Clone(c.ExecutorPublicKey)
			challenge := h
			challenge.Nonce = bytes.Clone(h.Nonce)
			pid, created := uint32(23), uint64(6789)
			proofRaw := bytes.Clone(raw)
			switch change {
			case "nonce":
				challenge.Nonce[0]++
			case "pid":
				pid++
			case "created":
				created++
			case "image":
				p.ExecutableDigest = actionpermit.Digest([]byte("other"))
			case "config":
				p.ConfigurationDigest = actionpermit.Digest([]byte("other"))
			case "binding":
				p.Binding.GrantID = "grant_" + strings.Repeat("9", 32)
			case "key":
				p.ExecutorPublicKey[0]++
			case "domain":
				var s signedProof
				_ = json.Unmarshal(raw, &s)
				b, _ := json.Marshal(s.Proof)
				s.Signature = ed25519.Sign(key, b)
				proofRaw, _ = json.Marshal(s)
			case "unknown":
				proofRaw = append(proofRaw[:len(proofRaw)-1], []byte(`,"serviceControl":true}`)...)
			}
			if verifyProof(proofRaw, challenge, p, pid, created) == nil {
				t.Fatal("unproven peer accepted")
			}
		})
	}
}
func TestClientNeverRetriesLostSubmitOrOtherOperations(t *testing.T) {
	c, _ := testPeer()
	client, _ := NewClient(c)
	calls := 0
	client.call = func(context.Context, PeerConfig, request) (response, error) {
		calls++
		return response{}, job.ErrUncertain
	}
	if e := client.Submit(context.Background(), []byte("signed permit")); !errors.Is(e, job.ErrUncertain) || calls != 1 {
		t.Fatal(e, calls)
	}
	if e := client.CheckPeer(context.Background(), job.Binding{}); !errors.Is(e, ErrPeer) || calls != 1 {
		t.Fatal("wrong binding touched transport", e)
	}
}
func TestUpdateIPCRejectsForeignOpcodesAndFieldSmuggling(t *testing.T) {
	for _, op := range []string{"restart", "stop", "start", "download", "install", "command", "delete", "acknowledge", "reset"} {
		if (request{Version: Version, Operation: op}).validate() == nil {
			t.Fatal(op)
		}
	}
	for _, r := range []request{{Version: Version, Operation: "status", Envelope: []byte("x")}, {Version: Version, Operation: "peer", Kind: "result"}, {Version: Version, Operation: "submit", Envelope: []byte("x"), JobID: "other"}, {Version: Version, Operation: "outbox", Kind: "result", JobID: "bad"}} {
		if r.validate() == nil {
			t.Fatal(r)
		}
	}
}
func TestClientRequiresTypedResponse(t *testing.T) {
	c, _ := testPeer()
	client, _ := NewClient(c)
	client.call = func(context.Context, PeerConfig, request) (response, error) {
		return response{Version: Version, Report: []byte("smuggled")}, nil
	}
	if client.Submit(context.Background(), []byte("permit")) == nil || client.CheckPeer(context.Background(), c.Binding) == nil {
		t.Fatal("unexpected output accepted")
	}
}
func TestPipeAccessExcludesInstanceCreation(t *testing.T) {
	const explicitClientAccess uint32 = 0x00120183
	if explicitClientAccess&4 != 0 {
		t.Fatal("FILE_CREATE_PIPE_INSTANCE")
	}
}

func TestRetirementIPCIsTypedAndNeverRetries(t *testing.T) {
	peer, _ := testPeer()
	client, _ := NewClient(peer)
	calls := 0
	client.call = func(_ context.Context, _ PeerConfig, r request) (response, error) {
		calls++
		if r.Operation != "retire" || !bytes.Equal(r.Envelope, []byte("exact retirement")) {
			t.Fatal("wrong opcode", r.Operation)
		}
		return response{}, job.ErrUncertain
	}
	if _, e := client.Retire(context.Background(), []byte("exact retirement")); !errors.Is(e, job.ErrUncertain) || calls != 1 {
		t.Fatal("retirement replayed", calls, e)
	}
	r := request{Version: Version, Operation: "outbox", Kind: "retired", JobID: "update_" + strings.Repeat("4", 32), ReferenceDigest: actionpermit.Digest([]byte("retire"))}
	if r.validate() != nil {
		t.Fatal("saved retirement outbox denied")
	}
	r.Envelope = []byte("smuggled")
	if r.validate() == nil {
		t.Fatal("outbox accepted command")
	}
	client.call = func(context.Context, PeerConfig, request) (response, error) {
		return response{Version: Version, Status: &job.ExecutorStatus{}}, nil
	}
	if _, e := client.Retire(context.Background(), []byte("exact retirement")); e == nil {
		t.Fatal("retirement accepted untyped status")
	}
}
