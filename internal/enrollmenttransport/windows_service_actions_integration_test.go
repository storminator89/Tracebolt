package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowsactionwire"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type windowsActionMemory map[string][]byte

func (m windowsActionMemory) Read(n string) ([]byte, error) {
	v, ok := m[n]
	if !ok {
		return nil, windowsaction.ErrIntegrity
	}
	return bytes.Clone(v), nil
}
func (m windowsActionMemory) Write(n string, v []byte) error { m[n] = bytes.Clone(v); return nil }
func (m windowsActionMemory) Verify() error                  { return nil }

type windowsActionNativeFixture struct {
	state         uint32
	starts, stops int
}

func (f *windowsActionNativeFixture) Open(windowsaction.Target, string, string) (windowsaction.Service, error) {
	return f, nil
}
func (f *windowsActionNativeFixture) Inspect() (windowsaction.Snapshot, error) {
	pid := uint32(0)
	if f.state == 4 {
		pid = 42
	}
	return windowsaction.Snapshot{State: f.state, AcceptsStop: true, ProcessID: pid}, nil
}
func (f *windowsActionNativeFixture) Start() error { f.starts++; f.state = 4; return nil }
func (f *windowsActionNativeFixture) Stop() error  { f.stops++; f.state = 1; return nil }
func (f *windowsActionNativeFixture) Close() error { return nil }
func TestWindowsServiceActionTransportThroughBrokerAndDurableStatus(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
			h, server, client := f.listen(t, nil)
			ctx := context.Background()
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
			pub := key.Public().(ed25519.PublicKey)
			policy := windowsaction.Policy{Version: windowsaction.PolicyVersion, Enabled: true, Binding: windowsaction.Binding{ManagerID: f.config.Binding.InstanceID, EndpointID: f.snapshot.Approval.DeviceID, KeyID: windowsaction.Digest(pub), IncarnationDigest: "sha256:" + f.cert.CertificateHash(), InstallationID: "broker_" + strings.Repeat("5", 32), Target: "FixtureService"}, PublicKey: pub, BrokerSID: "S-1-5-80-1-2-3-4-5", AgentSID: "S-1-5-80-2-3-4-5-6", ReviewDigest: windowsaction.Digest([]byte("inert reviewed fixture")), Target: windowsaction.Target{Name: "FixtureService", Executable: `C:\Program Files\Fixture\app.exe`, ExecutableDigest: windowsaction.Digest([]byte("never executed")), ConfigurationDigest: windowsaction.Digest([]byte("fake config")), Classification: "reviewed-standalone-application"}}
			policy.Binding.TargetDigest = windowsaction.TargetDigest(policy.Target)
			policy.Binding.GrantDigest = windowsaction.GrantDigest(policy)
			now := time.Now().UTC()
			if e := f.store.SetupWindowsServiceActionsCreateOnly(ctx, pub, policy.Binding, now); e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "windows-command.key")
			if e := os.WriteFile(keyPath, key, 0600); e != nil {
				t.Fatal(e)
			}
			config := windowsactionmanager.Config{Version: windowsactionmanager.ConfigVersion, Enabled: true, ManagerID: policy.Binding.ManagerID, TransportProfile: windowsactionmanager.Profile(profile), HTTPTestAcknowledged: profile == "http-test", PrivateKeyFile: keyPath}
			raw, _ := json.Marshal(config)
			configPath := filepath.Join(dir, "windows-actions.json")
			if e := os.WriteFile(configPath, raw, 0600); e != nil {
				t.Fatal(e)
			}
			manager, e := windowsactionmanager.Load(ctx, f.store, configPath)
			if e != nil {
				t.Fatal(e)
			}
			defer manager.Close()
			if e = h.ConfigureWindowsServiceActions(manager); e != nil {
				t.Fatal(e)
			}
			authority, state := windowsActionMemory{}, windowsActionMemory{}
			raw, _ = json.Marshal(policy)
			authority["policy.json"] = raw
			raw, _ = json.Marshal(policy.Binding)
			authority["started.json"] = raw
			authority["receipt.json"] = raw
			raw, _ = json.Marshal(struct {
				Version    string                `json:"version"`
				Binding    windowsaction.Binding `json:"binding"`
				ClockFloor int64                 `json:"clockFloor"`
				Sequence   uint64                `json:"sequence,string"`
				Jobs       []any                 `json:"jobs"`
			}{windowsaction.LedgerVersion, policy.Binding, now.Unix(), 0, []any{}})
			state["ledger.json"] = raw
			native := &windowsActionNativeFixture{state: 1}
			broker, e := windowsaction.NewBroker(authority, state, native, func() time.Time { return time.Now().UTC() })
			if e != nil {
				t.Fatal(e)
			}
			call := func(path string, seq uint64, raw []byte, want int) []byte {
				t.Helper()
				var req *http.Request
				var e error
				if profile == "http-test" {
					req, e = windowsactionwire.NewSignedRequest(ctx, server.URL, path, f.pair, seq, time.Now().UTC(), raw)
				} else {
					req, e = http.NewRequest("POST", server.URL+path, bytes.NewReader(raw))
					if e == nil {
						req.Header.Set("Content-Type", "application/json")
					}
				}
				if e != nil {
					t.Fatal(e)
				}
				return response(t, client, req, want)
			}
			for _, op := range []string{"start", "stop", "restart"} {
				if op == "restart" {
					native.state = 4
				}
				caps, e := broker.Capabilities()
				if e != nil {
					t.Fatal(e)
				}
				raw, e = windowsactionwire.EncodeCapabilities(caps)
				if e != nil {
					t.Fatal(e)
				}
				call(windowsactionwire.CapabilitiesPath, 1, raw, 200)
				r, e := manager.Preview(ctx, policy.Binding.EndpointID, "operator_"+strings.Repeat("6", 32), policy.Binding.Target, op)
				if e != nil {
					t.Fatal("preview", e)
				}
				p := r.Preview
				r, e = manager.Approve(ctx, policy.Binding.EndpointID, p.ID, p.Digest, p.ActorID)
				if e != nil {
					t.Fatal("approval", e)
				}
				raw = call(windowsactionwire.PeekPath, 1, []byte("{}"), 200)
				if bytes.Contains(raw, []byte(`"envelope"`)) {
					t.Fatal("peek leaked envelope")
				}
				delivery, e := windowsactionwire.DecodeDelivery(raw)
				if e != nil {
					t.Fatal(e)
				}
				claim, _ := windowsactionwire.EncodeClaim(delivery.Identity)
				raw = call(windowsactionwire.ClaimPath, delivery.Identity.Sequence, claim, 200)
				grant, e := windowsactionwire.DecodeGrant(raw)
				if e != nil {
					t.Fatal(e)
				}
				call(windowsactionwire.ClaimPath, delivery.Identity.Sequence, claim, 409)
				result, e := broker.Submit(ctx, grant.Envelope)
				if e != nil || result.Phase != "complete" {
					t.Fatal("fake native broker", e, result)
				}
				raw, _ = windowsactionwire.EncodeResult(result)
				call(windowsactionwire.ResultPath, delivery.Identity.Sequence, raw, 200)
				call(windowsactionwire.ResultPath, delivery.Identity.Sequence, raw, 200)
				saved, _, e := manager.ViewAt(ctx, policy.Binding.EndpointID)
				if e != nil || saved.Jobs[len(saved.Jobs)-1].State(time.Now().UTC()) != "complete" {
					t.Fatal("durable outcome", e)
				}
			}
			if native.starts != 2 || native.stops != 2 {
				t.Fatal("unexpected native calls", native.starts, native.stops)
			}
			// The manager startup seam reopens exact existing state and never re-delivers a terminal job.
			reopened, e := windowsactionmanager.Load(ctx, f.store, configPath)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if _, e = reopened.Peek(ctx, f.snapshot.InvitationID, f.cert.CertificateHash()); e != windowsactionjob.ErrNotFound {
				t.Fatal("terminal job redelivered", e)
			}
		})
	}
}
