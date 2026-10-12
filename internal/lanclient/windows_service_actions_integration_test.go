//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowsactionwire"
)

type actionMemory struct{ files map[string][]byte }

func (s *actionMemory) Read(n string) ([]byte, error) {
	b, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (s *actionMemory) Write(n string, b []byte) error { s.files[n] = bytes.Clone(b); return nil }
func (s *actionMemory) Verify() error                  { return nil }

type actionSCM struct {
	state         uint32
	stops, starts int
}

func (s *actionSCM) Open(windowsaction.Target, string, string) (windowsaction.Service, error) {
	return s, nil
}
func (s *actionSCM) Inspect() (windowsaction.Snapshot, error) {
	pid := uint32(0)
	if s.state == 4 {
		pid = 777
	}
	return windowsaction.Snapshot{State: s.state, AcceptsStop: true, ProcessID: pid}, nil
}
func (s *actionSCM) Stop() error  { s.stops++; s.state = 1; return nil }
func (s *actionSCM) Start() error { s.starts++; s.state = 4; return nil }
func (s *actionSCM) Close() error { return nil }

type brokerBridge struct {
	broker            *windowsaction.Broker
	lost              bool
	submits, statuses int
}

func (b *brokerBridge) Capabilities(context.Context) (windowsaction.Capabilities, error) {
	return b.broker.Capabilities()
}
func (b *brokerBridge) Submit(ctx context.Context, raw []byte) (windowsaction.Result, error) {
	b.submits++
	r, e := b.broker.Submit(ctx, raw)
	if b.lost {
		b.lost = false
		return windowsaction.Result{}, errors.New("invented lost broker response")
	}
	return r, e
}
func (b *brokerBridge) Status(_ context.Context, id windowsaction.Identity) (windowsaction.Result, error) {
	b.statuses++
	return b.broker.Status(id)
}
func TestWindowsActionManagerIngressRelayBrokerThreeOperationsAndLostResponse(t *testing.T) {
	for _, relayVersion := range []string{"v1", "v2"} {
		for _, profile := range []string{"tls", "http-test"} {
			for _, op := range []string{windowsaction.Start, windowsaction.Stop, windowsaction.Restart} {
				t.Run(relayVersion+"/"+profile+"/"+op, func(t *testing.T) {
					f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", profile)
					ctx := context.Background()
					now := time.Now().UTC().Truncate(time.Second)
					key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{109}, 32))
					pub := key.Public().(ed25519.PublicKey)
					p := windowsaction.Policy{Version: windowsaction.PolicyVersion, Enabled: true, Binding: windowsaction.Binding{ManagerID: f.config.Binding.InstanceID, KeyID: windowsaction.Digest(pub), EndpointID: f.material.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(f.material), InstallationID: "broker_" + strings.Repeat("1", 32), Target: "InventedStandaloneApp"}, PublicKey: pub, BrokerSID: "S-1-5-80-1-2-3-4-5", AgentSID: "S-1-5-80-2-3-4-5-6", Target: windowsaction.Target{Name: "InventedStandaloneApp", Executable: `C:\Program Files\Fixture\app.exe`, ExecutableDigest: windowsaction.Digest([]byte("exe")), ConfigurationDigest: windowsaction.Digest([]byte("config")), Classification: "reviewed-standalone-application"}, ReviewDigest: windowsaction.Digest([]byte("review"))}
					if relayVersion == "v2" {
						p.ProvisioningVersion = windowsaction.ProvisionVersion
					}
					p.Binding.TargetDigest = windowsaction.TargetDigest(p.Target)
					p.Binding.GrantDigest = windowsaction.GrantDigest(p)
					if e := f.store.SetupWindowsServiceActionsCreateOnly(ctx, pub, p.Binding, now); e != nil {
						t.Fatal("manager setup", e)
					}
					dir := t.TempDir()
					keyPath := filepath.Join(dir, "command.key")
					configPath := filepath.Join(dir, "command.json")
					if e := os.WriteFile(keyPath, key, 0600); e != nil {
						t.Fatal(e)
					}
					config := windowsactionmanager.Config{Version: windowsactionmanager.ConfigVersion, Enabled: true, ManagerID: f.config.Binding.InstanceID, TransportProfile: windowsactionmanager.Profile(profile), HTTPTestAcknowledged: profile == "http-test", PrivateKeyFile: keyPath}
					raw, _ := json.Marshal(config)
					if e := os.WriteFile(configPath, raw, 0600); e != nil {
						t.Fatal(e)
					}
					manager, e := windowsactionmanager.Load(ctx, f.store, configPath)
					if e != nil {
						t.Fatal("load", e)
					}
					defer manager.Close()
					if e = f.ingress.ConfigureWindowsServiceActions(manager); e != nil {
						t.Fatal(e)
					}
					authority := &actionMemory{files: map[string][]byte{}}
					state := &actionMemory{files: map[string][]byte{}}
					raw, _ = json.Marshal(p)
					authority.files["policy.json"] = raw
					raw, _ = json.Marshal(p.Binding)
					authority.files["started.json"] = raw
					authority.files["receipt.json"] = raw
					bindingRaw, _ := json.Marshal(p.Binding)
					state.files["ledger.json"] = []byte(`{"version":"tracebolt.windows-service-action-ledger.v1","binding":` + string(bindingRaw) + `,"clockFloor":` + jsonNumber(now.Unix()) + `,"sequence":"0","jobs":[]}`)
					scm := &actionSCM{state: 4}
					if op == windowsaction.Start {
						scm.state = 1
					}
					broker, e := windowsaction.NewBroker(authority, state, scm, func() time.Time { return time.Now().UTC() })
					if e != nil {
						t.Fatal(e)
					}
					bridge := &brokerBridge{broker: broker, lost: op == windowsaction.Restart}
					grant := WindowsActionRelayGrant{"tracebolt.windows-service-action-relay.v1", true, f.material.binding, f.material.config.ManagerOrigin, p.Binding, profile == "http-test", "", ""}
					sender := openWindowsActionSender(f.material)
					defer sender.Close()
					if relayVersion == "v2" {
						grant.Version = "tracebolt.windows-service-action-relay.v2"
						grant.ProvisionDigest = windowsaction.Digest([]byte("reviewed provision plan"))
						grant.BrokerImageDigest = windowsaction.Digest([]byte("reviewed broker image"))
					}
					queryCalls := 0
					sender.peerQueries = func(context.Context, windowsaction.Binding, string) error { queryCalls++; return nil }
					sender.local = func(Material) (WindowsActionRelayGrant, error) { return grant, nil }
					sender.current = func(Material) bool { return true }
					sender.broker = bridge
					sender.client = &http.Client{Transport: fullServicesRoundTrip(func(r *http.Request) (*http.Response, error) {
						if profile == "tls" {
							cert, _ := x509.ParseCertificate(f.material.certificate.Certificate[0])
							issuerCert, _ := x509.ParseCertificate(f.issuer.IssuerDER())
							r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, issuerCert}}}
						}
						w := httptest.NewRecorder()
						f.ingress.ServeHTTP(w, r)
						return w.Result(), nil
					})}
					if got := sender.Run(ctx); got != "idle" {
						t.Fatal("capabilities", got)
					}
					actor := "operator_" + strings.Repeat("2", 32)
					r, e := manager.Preview(ctx, p.Binding.EndpointID, actor, p.Binding.Target, op)
					if e != nil {
						t.Fatal("preview", e)
					}
					r, e = manager.Approve(ctx, p.Binding.EndpointID, r.Preview.ID, r.Preview.Digest, actor)
					if e != nil {
						t.Fatal("approve", e)
					}
					id := r.Jobs[0].Identity()
					got := sender.Run(ctx)
					if op == windowsaction.Restart {
						if got != "outcome_unknown" {
							t.Fatal("lost response", got)
						}
						got = sender.Run(ctx)
					}
					if got != "reported" {
						t.Fatal("execute", got)
					}
					r, e = manager.View(ctx, p.Binding.EndpointID)
					if e != nil || len(r.Jobs[0].Results) != 1 || r.Jobs[0].Results[0].Phase != "complete" {
						t.Fatal("durable result", e, r)
					}
					result := r.Jobs[0].Results[0]
					if result.Identity != id || bridge.submits != 1 || scm.starts > 1 || scm.stops > 1 {
						t.Fatal("identity/repeat", result, bridge.submits, scm)
					}
					if op == windowsaction.Restart && bridge.statuses != 1 {
						t.Fatal("lost response was not status-only")
					}
					if relayVersion == "v1" && queryCalls != 0 || relayVersion == "v2" && queryCalls == 0 {
						t.Fatal("fresh peer query consent was promoted or skipped")
					}
					// Old read grants and local revocation cannot even reach IPC or HTTP actions.
					submits := bridge.submits
					grant.Enabled = false
					if got = sender.Run(ctx); got != "disabled" || bridge.submits != submits {
						t.Fatal("disabled grant", got)
					}
					// HTTP authentication has a Windows-specific domain, never the Linux path.
					if !strings.HasPrefix(windowsactionwire.ClaimPath, "/v1/windows-service-actions/") {
						t.Fatal("mixed domain")
					}
				})
			}
		}
	}
}
func jsonNumber(n int64) string { b, _ := json.Marshal(n); return string(b) }
