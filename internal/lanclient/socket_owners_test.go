//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/socketowner"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every key, identity, row, helper and HTTP exchange below is invented. The
// tests create only private temporary fixture files; no listener, socket,
// native collection, helper process, external service or permission change runs.
type socketRoundTripper func(*http.Request) (*http.Response, error)

func (f socketRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type socketFixture struct {
	t                                   *testing.T
	sender                              *systemSender
	material                            Material
	key                                 ed25519.PrivateKey
	path                                string
	now                                 time.Time
	local                               SocketOwnerConsent
	reference                           socketowner.Reference
	bodies                              [][]byte
	captures, verifies, reads, ordinary int
	failHTTP                            bool
	readerHook                          func(int)
	verifyHook                          func(int)
	captureHook                         func()
	helperError                         error
	observationHook                     func(*socketowner.Observation)
}

func (f *socketFixture) Verify(_ context.Context, p socketowner.Policy, expected *socketowner.Reference) (socketowner.Reference, error) {
	f.verifies++
	if f.verifyHook != nil {
		f.verifyHook(f.verifies)
	}
	if f.helperError != nil {
		return socketowner.Reference{}, f.helperError
	}
	if socketowner.PolicyDigest(p) != f.reference.PolicyDigest || p.Epoch != f.reference.GrantEpoch || expected != nil && *expected != f.reference {
		return socketowner.Reference{}, socketowner.ErrChanged
	}
	return f.reference, nil
}
func (f *socketFixture) Capture(_ context.Context, p socketowner.Policy, id string, expected socketowner.Reference) (socketowner.Observation, error) {
	f.captures++
	if f.captureHook != nil {
		f.captureHook()
	}
	if f.helperError != nil || expected != f.reference || socketowner.PolicyDigest(p) != f.reference.PolicyDigest {
		return socketowner.Observation{}, socketowner.ErrChanged
	}
	started := f.now
	f.now = f.now.Add(10*time.Millisecond + 123*time.Nanosecond)
	name := "invented-process"
	out := socketowner.Observation{GenerationID: id, StartedAt: started, FinishedAt: f.now, Sockets: []systeminventory.Socket{{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: 41234}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{{PID: 123, ProcessName: &name, NameReason: systeminventory.ReasonNone}}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionObserved, Reason: systeminventory.ReasonNone}}}}
	if f.observationHook != nil {
		f.observationHook(&out)
	}
	return out, nil
}
func (f *socketFixture) writeCertificate(serial int64) {
	f.t.Helper()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, f.key.Public(), f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	f.write(f.material.config.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func (f *socketFixture) write(path string, raw []byte) {
	f.t.Helper()
	if os.WriteFile(path, raw, 0600) != nil {
		f.t.Fatal("fixture write")
	}
}
func (f *socketFixture) writeConfig(c Config) {
	f.t.Helper()
	raw, _ := json.Marshal(c)
	f.write(f.path, raw)
	hash := sha256.Sum256(raw)
	material, err := loadConfig(c)
	if err != nil {
		f.t.Fatal("fixture configuration", err)
	}
	ready, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(hash[:]), "certificateHash": journalLeaf(material), "serverAuthenticated": c.Profile == "tls"})
	f.write(filepath.Join(filepath.Dir(f.path), "ready.json"), ready)
}
func (f *socketFixture) writeConsent() {
	raw, _ := json.Marshal(f.local)
	f.write(socketOwnerConsentPath(f.material), raw)
}
func (f *socketFixture) open() {
	f.t.Helper()
	sender, err := openSystemSenderWithSource(f.material, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		f.ordinary++
		return systeminventory.Empty(id, at, systeminventory.ReasonPermissionDenied), nil
	}, func() time.Time { return f.now })
	if err != nil {
		f.t.Fatal(err)
	}
	f.sender = sender
	sender.socketHelper = f
	// Only the numeric service-process identity is fake. Actual config, ready,
	// key/certificate agreement and all three ledgers use the existing producer.
	sender.socketIdentity = func(path string) (Material, uint32, uint32, error) {
		f.reads++
		if f.readerHook != nil {
			f.readerHook(f.reads)
		}
		m, e := loadActionSetupMaterial(path)
		return m, 1234, 1234, e
	}
	sender.client = &http.Client{Transport: socketRoundTripper(func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		f.bodies = append(f.bodies, bytes.Clone(raw))
		if f.failHTTP {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		}
		frame, err := systemwire.Decode(raw)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		receipt, _ := json.Marshal(systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: f.material.config.AgentID, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: frame.Snapshot.CollectedAt, ReceivedAt: f.now, BodyHash: hex.EncodeToString(sum[:])})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(receipt))}, nil
	})}
}
func newSocketFixture(t *testing.T) *socketFixture { return newSocketFixtureProfile(t, "http-test") }
func newSocketFixtureProfile(t *testing.T, profile string) *socketFixture {
	t.Helper()
	dir := t.TempDir()
	f := &socketFixture{t: t, now: time.Now().UTC().Truncate(time.Second), key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32)), path: filepath.Join(dir, "agent.json")}
	c := Config{SchemaVersion: CompleteConfigVersion, CollectionProfile: "managed-operations-v3", Profile: "http-test", ManagerOrigin: "http://socket-fixture.test", AgentID: "agent_" + strings.Repeat("a", 32), CertificateFile: filepath.Join(dir, "client.pem"), PrivateKeyFile: filepath.Join(dir, "client-key.pem"), StateDirectory: filepath.Join(dir, "state"), InsecureHTTPAcknowledged: profile == "http-test"}
	if profile == "tls" {
		c.Profile = "tls"
		c.ManagerOrigin = "https://socket-fixture.test"
		c.InsecureHTTPAcknowledged = false
		c.ServerCAFile = filepath.Join(dir, "server-ca.pem")
		ca := &x509.Certificate{SerialNumber: big.NewInt(8), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		raw, err := x509.CreateCertificate(rand.Reader, ca, ca, f.key.Public(), f.key)
		if err != nil {
			t.Fatal(err)
		}
		f.write(c.ServerCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	f.material.config = c
	f.writeCertificate(1)
	key, _ := x509.MarshalPKCS8PrivateKey(f.key)
	f.write(c.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if InitializeGuidedState(c) != nil {
		t.Fatal("fixture state")
	}
	f.writeConfig(c)
	m, err := Load(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.material = m
	p := socketowner.Policy{Version: socketowner.PolicyVersion, Scope: socketowner.Scope, SenderBinding: m.binding, ManagerOrigin: c.ManagerOrigin, TransportProfile: c.Profile, CollectionProfile: c.CollectionProfile, AgentUID: 1234, AgentGID: 1234, HelperUID: 1235, HelperGID: 1235, Epoch: strings.Repeat("e", 64), Enabled: true, MetadataAcknowledged: true, PtraceRiskAcknowledged: true, HTTPAcknowledged: profile == "http-test"}
	f.local = SocketOwnerConsent{Version: SocketOwnerConsentVersion, EndpointID: c.AgentID, IncarnationDigest: "sha256:" + journalLeaf(m), Policy: p}
	f.reference = socketowner.Reference{GrantEpoch: p.Epoch, PolicyDigest: socketowner.PolicyDigest(p), AuthorityRevision: strings.Repeat("b", 64), ContextID: strings.Repeat("c", 64)}
	f.writeConsent()
	f.open()
	t.Cleanup(func() { f.sender.Close() })
	return f
}
func (f *socketFixture) frame(i int) systemwire.Frame {
	f.t.Helper()
	frame, err := systemwire.Decode(f.bodies[i])
	if err != nil {
		f.t.Fatal(err)
	}
	return frame
}
func (f *socketFixture) change(kind string) {
	f.t.Helper()
	c := f.material.config
	switch kind {
	case "binding":
		c.AgentID = "agent_" + strings.Repeat("d", 32)
		f.writeConfig(c)
	case "certificate":
		f.writeCertificate(2)
		f.writeConfig(c)
	case "key":
		f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
		f.writeCertificate(2)
		key, _ := x509.MarshalPKCS8PrivateKey(f.key)
		f.write(c.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		f.writeConfig(c)
	case "origin":
		c.ManagerOrigin = map[string]string{"tls": "https://other-fixture.test", "http-test": "http://other-fixture.test"}[c.Profile]
		f.writeConfig(c)
	case "profile":
		c.SchemaVersion = OperationalConfigVersion
		c.CollectionProfile = "managed-operations-v1"
		raw, _ := json.Marshal(c)
		f.write(f.path, raw)
	case "activation":
		f.write(filepath.Join(filepath.Dir(f.path), "ready.json"), []byte(`{}`))
	case "metrics_ledger":
		f.write(filepath.Join(c.StateDirectory, "state.json"), []byte(`{}`))
	case "inventory_ledger":
		if os.Rename(inventoryStateDirectory(c), inventoryStateDirectory(c)+"-preserved") != nil {
			f.t.Fatal("fixture inventory withdrawal")
		}
	case "consent":
		f.local.Policy.Enabled = false
		f.writeConsent()
	case "epoch":
		f.reference.GrantEpoch = strings.Repeat("f", 64)
	case "runtime":
		f.reference.ContextID = strings.Repeat("f", 64)
	case "revision":
		f.reference.AuthorityRevision = strings.Repeat("f", 64)
	default:
		f.t.Fatal("unknown mutation", kind)
	}
}

func TestSocketOwnersCallPathExactRetryRestartAndOriginalTimes(t *testing.T) {
	f := newSocketFixture(t)
	f.failHTTP = true
	report, err := f.sender.Run(context.Background())
	if !errors.Is(err, ErrSystemTransport) || report.Sequence != 1 || len(f.bodies) != 1 || f.captures != 1 {
		t.Fatal(report, err)
	}
	first := f.frame(0)
	if first.SocketOwnerProvenance == nil || first.Snapshot.DurationMS != 11 || first.Snapshot.Sockets.Items[0].Owners[0].PID != 123 {
		t.Fatal("missing source/time/owner")
	}
	captured := *first.SocketOwnerProvenance
	if !captured.StartedAt.Equal(first.Snapshot.CollectedAt) || !captured.FinishedAt.Equal(f.now) {
		t.Fatal("helper times relabelled")
	}
	f.sender.Close()
	f.open()
	f.now = f.now.Add(30 * time.Second)
	f.failHTTP = false
	report, err = f.sender.Run(context.Background())
	if err != nil || !report.RetriedPending || report.Sequence != 1 || report.Status != "acknowledged" || f.captures != 1 || f.ordinary != 1 || len(f.bodies) != 2 || !bytes.Equal(f.bodies[0], f.bodies[1]) {
		t.Fatal("exact retry failed", report, err)
	}
	if *f.frame(1).SocketOwnerProvenance != captured {
		t.Fatal("retry renewed age")
	}
	next, err := f.sender.state.NextSequence()
	if err != nil || next != 2 {
		t.Fatal("floor", next, err)
	}
}

func TestSocketOwnersCallPathActivatedChangesAtCaptureStageSend(t *testing.T) {
	for _, phase := range []struct {
		name string
		read int
	}{{"before_capture", 1}, {"after_capture", 3}, {"before_stage", 4}, {"before_send", 6}} {
		for _, kind := range []string{"binding", "certificate", "key", "origin", "profile", "activation", "metrics_ledger", "inventory_ledger", "consent"} {
			t.Run(phase.name+"/"+kind, func(t *testing.T) {
				f := newSocketFixture(t)
				f.readerHook = func(n int) {
					if n == phase.read {
						f.change(kind)
					}
				}
				report, err := f.sender.Run(context.Background())
				if err != nil {
					t.Fatal(report, err)
				}
				if phase.name == "before_send" {
					if len(f.bodies) != 0 || report.Status != "socket_owners_disabled" {
						t.Fatal("tagged body sent after identity change")
					}
					pending, e := f.sender.state.Pending()
					next, ne := f.sender.state.NextSequence()
					if e != nil || ne != nil || pending != nil || next != 2 {
						t.Fatal("discard did not preserve floor")
					}
				} else if len(f.bodies) != 1 || f.frame(0).SocketOwnerProvenance != nil || f.frame(0).Snapshot.Sockets.Meta.Coverage != systeminventory.Failed || f.frame(0).Sequence != 1 {
					t.Fatal("ordinary fallback lost or enriched bytes escaped")
				}
				if phase.name == "before_capture" && f.captures != 0 {
					t.Fatal("captured before currentness")
				}
			})
		}
	}
}

func TestSocketOwnersCallPathWithdrawnPendingWholeBodyDiscardAtRetryRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		for _, kind := range []string{"binding", "certificate", "key", "origin", "profile", "activation", "metrics_ledger", "inventory_ledger", "consent", "epoch", "runtime", "revision", "expired"} {
			t.Run(kind+map[bool]string{false: "/retry", true: "/restart"}[restart], func(t *testing.T) {
				f := newSocketFixtureProfile(t, "tls")
				f.failHTTP = true
				if _, err := f.sender.Run(context.Background()); !errors.Is(err, ErrSystemTransport) {
					t.Fatal(err)
				}
				old := bytes.Clone(f.bodies[0])
				before := f.frame(0)
				if before.SocketOwnerProvenance == nil {
					t.Fatal("fixture missing helper source")
				}
				if restart {
					f.sender.Close()
					f.open()
				}
				if kind == "expired" {
					f.now = f.now.Add(3 * time.Minute)
				} else {
					f.change(kind)
				}
				f.failHTTP = false
				_, err := f.sender.Run(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(f.bodies) != 2 || bytes.Equal(old, f.bodies[1]) || f.frame(1).Sequence != 2 {
					t.Fatal("old body retried or sequence reused")
				}
				// A new runtime can legitimately yield a new capture/reference;
				// changed grants/identity never migrate the old grant implicitly.
				if kind != "runtime" && kind != "revision" && kind != "expired" && f.frame(1).SocketOwnerProvenance != nil {
					t.Fatal("stale grant implicitly migrated")
				}
				next, e := f.sender.state.NextSequence()
				if e != nil || next != 3 {
					t.Fatal("floor lost")
				}
			})
		}
	}
}

func TestSocketOwnersOptionalFailureKeepsOrdinaryInventory(t *testing.T) {
	for _, kind := range []string{"absent", "malformed", "disabled", "foreign_binding", "foreign_endpoint", "foreign_incarnation", "foreign_uid", "helper", "generation", "times", "nil_rows", "oversized_interval", "no_path", "budget"} {
		t.Run(kind, func(t *testing.T) {
			f := newSocketFixture(t)
			switch kind {
			case "absent":
				if os.Rename(socketOwnerConsentPath(f.material), socketOwnerConsentPath(f.material)+"-preserved") != nil {
					t.Fatal("fixture consent")
				}
			case "malformed":
				f.write(socketOwnerConsentPath(f.material), []byte(`{}`))
			case "disabled":
				f.change("consent")
			case "foreign_binding":
				f.local.Policy.SenderBinding = strings.Repeat("f", 64)
				f.writeConsent()
			case "foreign_endpoint":
				f.local.EndpointID = "agent_" + strings.Repeat("f", 32)
				f.writeConsent()
			case "foreign_incarnation":
				f.local.IncarnationDigest = "sha256:" + strings.Repeat("f", 64)
				f.writeConsent()
			case "foreign_uid":
				f.local.Policy.AgentUID++
				f.writeConsent()
			case "helper":
				f.helperError = socketowner.ErrRejected
			case "generation":
				f.observationHook = func(o *socketowner.Observation) { o.GenerationID = "sample_" + strings.Repeat("f", 32) }
			case "times":
				f.observationHook = func(o *socketowner.Observation) { o.StartedAt = o.StartedAt.Add(-time.Second) }
			case "nil_rows":
				f.observationHook = func(o *socketowner.Observation) { o.Sockets = nil }
			case "oversized_interval":
				f.observationHook = func(o *socketowner.Observation) {
					o.FinishedAt = o.StartedAt.Add(6 * time.Second)
					f.now = o.FinishedAt
				}
			case "no_path":
				f.sender.material.configPath = ""
			}
			ctx := context.Background()
			if kind == "budget" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			report, err := f.sender.Run(ctx)
			if err != nil || report.Status != "acknowledged" || len(f.bodies) != 1 || f.frame(0).SocketOwnerProvenance != nil || f.ordinary != 1 {
				t.Fatal("optional source suppressed ordinary inventory", report, err)
			}
			if kind == "absent" || kind == "malformed" || strings.HasPrefix(kind, "foreign_") || kind == "disabled" || kind == "no_path" || kind == "budget" {
				if f.captures != 0 || f.verifies != 0 {
					t.Fatal("contacted helper without grant/current identity/budget")
				}
			}
		})
	}
}

func TestSocketOwnersProducerReadsAllExistingLedgers(t *testing.T) {
	f := newSocketFixture(t)
	if _, _, _, err := f.sender.socketIdentity(f.path); err != nil {
		t.Fatal(err)
	}
	if os.Rename(systemStateDirectory(f.material.config), systemStateDirectory(f.material.config)+"-preserved") != nil {
		t.Fatal("fixture system withdrawal")
	}
	if _, _, _, err := f.sender.socketIdentity(f.path); !errors.Is(err, ErrState) {
		t.Fatal("missing system ledger accepted", err)
	}
	// A missing/corrupt active ledger is never reinitialized or repaired. Sender
	// state itself fails closed, retaining the old directory and consumed floor.
	if _, err := f.sender.Run(context.Background()); !errors.Is(err, ErrState) {
		t.Fatal("missing sender state adopted", err)
	}
	if len(f.bodies) != 0 || f.captures != 0 {
		t.Fatal("source/network escaped missing ledger")
	}
}

func TestSocketOwnersCaptureMutationAndHelperWithdrawalCheckpoints(t *testing.T) {
	for _, phase := range []string{"capture", "prestage", "presend"} {
		for _, kind := range []string{"activation", "certificate", "consent", "epoch", "runtime", "revision"} {
			t.Run(phase+"/"+kind, func(t *testing.T) {
				f := newSocketFixture(t)
				if phase == "capture" {
					f.captureHook = func() { f.change(kind) }
				} else {
					target := 2
					if phase == "presend" {
						target = 3
					}
					f.verifyHook = func(n int) {
						if n == target {
							f.change(kind)
						}
					}
				}
				report, err := f.sender.Run(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if phase == "presend" {
					if len(f.bodies) != 0 || report.Status != "socket_owners_disabled" {
						t.Fatal("withdrawn staged body escaped")
					}
					pending, e := f.sender.state.Pending()
					next, ne := f.sender.state.NextSequence()
					if e != nil || ne != nil || pending != nil || next != 2 {
						t.Fatal("whole body/floor violation")
					}
				} else if len(f.bodies) != 1 || f.frame(0).SocketOwnerProvenance != nil {
					t.Fatal("capture/authority mutation escaped")
				}
			})
		}
	}
}

func TestSocketOwnersChangesAtFinalRetrySendDiscardConsumedBody(t *testing.T) {
	for _, restart := range []bool{false, true} {
		for _, kind := range []string{"binding", "certificate", "key", "origin", "profile", "activation", "metrics_ledger", "inventory_ledger", "consent", "epoch", "runtime", "revision"} {
			t.Run(kind+map[bool]string{false: "/retry", true: "/restart"}[restart], func(t *testing.T) {
				f := newSocketFixture(t)
				f.failHTTP = true
				if _, err := f.sender.Run(context.Background()); !errors.Is(err, ErrSystemTransport) {
					t.Fatal(err)
				}
				if restart {
					f.sender.Close()
					f.open()
				}
				target := f.reads + 3 // after retry admission, immediately before send
				f.readerHook = func(n int) {
					if n == target {
						f.change(kind)
					}
				}
				f.failHTTP = false
				report, err := f.sender.Run(context.Background())
				if err != nil || report.Status != "socket_owners_disabled" || len(f.bodies) != 1 || f.captures != 1 {
					t.Fatal("retry checkpoint escaped", report, err)
				}
				pending, e := f.sender.state.Pending()
				next, ne := f.sender.state.NextSequence()
				if e != nil || ne != nil || pending != nil || next != 2 {
					t.Fatal("retry discard reused floor")
				}
			})
		}
	}
}

func TestSocketOwnersSystemLedgerLossAtCheckpointNeverRepairsOrSends(t *testing.T) {
	for _, phase := range []struct {
		name string
		read int
	}{{"before_capture", 1}, {"after_capture", 3}, {"before_stage", 4}, {"before_send", 6}, {"retry", 8}, {"final_retry_send", 10}} {
		t.Run(phase.name, func(t *testing.T) {
			f := newSocketFixture(t)
			if phase.read > 7 {
				f.failHTTP = true
				if _, err := f.sender.Run(context.Background()); !errors.Is(err, ErrSystemTransport) {
					t.Fatal(err)
				}
			}
			sent := len(f.bodies)
			dir := systemStateDirectory(f.material.config)
			f.readerHook = func(n int) {
				if n == phase.read {
					if os.Rename(dir, dir+"-preserved") != nil {
						t.Fatal("fixture ledger withdrawal")
					}
				}
			}
			_, err := f.sender.Run(context.Background())
			if !errors.Is(err, ErrState) || len(f.bodies) != sent {
				t.Fatal("missing system ledger was adopted or body sent", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("missing ledger recreated")
			}
			// Inspect the preserved fixture bytes only. They must still record
			// the consumed floor and whole pending body when already staged.
			raw, err := os.ReadFile(filepath.Join(dir+"-preserved", "system-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("fixture record")
			}
			expected := float64(0)
			if phase.read >= 6 {
				expected = 1
			}
			if record["lastSequence"] != expected {
				t.Fatal("consumed sequence changed", record["lastSequence"])
			}
		})
	}
}

func TestSocketOwnersPreserveExistingOptionalSections(t *testing.T) {
	f := newSocketFixture(t)
	consentFixture(t, f.material)
	cachedUpdatesConsentFixture(t, f.material)
	f.sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
		return endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied), nil
	}
	f.sender.updatesCollect = func(_ context.Context, id string, at time.Time, _ cachedupdates.LocalConsent, _ string) (cachedupdates.Snapshot, error) {
		return cachedupdates.Empty(id, at, cachedupdates.ReasonPermissionDenied), nil
	}
	if _, err := f.sender.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	frame := f.frame(0)
	if frame.SocketOwnerProvenance == nil || frame.EndpointIdentity == nil || frame.CachedUpdates == nil || frame.ConsentScope != endpointidentity.Scope || frame.CachedUpdatesConsentScope != cachedupdates.Scope {
		t.Fatal("optional sections lost")
	}
}
func TestSocketOwnersNewIdentityCannotAdoptOldPendingLedger(t *testing.T) {
	for _, kind := range []string{"certificate", "key", "binding", "origin"} {
		t.Run(kind, func(t *testing.T) {
			f := newSocketFixture(t)
			f.failHTTP = true
			if _, err := f.sender.Run(context.Background()); !errors.Is(err, ErrSystemTransport) {
				t.Fatal(err)
			}
			old, err := os.ReadFile(filepath.Join(systemStateDirectory(f.material.config), "system-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			f.sender.Close()
			f.change(kind)
			changed, err := Load(f.path)
			if err != nil {
				t.Fatal(err)
			}
			if changed.binding == f.material.binding {
				t.Fatal("fixture did not change binding")
			}
			if _, err = openSystemSenderWithSource(changed, f.sender.collect, f.sender.now); !errors.Is(err, ErrState) {
				t.Fatal("new identity adopted old sequence domain", err)
			}
			after, err := os.ReadFile(filepath.Join(systemStateDirectory(f.material.config), "system-state.json"))
			if err != nil || !bytes.Equal(old, after) {
				t.Fatal("renewal changed old pending/floor")
			}
			if len(f.bodies) != 1 {
				t.Fatal("renewal transmitted")
			}
		})
	}
}
