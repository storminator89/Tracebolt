package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanclient"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lantrust"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
)

var errRetentionFixture = errors.New("private fixture error that must not escape")

type retentionFixture struct {
	t                                                     *testing.T
	r                                                     installReceipt
	files                                                 map[string]map[string][]byte
	specs                                                 map[string]setupRetentionSpec
	stopped                                               bool
	activeOpens, openHandles, materialCalls, inspectCalls int
	faultPath, fault                                      string
	reads                                                 [][]byte
	stages                                                []string
}

func retentionJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	return raw
}
func newRetentionFixture(t *testing.T, http bool) *retentionFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Tracebolt", "windows-agent")
	l := windowsservice.Layout{ProgramFiles: filepath.Dir(root), ProgramData: filepath.Dir(root), Executable: filepath.Join(filepath.Dir(root), "service.exe"), StateRoot: root, EnrollmentRoot: filepath.Join(root, "enrollment"), SenderRoot: filepath.Join(root, "enrollment", "telemetry")}
	consent := readSetupConsentFixture()
	consent.InsecureHTTPAcknowledged = http
	r := installReceipt{Version: 2, Prepared: true, Service: windowsservice.Receipt{Version: 1, Complete: true, Layout: l, ServiceSID: "S-1-5-80-1-2-3-4-5", InstallationID: strings.Repeat("a", 32), ConfigurationSHA256: strings.Repeat("b", 64), ExecutableSHA256: strings.Repeat("c", 64)}, ReadSetup: &readSetupProgress{Consent: consent, Phase: "configured", Grants: lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: readSetupScopes()[1:]}}}
	c := lanclient.Config{SchemaVersion: lanclient.WindowsInventoryConfigVersion, CollectionProfile: consent.CollectionProfile, Profile: "tls", ManagerOrigin: "https://fixture.invalid", AgentID: "agent_" + strings.Repeat("1", 32), CertificateFile: filepath.Join(l.EnrollmentRoot, "agent-cert.pem"), PrivateKeyFile: filepath.Join(l.EnrollmentRoot, "agent-key.pem"), ServerCAFile: filepath.Join(l.EnrollmentRoot, "server-ca.pem"), StateDirectory: l.SenderRoot, InsecureHTTPAcknowledged: http}
	if http {
		c.Profile, c.ManagerOrigin, c.ServerCAFile = "http-test", "http://fixture.invalid", ""
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture key failed")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "invented local fixture"}, NotBefore: now, NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture key encoding failed")
	}
	leaf, _ := x509.ParseCertificate(der)
	r.ReadSetup.SenderBinding = setupRetentionDigest([]byte("tracebolt.sender-binding.windows.v1\n" + c.CollectionProfile + "\n" + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
	f := &retentionFixture{t: t, r: r, files: map[string]map[string][]byte{}, specs: map[string]setupRetentionSpec{}}
	for _, spec := range setupRetentionCore(r) {
		f.specs[spec.path] = spec
		f.files[spec.path] = map[string][]byte{}
		for _, name := range spec.files {
			f.files[spec.path][name] = []byte(`{"invented":"immutable"}`)
		}
	}
	enrollment := f.files[l.EnrollmentRoot]
	enrollment["agent.json"] = retentionJSON(t, c)
	enrollment["agent-cert.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	enrollment["agent-key.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	enrollment["ready.json"] = retentionJSON(t, struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated bool   `json:"serverAuthenticated"`
	}{"tracebolt.enrollment-ready.v2", setupRetentionDigest(enrollment["agent.json"]), setupRetentionDigest(der), !http})
	for i, spec := range setupRetentionGrantSpecs(r) {
		var v any
		grant := strings.Repeat(fmt.Sprint(i+1), 32)
		switch i {
		case 0:
			v = windowseventhealth.Consent{SchemaVersion: windowseventhealth.ConsentVersion, Scope: windowseventhealth.Scope, SenderBinding: r.ReadSetup.SenderBinding, GrantID: grant, Enabled: true}
		case 1:
			v = windowsvolumes.Consent{SchemaVersion: windowsvolumes.ConsentVersion, Scope: windowsvolumes.Scope, SenderBinding: r.ReadSetup.SenderBinding, GrantID: grant, Enabled: true}
		case 2:
			v = windowsprocessmetrics.Consent{SchemaVersion: windowsprocessmetrics.ConsentVersion, Scope: windowsprocessmetrics.Scope, SenderBinding: r.ReadSetup.SenderBinding, GrantID: grant, Enabled: true}
		case 3:
			v = windowsnetwork.Consent{SchemaVersion: windowsnetwork.ConsentVersion, Scope: windowsnetwork.Scope, SenderBinding: r.ReadSetup.SenderBinding, GrantID: grant, Enabled: true}
		}
		raw := retentionJSON(t, v)
		r.ReadSetup.GrantDigests = append(r.ReadSetup.GrantDigests, lanclient.WindowsCapabilityGrantDigest{Scope: readSetupScopes()[i+1], SHA256: setupRetentionDigest(raw)})
		f.specs[spec.path], f.files[spec.path] = spec, map[string][]byte{"consent.json": raw}
	}
	f.r = r
	f.files[l.StateRoot+"-installer"]["receipt.json"] = retentionJSON(t, r)
	spec := setupRetentionSpec{label: "sender", path: l.SenderRoot, options: windowsagentconfig.Sender(r.Service.ServiceSID, false), files: []string{"state.json"}}
	f.specs[spec.path], f.files[spec.path] = spec, map[string][]byte{"state.json": retentionSenderRaw(r.ReadSetup.SenderBinding, 9, nil)}
	return f
}
func retentionSenderRaw(binding string, seq uint64, body []byte) []byte {
	pending := "null"
	if body != nil {
		p, _ := json.Marshal(struct {
			Sequence uint64 `json:"sequence"`
			Digest   string `json:"digest"`
			Body     []byte `json:"body"`
		}{seq, setupRetentionDigest(body), body})
		pending = string(p)
	}
	return []byte(fmt.Sprintf(`{"version":1,"binding":%q,"lastSequence":%d,"pending":%s}`, binding, seq, pending))
}
func (f *retentionFixture) stage(s string) { f.stages = append(f.stages, s) }
func (f *retentionFixture) inspect(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
	f.inspectCalls++
	if r != f.r.Service {
		return windowsservice.Snapshot{}, errRetentionFixture
	}
	return windowsservice.Snapshot{Exists: true, ServiceSID: r.ServiceSID, State: windowsservice.Running}, nil
}
func (f *retentionFixture) material(path string) error {
	f.materialCalls++
	if path != filepath.Join(f.r.Service.Layout.EnrollmentRoot, "agent.json") || f.openHandles != 0 {
		return errRetentionFixture
	}
	return nil
}
func (f *retentionFixture) open(path string, opts windowsstate.Options) (setupRetentionStore, error) {
	spec, ok := f.specs[path]
	if !ok || opts.Create || !reflect.DeepEqual(opts, spec.options) {
		f.t.Fatal("retention changed protected schema, SID or path")
	}
	if !f.stopped && (spec.label == "sender" || strings.HasSuffix(spec.label, "grant")) {
		f.activeOpens++
		return nil, errRetentionFixture
	}
	if f.faultPath == path && f.fault == "open" {
		return nil, errRetentionFixture
	}
	f.openHandles++
	return &retentionStoreFixture{f: f, spec: spec}, nil
}

type retentionStoreFixture struct {
	f      *retentionFixture
	spec   setupRetentionSpec
	closed bool
}

func (s *retentionStoreFixture) fault(kind string) bool {
	return s.f.faultPath == s.spec.path && s.f.fault == kind
}
func (s *retentionStoreFixture) Entries() ([]string, error) {
	if s.fault("entries") {
		return nil, errRetentionFixture
	}
	var entries []string
	for name := range s.f.files[s.spec.path] {
		entries = append(entries, name)
	}
	entries = append(entries, s.spec.children...)
	slices.Sort(entries)
	return entries, nil
}
func (s *retentionStoreFixture) Read(name string) ([]byte, error) {
	if s.fault("read") {
		partial := []byte("partial private bytes")
		s.f.reads = append(s.f.reads, partial)
		return partial, errRetentionFixture
	}
	raw, ok := s.f.files[s.spec.path][name]
	if !ok {
		return nil, os.ErrNotExist
	}
	copy := bytes.Clone(raw)
	s.f.reads = append(s.f.reads, copy)
	return copy, nil
}
func (s *retentionStoreFixture) Verify() error {
	if s.fault("verify") {
		return errRetentionFixture
	}
	return nil
}
func (s *retentionStoreFixture) Close() error {
	if s.closed {
		s.f.t.Fatal("protected store closed more than once")
	}
	s.closed = true
	s.f.openHandles--
	if s.fault("close") {
		return errRetentionFixture
	}
	return nil
}
func (f *retentionFixture) capture() (setupRetainedState, error) {
	return captureSetupRetainedState(context.Background(), f.r, f.r.Service.Layout, f.open, f.inspect, f.material, f.stage)
}
func (f *retentionFixture) assertReleased(t *testing.T) {
	t.Helper()
	if f.openHandles != 0 || f.activeOpens != 0 {
		t.Fatal("retention leaked handles or opened running sender/grant stores")
	}
	for _, raw := range f.reads {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("retention retained raw store contents")
		}
	}
}

func TestSetupRetentionTLSAndHTTPPreserveOriginalBindingWithoutLiveSIDAfterStop(t *testing.T) {
	for _, http := range []bool{false, true} {
		t.Run(fmt.Sprint(http), func(t *testing.T) {
			f := newRetentionFixture(t, http)
			o, err := f.capture()
			if err != nil {
				t.Fatal("baseline rejected")
			}
			f.assertReleased(t)
			if f.materialCalls != 1 || f.inspectCalls != 1 {
				t.Fatal("active owned/material proof skipped")
			}
			// The running sender can advance before Stop. Immutable capture never read
			// or hashed this mutable ledger; actual accepted sequence is the floor.
			f.files[f.r.Service.Layout.SenderRoot]["state.json"] = retentionSenderRaw(f.r.ReadSetup.SenderBinding, 13, []byte(`{"invented":"pending"}`))
			f.stopped = true
			if o.captureStopped(context.Background(), 11, f.open, f.stage) != nil {
				t.Fatal("valid sender progress rejected")
			}
			if o.verifyAbsent(context.Background(), 11, f.open, f.stage) != nil {
				t.Fatal("same retained state rejected without a live service")
			}
			if f.materialCalls != 1 || f.inspectCalls != 1 {
				t.Fatal("stopped/absent verification resolved the deleted service")
			}
			f.assertReleased(t)
		})
	}
}
func TestSetupRetentionBaselineRejectsOwnedMaterialAndExactReceiptFailures(t *testing.T) {
	for _, name := range []string{"owned", "absent", "foreign-sid", "pending", "material", "changed-material", "layout", "receipt", "incomplete", "nil-reader", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newRetentionFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inspect, material, open, layout := f.inspect, f.material, setupRetentionOpen(f.open), f.r.Service.Layout
			switch name {
			case "owned":
				inspect = func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
					return windowsservice.Snapshot{}, errRetentionFixture
				}
			case "absent", "foreign-sid", "pending":
				inspect = func(ctx context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
					s, _ := f.inspect(ctx, r)
					if name == "absent" {
						s.Exists = false
					}
					if name == "foreign-sid" {
						s.ServiceSID = "foreign"
					}
					if name == "pending" {
						s.State = windowsservice.StopPending
					}
					return s, nil
				}
			case "material":
				material = func(string) error { return errRetentionFixture }
			case "changed-material":
				material = func(string) error {
					f.files[layout.StateRoot]["bootstrap.json"] = []byte(`{"changed":true}`)
					return nil
				}
			case "layout":
				layout.StateRoot += "-foreign"
			case "receipt":
				f.files[layout.StateRoot+"-installer"]["receipt.json"] = []byte(`{}`)
			case "incomplete":
				f.r.ReadSetup.Phase = "grants-verified"
			case "nil-reader":
				open = nil
			case "cancelled":
				cancel()
			}
			o, err := captureSetupRetainedState(ctx, f.r, layout, open, inspect, material, f.stage)
			if err != setupgate.ErrGuard || o.immutable != nil {
				t.Fatal("invalid baseline escaped")
			}
			f.assertReleased(t)
		})
	}
}
func TestSetupRetentionProtectedStoresFailClosedAtEveryBoundary(t *testing.T) {
	for _, phase := range []string{"baseline", "stopped", "absent"} {
		for _, label := range []string{"receipt", "runtime", "enrollment", "event-grant", "volume-grant", "process-grant", "network-grant", "sender"} {
			if phase == "baseline" && (label == "sender" || strings.HasSuffix(label, "grant")) {
				continue
			}
			for _, fault := range []string{"open", "entries", "read", "verify", "close"} {
				t.Run(phase+"/"+label+"/"+fault, func(t *testing.T) {
					f := newRetentionFixture(t, true)
					var o setupRetainedState
					if phase != "baseline" {
						var err error
						o, err = f.capture()
						if err != nil {
							t.Fatal("fixture baseline failed")
						}
						f.stopped = true
					}
					if phase == "absent" && o.captureStopped(context.Background(), 9, f.open, f.stage) != nil {
						t.Fatal("fixture stopped capture failed")
					}
					for path, spec := range f.specs {
						if spec.label == label {
							f.faultPath = path
						}
					}
					f.fault = fault
					var err error
					switch phase {
					case "baseline":
						_, err = f.capture()
					case "stopped":
						err = o.captureStopped(context.Background(), 9, f.open, f.stage)
					case "absent":
						err = o.verifyAbsent(context.Background(), 9, f.open, f.stage)
					}
					if err != setupgate.ErrGuard {
						t.Fatal("protected-store failure accepted or raw error escaped")
					}
					f.assertReleased(t)
				})
			}
		}
	}
}
func TestSetupRetentionImmutableBytesAndRequiredEntriesCannotDisappearOrChange(t *testing.T) {
	for _, phase := range []string{"stopped", "absent"} {
		for _, kind := range []string{"changed", "missing", "extra", "empty", "oversized"} {
			for _, label := range []string{"receipt", "runtime", "enrollment", "event-grant", "volume-grant", "process-grant", "network-grant"} {
				t.Run(phase+"/"+kind+"/"+label, func(t *testing.T) {
					f := newRetentionFixture(t, false)
					o, err := f.capture()
					if err != nil {
						t.Fatal("fixture baseline failed")
					}
					f.stopped = true
					if phase == "absent" && o.captureStopped(context.Background(), 9, f.open, f.stage) != nil {
						t.Fatal("fixture stopped failed")
					}
					var spec setupRetentionSpec
					for _, s := range f.specs {
						if s.label == label {
							spec = s
						}
					}
					name := spec.files[0]
					switch kind {
					case "changed":
						f.files[spec.path][name] = []byte(`{"changed":true}`)
					case "missing":
						delete(f.files[spec.path], name)
					case "extra":
						f.files[spec.path]["foreign.json"] = []byte(`{}`)
					case "empty":
						f.files[spec.path][name] = nil
					case "oversized":
						f.files[spec.path][name] = bytes.Repeat([]byte{'a'}, int(spec.options.MaxBytes)+1)
					}
					if phase == "stopped" {
						err = o.captureStopped(context.Background(), 9, f.open, f.stage)
					} else {
						err = o.verifyAbsent(context.Background(), 9, f.open, f.stage)
					}
					if err != setupgate.ErrGuard {
						t.Fatal("changed/missing/unbounded retained object accepted")
					}
					f.assertReleased(t)
				})
			}
		}
	}
}
func TestSetupRetentionCanonicalSenderRejectsMalformedForeignRollbackAndPendingTampering(t *testing.T) {
	binding := strings.Repeat("a", 64)
	good := retentionSenderRaw(binding, 9, []byte(`{"fixture":true}`))
	if !setupRetentionSender(good, binding, 9) || !setupRetentionSender(retentionSenderRaw(binding, 12, nil), binding, 9) {
		t.Fatal("valid canonical sender rejected")
	}
	cases := map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte{'x'}, lanclientstate.MaxStateBytes+1),
		"foreign": retentionSenderRaw(strings.Repeat("b", 64), 9, nil), "reset": retentionSenderRaw(binding, 0, nil), "rollback": retentionSenderRaw(binding, 8, nil), "overflow": retentionSenderRaw(binding, math.MaxUint64, nil),
		"trailing": append(bytes.Clone(good), []byte(`{}`)...), "unknown": bytes.Replace(good, []byte(`"version":1`), []byte(`"version":1,"unknown":1`), 1),
		"duplicate": bytes.Replace(good, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), "alias": bytes.Replace(good, []byte(`"version"`), []byte(`"Version"`), 1),
		"missing": bytes.Replace(good, []byte(`"version":1,`), nil, 1), "null-scalar": bytes.Replace(good, []byte(`"version":1`), []byte(`"version":null`), 1), "wrong-version": bytes.Replace(good, []byte(`"version":1`), []byte(`"version":2`), 1),
		"wrong-pending-sequence": bytes.Replace(good, []byte(`"sequence":9`), []byte(`"sequence":8`), 1), "null-pending-sequence": bytes.Replace(good, []byte(`"sequence":9`), []byte(`"sequence":null`), 1),
		"pending-digest": bytes.Replace(good, []byte(setupRetentionDigest([]byte(`{"fixture":true}`))), []byte(strings.Repeat("0", 64)), 1),
		"non-json-body":  retentionSenderRaw(binding, 9, []byte("private non-json bytes")), "empty-body": retentionSenderRaw(binding, 9, []byte{}), "oversized-body": retentionSenderRaw(binding, 9, []byte(`"`+strings.Repeat("x", lanclientstate.MaxBodyBytes)+`"`)),
		"noncanonical-base64": bytes.Replace(good, []byte(base64.StdEncoding.EncodeToString([]byte(`{"fixture":true}`))), []byte(base64.StdEncoding.EncodeToString([]byte(`{"fixture":true}`))+`\n`), 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if setupRetentionSender(raw, binding, 9) {
				t.Fatal("invalid sender accepted")
			}
		})
	}
	for _, floor := range []uint64{0, math.MaxUint64, 10} {
		if setupRetentionSender(good, binding, floor) {
			t.Fatal("invalid floor accepted")
		}
	}
}
func TestSetupRetentionStoppedSenderCannotMutateEvenWithValidNewSequence(t *testing.T) {
	for _, kind := range []string{"reset", "replacement-binding", "advance", "same-sequence-body", "ack-clear"} {
		t.Run(kind, func(t *testing.T) {
			f := newRetentionFixture(t, true)
			o, err := f.capture()
			if err != nil {
				t.Fatal("fixture baseline failed")
			}
			f.stopped = true
			path, binding := f.r.Service.Layout.SenderRoot, f.r.ReadSetup.SenderBinding
			f.files[path]["state.json"] = retentionSenderRaw(binding, 9, []byte(`{"old":true}`))
			if o.captureStopped(context.Background(), 9, f.open, f.stage) != nil {
				t.Fatal("fixture stopped capture failed")
			}
			switch kind {
			case "reset":
				f.files[path]["state.json"] = retentionSenderRaw(binding, 0, nil)
			case "replacement-binding":
				f.files[path]["state.json"] = retentionSenderRaw(strings.Repeat("b", 64), 9, nil)
			case "advance":
				f.files[path]["state.json"] = retentionSenderRaw(binding, 10, nil)
			case "same-sequence-body":
				f.files[path]["state.json"] = retentionSenderRaw(binding, 9, []byte(`{"new":true}`))
			case "ack-clear":
				f.files[path]["state.json"] = retentionSenderRaw(binding, 9, nil)
			}
			if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard {
				t.Fatal("quiescent sender mutation accepted")
			}
			f.assertReleased(t)
		})
	}
}
func TestSetupRetentionRequiresStoppedCaptureAndOriginalCopiedReceipt(t *testing.T) {
	f := newRetentionFixture(t, true)
	o, err := f.capture()
	if err != nil {
		t.Fatal("fixture baseline failed")
	}
	if o.verifyAbsent(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard {
		t.Fatal("absence bypassed stopped proof")
	}
	f.r.ReadSetup.Consent.Scopes[0] = "foreign"
	f.r.ReadSetup.SenderBinding = strings.Repeat("0", 64)
	f.r.ReadSetup.GrantDigests[0].SHA256 = strings.Repeat("0", 64)
	f.r.Service.ServiceSID = "foreign"
	f.stopped = true
	if o.captureStopped(context.Background(), 9, f.open, f.stage) != nil || o.verifyAbsent(context.Background(), 9, f.open, f.stage) != nil {
		t.Fatal("caller mutation rebound captured proof")
	}
	if o.captureStopped(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard {
		t.Fatal("stopped baseline could be overwritten")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o.verifyAbsent(ctx, 9, f.open, f.stage) != setupgate.ErrGuard {
		t.Fatal("expired verifier succeeded")
	}
	f.assertReleased(t)
}
func TestSetupRetentionNativeOrderingDoesNotReopenRunningSenderOrResolveDeletedService(t *testing.T) {
	raw, err := os.ReadFile("setup_acceptance_native_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	capture, pending, stopped, release, absent, verify := strings.Index(source, "captureSetupRetainedState("), strings.Index(source, `r.Checks["deletePendingObserved"] = true`), strings.Index(source, "retained.captureStopped("), strings.Index(source, `r.Stage = "uninstall-release"`), strings.Index(source, `r.Checks["serviceAbsent"] = true`), strings.Index(source, "retained.verifyAbsent(")
	if capture < 0 || !(capture < pending && pending < stopped && stopped < release && release < absent && absent < verify) {
		t.Fatal("native retention ordering changed")
	}
	if strings.Contains(source, "lanclient.WindowsCapabilityIdentity(") || strings.Contains(source, "lanclient.WindowsCapabilityGrantDigests(") || !strings.Contains(source, "retained.captureStopped(ctx, f.Evidence().LastSequence,") || !strings.Contains(source, "retained.verifyAbsent(ctx, f.Evidence().LastSequence,") {
		t.Fatal("live identity lookup or frame-count floor returned")
	}
}

func TestSetupRetentionBaselineRejectsChangedIdentityReadyAndFixedPaths(t *testing.T) {
	for _, kind := range []string{"config", "certificate", "key", "ready", "ready-config-hash", "ready-certificate-hash", "ready-transport", "ready-version", "sender-binding", "config-certificate-path", "config-key-path", "config-sender-path", "config-ca-path", "config-profile", "config-scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newRetentionFixture(t, false)
			enrollment := f.files[f.r.Service.Layout.EnrollmentRoot]
			switch kind {
			case "config":
				enrollment["agent.json"] = []byte(`{}`)
			case "certificate":
				enrollment["agent-cert.pem"] = []byte("corrupt invented certificate")
			case "key":
				enrollment["agent-key.pem"] = []byte("corrupt invented key")
			case "ready":
				enrollment["ready.json"] = []byte(`{}`)
			case "ready-config-hash", "ready-certificate-hash", "ready-transport", "ready-version":
				var ready map[string]any
				_ = json.Unmarshal(enrollment["ready.json"], &ready)
				field, value := "configHash", any(strings.Repeat("0", 64))
				switch kind {
				case "ready-certificate-hash":
					field = "certificateHash"
				case "ready-transport":
					field, value = "serverAuthenticated", false
				case "ready-version":
					field, value = "version", "other"
				}
				ready[field] = value
				enrollment["ready.json"] = retentionJSON(t, ready)
			case "sender-binding":
				f.r.ReadSetup.SenderBinding = strings.Repeat("0", 64)
				f.files[f.r.Service.Layout.StateRoot+"-installer"]["receipt.json"] = retentionJSON(t, f.r)
			default:
				var c lanclient.Config
				_ = json.Unmarshal(enrollment["agent.json"], &c)
				switch kind {
				case "config-certificate-path":
					c.CertificateFile += ".foreign"
				case "config-key-path":
					c.PrivateKeyFile += ".foreign"
				case "config-sender-path":
					c.StateDirectory += ".foreign"
				case "config-ca-path":
					c.ServerCAFile += ".foreign"
				case "config-profile":
					c.Profile = "other"
				case "config-scope":
					c.CollectionProfile = "other"
				}
				enrollment["agent.json"] = retentionJSON(t, c)
				// Keep ready's config digest self-consistent; fixed path/scope binding must
				// still reject a semantically foreign handoff.
				var ready map[string]any
				_ = json.Unmarshal(enrollment["ready.json"], &ready)
				ready["configHash"] = setupRetentionDigest(enrollment["agent.json"])
				enrollment["ready.json"] = retentionJSON(t, ready)
			}
			if _, err := f.capture(); err != setupgate.ErrGuard {
				t.Fatal("changed identity/handoff accepted")
			}
			f.assertReleased(t)
		})
	}
}

func TestSetupRetentionEveryGrantRequiresCanonicalEnabledOriginalIdentityAndGrantID(t *testing.T) {
	for _, i := range []int{0, 1, 2, 3} {
		for _, kind := range []string{"disabled", "foreign-binding", "foreign-scope", "grant-id", "unknown", "duplicate", "null", "trailing"} {
			t.Run(fmt.Sprint(i)+"/"+kind, func(t *testing.T) {
				f := newRetentionFixture(t, true)
				o, err := f.capture()
				if err != nil {
					t.Fatal("fixture baseline failed")
				}
				f.stopped = true
				spec := setupRetentionGrantSpecs(f.r)[i]
				raw := f.files[spec.path]["consent.json"]
				switch kind {
				case "disabled":
					raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":false`), 1)
				case "foreign-binding":
					raw = bytes.Replace(raw, []byte(f.r.ReadSetup.SenderBinding), []byte(strings.Repeat("0", 64)), 1)
				case "foreign-scope":
					raw = bytes.Replace(raw, []byte(f.r.ReadSetup.GrantDigests[i].Scope), []byte("foreign"), 1)
				case "grant-id":
					raw = bytes.Replace(raw, []byte(strings.Repeat(fmt.Sprint(i+1), 32)), []byte(strings.Repeat("e", 32)), 1)
				case "unknown":
					raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"unknown":1`), 1)
				case "duplicate":
					raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":true`), 1)
				case "null":
					raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":null`), 1)
				case "trailing":
					raw = append(bytes.Clone(raw), []byte(`{}`)...)
				}
				f.files[spec.path]["consent.json"] = raw
				if o.captureStopped(context.Background(), 9, f.open, f.stage) != setupgate.ErrGuard {
					t.Fatal("foreign/noncanonical/disabled/replaced grant accepted")
				}
				if setupRetentionGrant(raw, f.r.ReadSetup.GrantDigests[i].Scope, f.r.ReadSetup.SenderBinding) && kind != "grant-id" {
					t.Fatal("canonical semantic grant decoder accepted malformed scope")
				}
				f.assertReleased(t)
			})
		}
	}
}

func TestSetupRetentionGuardErrorsClearBytesAndClosePopulatedOpenFailureExactlyOnce(t *testing.T) {
	f := newRetentionFixture(t, true)
	spec := setupRetentionCore(f.r)[0]
	open := func(path string, opts windowsstate.Options) (setupRetentionStore, error) {
		store, err := f.open(path, opts)
		if err != nil {
			t.Fatal("fixture store failed")
		}
		return store, errRetentionFixture
	}
	raw, err := setupRetentionRead(context.Background(), spec, open)
	if raw != nil || err != setupgate.ErrGuard {
		t.Fatal("populated failed open escaped")
	}
	f.assertReleased(t)
	ctx, cancel := context.WithCancel(context.Background())
	open = func(path string, opts windowsstate.Options) (setupRetentionStore, error) {
		store, err := f.open(path, opts)
		cancel()
		return store, err
	}
	raw, err = setupRetentionRead(ctx, spec, open)
	if raw != nil || err != setupgate.ErrGuard {
		t.Fatal("cancellation during open escaped")
	}
	f.assertReleased(t)
}

func TestSetupRetentionIdentityPreservesActiveArtifactBounds(t *testing.T) {
	for name, max := range map[string]int{"agent.json": 16384, "agent-cert.pem": 65536, "agent-key.pem": 32768, "ready.json": 4096, "server-ca.pem": 65536} {
		t.Run(name, func(t *testing.T) {
			f := newRetentionFixture(t, false)
			enrollment := f.files[f.r.Service.Layout.EnrollmentRoot]
			enrollment[name] = append(enrollment[name], bytes.Repeat([]byte{' '}, max+1-len(enrollment[name]))...)
			if setupRetentionIdentity(f.r, enrollment) != setupgate.ErrGuard {
				t.Fatal("per-artifact active validation bound widened")
			}
		})
	}
}
