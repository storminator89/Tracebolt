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
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/lantrust"
	"localrmm/internal/renewalidentity"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsvolumes"
)

var errCurrentRetentionFixture = errors.New("invented current retention failure that must not escape")

// Every artifact and credential is invented and remains in memory. Paths are
// schema identifiers only: this fixture never opens a native store, service,
// provider, network connection, or filesystem artifact. Its material callback
// substitutes for the separately required native lanclient.Load acceptance.
type currentRetentionFixture struct {
	t                                               *testing.T
	r                                               installReceipt
	files                                           map[string]map[string][]byte
	specs                                           map[string]currentRetentionSpec
	stopped                                         bool
	installerLeaseHeld                              bool
	activeOpens, blockedInstallerOpens, openHandles int
	materialCalls, inspectCalls                     int
	faultPath, fault                                string
	reads                                           [][]byte
	stages                                          []string
	opens, closes, readPaths, verifyPaths           []string
	openCounts                                      map[string]int
}

func newCurrentRetentionFixture(t *testing.T) *currentRetentionFixture {
	t.Helper()
	root := filepath.Join(os.TempDir(), "tracebolt-invented-current21-retention", "windows-agent")
	l := windowsservice.Layout{ProgramFiles: filepath.Dir(root), ProgramData: filepath.Dir(root), Executable: filepath.Join(filepath.Dir(root), "service.exe"), StateRoot: root, EnrollmentRoot: filepath.Join(root, "enrollment"), SenderRoot: filepath.Join(root, "enrollment", "telemetry")}
	consent := freshReadAdminSetupConsent(false)
	r := installReceipt{Version: 12, Prepared: true, Service: windowsservice.Receipt{Version: 1, Complete: true, Layout: l, ServiceSID: "S-1-5-80-1-2-3-4-5", InstallationID: strings.Repeat("a", 32), ConfigurationSHA256: strings.Repeat("b", 64), ExecutableSHA256: strings.Repeat("c", 64)}, ReadSetup: &readSetupProgress{Consent: consent, Phase: "configured", Grants: lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: slices.Clone(consent.Scopes[1:])}}}
	f := &currentRetentionFixture{t: t, r: r, files: map[string]map[string][]byte{}, specs: map[string]currentRetentionSpec{}, openCounts: map[string]int{}}
	for _, spec := range currentRetentionCore(r) {
		f.specs[spec.path] = spec
		f.files[spec.path] = map[string][]byte{}
		for _, name := range spec.files {
			// These opaque retained records are compared byte-for-byte. The
			// identity/config/ready/manifest records are replaced below with
			// fully validated current renewable material.
			f.files[spec.path][name] = []byte(`{"invented":"immutable"}`)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	c, leaf := f.seedIdentity(now)
	r.ReadSetup.SenderBinding = currentRetentionDigest([]byte("tracebolt.sender-binding.windows.v1\n" + c.CollectionProfile + "\n" + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
	f.r = r
	for i, spec := range currentRetentionGrantSpecs(r) {
		scope := consent.Scopes[i+1]
		var raw []byte
		if scope == windowsfullsoftware.HistoryScope {
			// The software-history grant is exactly the final software grant,
			// including its rotated grant ID/revision and HistoryScope.
			raw = f.files[spec.path]["consent.json"]
		} else {
			raw = currentRetentionConsentFixture(t, scope, r.ReadSetup.SenderBinding, fmt.Sprintf("%032x", i+1), now)
			f.specs[spec.path], f.files[spec.path] = spec, map[string][]byte{"consent.json": raw}
			f.seedGeneration(spec, c.AgentID, now)
		}
		if !currentRetentionGrant(raw, scope, r.ReadSetup.SenderBinding) {
			t.Fatal("invented current grant failed its production decoder")
		}
		r.ReadSetup.GrantDigests = append(r.ReadSetup.GrantDigests, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: currentRetentionDigest(raw)})
	}
	f.r = r
	f.files[l.StateRoot+"-installer"]["receipt.json"] = retentionJSON(t, r)
	local := windowshistoryrequest.LocalContext{SenderBinding: r.ReadSetup.SenderBinding, Profile: "tls", DeviceID: c.AgentID, CertificateHash: currentRetentionDigest(leaf.Raw)}
	reports, err := windowshistorystate.NewReports(local)
	if err != nil {
		t.Fatal("invented history reports failed")
	}
	consumption, err := windowshistorystate.NewConsumption(local)
	if err != nil {
		t.Fatal("invented history consumption failed")
	}
	for _, child := range []struct {
		dir, file, lock, temp string
		value                 any
	}{{"reports", "reports.json", "reports.lock", "reports.tmp", reports}, {"consumption", "consumed.json", "consumed.lock", "consumed.tmp", consumption}} {
		spec := currentRetentionSpec{label: "event-history/" + child.dir, path: filepath.Join(l.StateRoot+"-event-history", child.dir), options: windowsstate.Options{RuntimeSID: r.Service.ServiceSID, Names: []string{child.file}, LockName: child.lock, TempName: child.temp, MaxBytes: windowshistorystate.MaxBytes}, files: []string{child.file}}
		f.specs[spec.path], f.files[spec.path] = spec, map[string][]byte{child.file: retentionJSON(t, child.value)}
	}
	spec := currentRetentionSpec{label: "sender", path: l.SenderRoot, options: windowsagentconfig.Sender(r.Service.ServiceSID, false), files: []string{"state.json"}}
	f.specs[spec.path], f.files[spec.path] = spec, map[string][]byte{"state.json": currentRetentionSenderRaw(r.ReadSetup.SenderBinding, 9, nil)}
	if !completeCurrentReadSetup(r) || currentRetentionIdentity(r, f.files[l.EnrollmentRoot]) != nil || !currentRetentionSender(f.files[l.SenderRoot]["state.json"], r.ReadSetup.SenderBinding, 9) {
		t.Fatal("invented current retention fixture failed its current contract")
	}
	t.Cleanup(func() {
		for _, files := range f.files {
			currentRetentionClear(files)
		}
		for _, raw := range f.reads {
			clear(raw)
		}
	})
	return f
}

// Match the production enrollmentcrypto/renewalidentity verification contract,
// including a client-auth intermediate, immutable issuance intent, original
// anchor and generation-one manifest. No private fixture key is written out.
func (f *currentRetentionFixture) seedIdentity(now time.Time) (lanclient.Config, *x509.Certificate) {
	t := f.t
	t.Helper()
	keypair := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("invented key generation failed")
		}
		return pub, key
	}
	create := func(template, parent *x509.Certificate, public ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
		if err != nil {
			t.Fatal("invented certificate generation failed")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal("invented certificate parsing failed")
		}
		return cert
	}
	rp, rk := keypair()
	defer clear(rk)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "invented retention root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign}
	root := create(rt, rt, rp, rk)
	ip, ik := keypair()
	defer clear(ik)
	issuer := create(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "invented retention issuer"}, NotBefore: rt.NotBefore, NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, root, ip, rk)
	public, key := keypair()
	defer clear(key)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("invented public key encoding failed")
	}
	id := func(prefix, digit string) string { return prefix + strings.Repeat(digit, 32) }
	a := enrollmentcrypto.Intent{ManagerInstanceID: id("manager_", "1"), Profile: "tls", Origin: "https://fixture.invalid:8443", CollectionProfile: f.r.ReadSetup.Consent.CollectionProfile, InvitationID: id("invite_", "2"), ClaimID: id("claim_", "3"), RequestID: id("request_", "4"), DeviceID: id("agent_", "5"), IntentID: id("intent_", "6"), KeyFingerprint: currentRetentionDigest(publicDER), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(publicDER), CSRHash: strings.Repeat("7", 64), ClaimHash: strings.Repeat("8", 64), IssuerFingerprint: currentRetentionDigest(issuer.Raw), SerialHex: strings.Repeat("9", 32), TemplateVersion: enrollmentcrypto.TemplateVersion, KeyGeneration: 1, NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	serial, _ := new(big.Int).SetString(a.SerialHex, 16)
	leaf := create(&x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: a.DeviceID}, NotBefore: time.Unix(a.NotBefore, 0), NotAfter: time.Unix(a.NotAfter, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, issuer, public, ik)
	identity, err := enrollmentcrypto.RenewalIdentityGeneration(a)
	if err != nil {
		t.Fatal("invented renewable identity failed")
	}
	manifest := renewalidentity.Manifest{Version: renewalidentity.Version, ManagerInstanceID: a.ManagerInstanceID, EnrollmentOrigin: a.Origin, AgentOrigin: "https://fixture.invalid", CollectionProfile: a.CollectionProfile, DeviceID: a.DeviceID, IdentityGeneration: identity, KeyFingerprint: a.KeyFingerprint, AnchorHash: currentRetentionDigest(leaf.Raw), IssuerFingerprint: a.IssuerFingerprint, AuthorityExpiresAt: issuer.NotAfter.Unix(), CredentialGeneration: 1, Revision: 1, CertificateDER: leaf.Raw, AnchorIntent: a, Intent: a, LastServerNow: now.Unix() - 10}
	if _, err := manifest.Validate(leaf, issuer, manifest.AgentOrigin, a.CollectionProfile, a.DeviceID, now); err != nil {
		t.Fatal("invented renewal manifest failed verification")
	}
	l := f.r.Service.Layout
	c := lanclient.Config{SchemaVersion: lanclient.WindowsRenewalConfigVersion, CollectionProfile: a.CollectionProfile, Profile: "tls", ManagerOrigin: manifest.AgentOrigin, AgentID: a.DeviceID, CertificateFile: filepath.Join(l.EnrollmentRoot, "agent-cert.pem"), PrivateKeyFile: filepath.Join(l.EnrollmentRoot, "agent-key.pem"), ServerCAFile: filepath.Join(l.EnrollmentRoot, "server-ca.pem"), StateDirectory: l.SenderRoot, RenewalManifestFile: filepath.Join(l.EnrollmentRoot, renewalidentity.ManifestName)}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("invented private key encoding failed")
	}
	defer clear(privateDER)
	e := f.files[l.EnrollmentRoot]
	e["agent.json"] = retentionJSON(t, c)
	e["agent-cert.pem"] = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	e["agent-key.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	e["server-ca.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	e[renewalidentity.ManifestName] = retentionJSON(t, manifest)
	e["ready.json"] = retentionJSON(t, struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated bool   `json:"serverAuthenticated"`
	}{"tracebolt.enrollment-ready.v2", currentRetentionDigest(e["agent.json"]), currentRetentionDigest(leaf.Raw), true})
	return c, leaf
}

func currentRetentionConsentFixture(t *testing.T, scope, binding, grant string, at time.Time) []byte {
	t.Helper()
	versions := map[string]string{
		windowseventhealth.Scope:           windowseventhealth.ConsentVersion,
		windowsvolumes.Scope:               windowsvolumes.ConsentVersion,
		windowsprocessmetrics.Scope:        windowsprocessmetrics.ConsentVersion,
		windowsnetwork.Scope:               windowsnetwork.ConsentVersion,
		windowsmanaged.ServiceStartupScope: windowsmanaged.ServiceStartupConsentVersion,
		windowsadapters.Scope:              windowsadapters.ConsentVersion,
		windowspatchcontext.Scope:          windowspatchcontext.ConsentVersion,
		windowssecurity.Scope:              windowssecurity.ConsentVersion,
		windowssessions.Scope:              windowssessions.ConsentVersion,
		windowshardware.Scope:              windowshardware.ConsentVersion,
		windowsstorage.Scope:               windowsstorage.ConsentVersion,
		windowssecuritycoverage.Scope:      windowssecuritycoverage.ConsentVersion,
		windowsresourcecontext.Scope:       windowsresourcecontext.ConsentVersion,
		windowsstorageio.Scope:             windowsstorageio.ConsentVersion,
	}
	if version, ok := versions[scope]; ok {
		// All these exact codecs have the same canonical five-field shape;
		// each byte record is checked with its own decoder by the caller.
		return retentionJSON(t, windowseventhealth.Consent{SchemaVersion: version, Scope: scope, SenderBinding: binding, GrantID: grant, Enabled: true})
	}
	switch scope {
	case windowsfullservices.Scope:
		return retentionJSON(t, windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at})
	case windowsfullsoftware.Scope:
		return retentionJSON(t, windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: scope, SenderBinding: binding, GrantID: grant, Revision: 2, Enabled: true, ChangedAt: at, HistoryScope: windowsfullsoftware.HistoryScope})
	case windowsfullprocesses.Scope:
		return retentionJSON(t, windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at})
	case windowsnetworkcontext.Scope:
		return retentionJSON(t, windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: scope, SenderBinding: binding, GrantID: grant, Revision: 1, Enabled: true, ChangedAt: at})
	case windowshistoryrequest.Scope:
		return retentionJSON(t, windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: scope, SenderBinding: binding, GrantID: grant, Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true})
	default:
		t.Fatal("unrecognized invented current grant scope")
		return nil
	}
}

// This adapter is construction-only; retention's read-only handles below have
// no Write method. Production state constructors supply valid retained packs
// and independent consumed floors without any provider capture.
type currentRetentionSeedStore map[string][]byte

func (s currentRetentionSeedStore) Read(name string) ([]byte, error) {
	raw, ok := s[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s currentRetentionSeedStore) Write(name string, raw []byte) error {
	s[name] = bytes.Clone(raw)
	return nil
}
func (s currentRetentionSeedStore) Close() error { return nil }

func (f *currentRetentionFixture) seedGeneration(spec currentRetentionSpec, device string, now time.Time) {
	f.t.Helper()
	s := currentRetentionSeedStore(f.files[spec.path])
	binding := f.r.ReadSetup.SenderBinding
	var err error
	switch spec.label {
	case "full-services":
		var c windowsfullservices.Consent
		c, err = windowsfullservices.DecodeConsent(s["consent.json"])
		if err == nil {
			err = windowsfullservices.InitializeState(s, device, binding)
		}
		if err == nil {
			var state *windowsfullservices.State
			state, err = windowsfullservices.OpenState(s, device, binding)
			if err == nil {
				_, err = state.Reserve(c, now)
			}
		}
	case "full-software":
		var c windowsfullsoftware.Consent
		c, err = windowsfullsoftware.DecodeConsent(s["consent.json"])
		if err == nil {
			err = windowsfullsoftware.InitializeState(s, device, binding)
		}
		if err == nil {
			var state *windowsfullsoftware.State
			state, err = windowsfullsoftware.OpenState(s, device, binding)
			if err == nil {
				_, err = state.Reserve(c, now)
			}
		}
	case "full-processes":
		var c windowsfullprocesses.Consent
		c, err = windowsfullprocesses.DecodeConsent(s["consent.json"])
		if err == nil {
			err = windowsfullprocesses.InitializeState(s, device, binding)
		}
		if err == nil {
			var state *windowsfullprocesses.State
			state, err = windowsfullprocesses.OpenState(s, device, binding)
			if err == nil {
				_, err = state.Reserve(c, now)
			}
		}
	case "network-context":
		var c windowsnetworkcontext.Consent
		c, err = windowsnetworkcontext.DecodeConsent(s["consent.json"])
		if err == nil {
			err = windowsnetworkcontext.InitializeState(s, device, binding)
		}
		if err == nil {
			var state *windowsnetworkcontext.State
			state, err = windowsnetworkcontext.OpenState(s, device, binding)
			if err == nil {
				_, err = state.Reserve(c, now)
			}
		}
	}
	if err != nil {
		f.t.Fatal("invented generation state failed")
	}
}

func currentRetentionSenderRaw(binding string, seq uint64, body []byte) []byte {
	pending := "null"
	if body != nil {
		p, _ := json.Marshal(struct {
			Sequence uint64 `json:"sequence"`
			Digest   string `json:"digest"`
			Body     []byte `json:"body"`
		}{seq, currentRetentionDigest(body), body})
		pending = string(p)
		clear(p)
	}
	return []byte(fmt.Sprintf(`{"windowsNetworkContextUsed":true,"windowsFullProcessesUsed":true,"windowsFullSoftwareUsed":true,"windowsFullServicesUsed":true,"version":5,"binding":%q,"lastSequence":%d,"pending":%s}`, binding, seq, pending))
}

func (f *currentRetentionFixture) stage(s string) { f.stages = append(f.stages, s) }
func (f *currentRetentionFixture) inspect(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
	f.inspectCalls++
	if r != f.r.Service || f.fault == "inspect" {
		return windowsservice.Snapshot{}, errCurrentRetentionFixture
	}
	state := windowsservice.Running
	if f.stopped {
		state = windowsservice.Stopped
	}
	return windowsservice.Snapshot{Exists: true, ServiceSID: r.ServiceSID, State: state}, nil
}
func (f *currentRetentionFixture) material(path string) error {
	f.materialCalls++
	if path != filepath.Join(f.r.Service.Layout.EnrollmentRoot, "agent.json") || f.openHandles != 0 || f.fault == "material" {
		return errCurrentRetentionFixture
	}
	return currentRetentionIdentity(f.r, f.files[f.r.Service.Layout.EnrollmentRoot])
}
func (f *currentRetentionFixture) open(path string, opts windowsstate.Options) (currentRetentionStore, error) {
	f.opens = append(f.opens, path)
	f.openCounts[path]++
	spec, ok := f.specs[path]
	if !ok || opts.Create || !reflect.DeepEqual(opts, spec.options) {
		f.t.Fatal("current retention changed protected schema, SID or path")
	}
	if spec.label == "receipt" && f.installerLeaseHeld {
		f.blockedInstallerOpens++
		return nil, errCurrentRetentionFixture
	}
	if !f.stopped && spec.label != "receipt" && spec.label != "runtime" && spec.label != "enrollment" {
		f.activeOpens++
		return nil, errCurrentRetentionFixture
	}
	if f.faultPath == path && f.fault == "open" {
		return nil, errCurrentRetentionFixture
	}
	f.openHandles++
	h := &currentRetentionStoreFixture{f: f, spec: spec}
	if f.faultPath == path && f.fault == "open-with-handle" {
		return h, errCurrentRetentionFixture
	}
	return h, nil
}

type currentRetentionStoreFixture struct {
	f      *currentRetentionFixture
	spec   currentRetentionSpec
	closed bool
}

func (s *currentRetentionStoreFixture) fault(kind string) bool {
	return s.f.faultPath == s.spec.path && s.f.fault == kind
}
func (s *currentRetentionStoreFixture) checkOpen() {
	if s.closed {
		s.f.t.Fatal("current retained store used after close")
	}
}
func (s *currentRetentionStoreFixture) Entries() ([]string, error) {
	s.checkOpen()
	if s.fault("entries") {
		return nil, errCurrentRetentionFixture
	}
	entries := slices.Clone(s.spec.children)
	for name := range s.f.files[s.spec.path] {
		entries = append(entries, name)
	}
	slices.Sort(entries)
	return entries, nil
}
func (s *currentRetentionStoreFixture) Read(name string) ([]byte, error) {
	s.checkOpen()
	s.f.readPaths = append(s.f.readPaths, filepath.Join(s.spec.path, name))
	if s.fault("read") {
		partial := []byte("invented partial private bytes")
		s.f.reads = append(s.f.reads, partial)
		return partial, errCurrentRetentionFixture
	}
	raw, ok := s.f.files[s.spec.path][name]
	if !ok {
		return nil, os.ErrNotExist
	}
	copy := bytes.Clone(raw)
	s.f.reads = append(s.f.reads, copy)
	return copy, nil
}
func (s *currentRetentionStoreFixture) Verify() error {
	s.checkOpen()
	s.f.verifyPaths = append(s.f.verifyPaths, s.spec.path)
	if s.fault("verify") {
		return errCurrentRetentionFixture
	}
	return nil
}
func (s *currentRetentionStoreFixture) Close() error {
	if s.closed {
		s.f.t.Fatal("current protected store closed more than once")
	}
	s.closed = true
	s.f.openHandles--
	s.f.closes = append(s.f.closes, s.spec.path)
	if s.fault("close") {
		return errCurrentRetentionFixture
	}
	return nil
}
func (f *currentRetentionFixture) capture() (currentRetainedState, error) {
	return captureCurrentRetainedState(context.Background(), f.r, f.r.Service.Layout, f.open, f.inspect, f.material, f.stage)
}
func (f *currentRetentionFixture) assertReleased(t *testing.T) {
	t.Helper()
	if f.openHandles != 0 || f.activeOpens != 0 {
		t.Fatal("current retention leaked handles or opened active sender/grant stores")
	}
	for _, raw := range f.reads {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("current retention retained raw store contents")
		}
	}
}
