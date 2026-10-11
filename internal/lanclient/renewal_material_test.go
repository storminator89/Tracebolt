//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalview"
	"localrmm/internal/lantrust"
	"localrmm/internal/renewalidentity"
	"localrmm/internal/socketowner"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsstate"
)

type renewalMaterialFixture struct {
	config           Config
	configPath       string
	anchor, issuer   *x509.Certificate
	key              ed25519.PrivateKey
	rootPEM          []byte
	initial, renewed renewalidentity.Manifest
}

func renewalFixtureHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// All credentials are ephemeral fixture material. No host identity, source,
// native provider, network connection or installed service is used.
func newRenewalMaterialFixture(t *testing.T, collection string, expiredAnchor bool) renewalMaterialFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	create := func(template, parent *x509.Certificate, public ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral renewal root"}, NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign}
	root := create(rt, rt, rp, rk)
	ip, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := create(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ephemeral renewal issuer"}, NotBefore: rt.NotBefore, NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, root, ip, rk)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix string, n string) string { return prefix + strings.Repeat(n, 32) }
	a := enrollmentcrypto.Intent{ManagerInstanceID: id("manager_", "1"), Profile: "tls", Origin: "https://fixture.invalid:8443", CollectionProfile: collection, InvitationID: id("invite_", "2"), ClaimID: id("claim_", "3"), RequestID: id("request_", "4"), DeviceID: id("agent_", "5"), IntentID: id("intent_", "6"), KeyFingerprint: renewalFixtureHash(publicDER), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(publicDER), CSRHash: strings.Repeat("7", 64), ClaimHash: strings.Repeat("8", 64), IssuerFingerprint: renewalFixtureHash(issuer.Raw), SerialHex: strings.Repeat("9", 32), TemplateVersion: enrollmentcrypto.TemplateVersion, KeyGeneration: 1, NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()}
	if expiredAnchor {
		a.NotBefore = now.Add(-8 * 24 * time.Hour).Unix()
		a.NotAfter = now.Add(-24 * time.Hour).Unix()
	}
	issue := func(i enrollmentcrypto.Intent) *x509.Certificate {
		serial, _ := new(big.Int).SetString(i.SerialHex, 16)
		return create(&x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: i.DeviceID}, NotBefore: time.Unix(i.NotBefore, 0), NotAfter: time.Unix(i.NotAfter, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, issuer, public, ik)
	}
	anchor := issue(a)
	currentIntent := a
	currentIntent.IntentID = id("intent_", "a")
	currentIntent.RequestID = id("request_", "b")
	currentIntent.SerialHex = strings.Repeat("c", 32)
	currentIntent.NotBefore = now.Add(-time.Minute).Unix()
	currentIntent.NotAfter = now.Add(7*24*time.Hour - time.Minute).Unix()
	current := issue(currentIntent)
	identity, identityErr := enrollmentcrypto.RenewalIdentityGeneration(a)
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	manifest := renewalidentity.Manifest{Version: renewalidentity.Version, ManagerInstanceID: a.ManagerInstanceID, EnrollmentOrigin: a.Origin, AgentOrigin: "https://fixture.invalid", CollectionProfile: collection, DeviceID: a.DeviceID, IdentityGeneration: identity, KeyFingerprint: a.KeyFingerprint, AnchorHash: renewalFixtureHash(anchor.Raw), IssuerFingerprint: a.IssuerFingerprint, AuthorityExpiresAt: issuer.NotAfter.Unix(), CredentialGeneration: 1, Revision: 1, CertificateDER: anchor.Raw, AnchorIntent: a, Intent: a, LastServerNow: now.Unix() - 10}
	renewed := manifest
	renewed.CertificateDER = current.Raw
	renewed.Intent = currentIntent
	renewed.CredentialGeneration = 2
	renewed.Revision = 2
	dir := t.TempDir()
	c := Config{SchemaVersion: RenewalConfigVersion, CollectionProfile: collection, Profile: "tls", ManagerOrigin: manifest.AgentOrigin, AgentID: a.DeviceID, CertificateFile: filepath.Join(dir, "agent-cert.pem"), PrivateKeyFile: filepath.Join(dir, "agent-key.pem"), ServerCAFile: filepath.Join(dir, "server-ca.pem"), StateDirectory: filepath.Join(dir, "telemetry"), RenewalManifestFile: filepath.Join(dir, renewalidentity.ManifestName)}
	if collection == enrollmentcrypto.CollectionProfileWindowsInventory {
		c.SchemaVersion = WindowsRenewalConfigVersion
	}
	f := renewalMaterialFixture{config: c, configPath: filepath.Join(dir, "agent.json"), anchor: anchor, issuer: issuer, key: key, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), initial: manifest, renewed: renewed}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	configRaw, _ := json.Marshal(c)
	readyRaw, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": renewalFixtureHash(configRaw), "certificateHash": manifest.AnchorHash, "serverAuthenticated": true})
	for path, raw := range map[string][]byte{c.CertificateFile: certPEM, c.PrivateKeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), c.ServerCAFile: f.rootPEM, f.configPath: configRaw, filepath.Join(dir, "ready.json"): readyRaw} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.write(t, manifest)
	return f
}
func (f renewalMaterialFixture) write(t *testing.T, m renewalidentity.Manifest) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.config.RenewalManifestFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func (f renewalMaterialFixture) material(t *testing.T, m renewalidentity.Manifest) Material {
	t.Helper()
	current, err := m.Validate(f.anchor, f.issuer, f.config.ManagerOrigin, f.config.CollectionProfile, f.config.AgentID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{current.Raw, f.issuer.Raw}, PrivateKey: f.key, Leaf: current}
	cfg, err := lantrust.ClientTLSConfig(pair, f.rootPEM, "fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	sum := senderBinding(f.config, f.anchor)
	out := Material{config: f.config, configPath: f.configPath, certificate: pair, authorityCertificate: bytes.Clone(f.anchor.Raw), renewal: &m, tlsConfig: cfg, binding: hex.EncodeToString(sum[:]), loaded: true}
	if !out.valid() {
		t.Fatal("fixture material invalid")
	}
	return out
}

func TestRenewalMaterialLoadsCurrentLeafAfterAnchorExpiry(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, true)
	if _, err := Load(f.configPath); err == nil {
		t.Fatal("expired generation one accepted")
	}
	f.write(t, f.renewed)
	m, err := Load(f.configPath)
	if err != nil || !m.valid() {
		t.Fatal("renewed current leaf rejected", err)
	}
	if !bytes.Equal(m.certificate.Certificate[0], f.renewed.CertificateDER) || journalLeaf(m) != f.initial.AnchorHash || m.CertificateExpiry().Unix() != f.renewed.Intent.NotAfter {
		t.Fatal("current credential and historical identity conflated")
	}
	if dir, ok := m.RenewalStateDirectory(); !ok || dir != filepath.Dir(f.configPath) {
		t.Fatal("renewal directory")
	}
	if InitializeGuidedState(f.config) != nil || ValidateGuidedHandoff(f.configPath) != nil {
		t.Fatal("stable ready/ledgers rejected")
	}
	if overviewConsentFor(m).CertificateHash != f.initial.AnchorHash || projectActionSetupIdentity(m, 1001, 1001).IncarnationDigest != "sha256:"+f.initial.AnchorHash {
		t.Fatal("scope incarnation changed")
	}
	configRaw, _ := os.ReadFile(f.configPath)
	readyRaw, _ := os.ReadFile(filepath.Join(filepath.Dir(f.configPath), "ready.json"))
	if validateUpdatesActivatedBytes(configRaw, readyRaw, m) != nil {
		t.Fatal("original immutable ready rejected")
	}
	var ready map[string]any
	json.Unmarshal(readyRaw, &ready)
	ready["certificateHash"] = renewalFixtureHash(f.renewed.CertificateDER)
	changed, _ := json.Marshal(ready)
	if validateUpdatesActivatedBytes(configRaw, changed, m) == nil {
		t.Fatal("current leaf substituted for original ready anchor")
	}
}

func TestRenewalMaterialPreservesBindingAndPendingBytes(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	before, err := Load(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if InitializeGuidedState(f.config) != nil {
		t.Fatal("initialize")
	}
	state, err := openSenderState(before)
	if err != nil {
		t.Fatal(err)
	}
	// The opaque pending body is deliberately not recaptured or rewritten by a
	// credential rollover. Its digest and floor remain the original state owner’s.
	pending := []byte(`{"fixture":"exact pending observation"}`)
	sequence, err := state.NextSequence()
	if err != nil {
		t.Fatal(err)
	}
	p, err := state.Stage(sequence, pending)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	paths := []string{f.config.CertificateFile, f.configPath, filepath.Join(filepath.Dir(f.configPath), "ready.json"), filepath.Join(f.config.StateDirectory, "state.json")}
	originals := map[string][]byte{}
	for _, path := range paths {
		originals[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.write(t, f.renewed)
	after, err := Load(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if before.binding != after.binding || journalLeaf(before) != journalLeaf(after) || overviewConsentFor(before) != overviewConsentFor(after) {
		t.Fatal("same-key renewal changed existing grant authority")
	}
	state, err = openSenderState(after)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	retained, err := state.Pending()
	if err != nil || retained == nil || retained.Sequence != p.Sequence || retained.Digest != p.Digest || !bytes.Equal(retained.Body(), pending) {
		t.Fatal("pending bytes/floor changed", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, originals[path]) {
			t.Fatal("immutable artifact changed", filepath.Base(path))
		}
	}
}

func TestRenewalMaterialRejectsWrongCurrentCredentialAndManifest(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	for name, change := range map[string]func(*renewalidentity.Manifest){
		"profile":  func(m *renewalidentity.Manifest) { m.CollectionProfile = enrollmentcrypto.CollectionProfileOperational },
		"identity": func(m *renewalidentity.Manifest) { m.DeviceID = "agent_" + strings.Repeat("e", 32) },
		"anchor":   func(m *renewalidentity.Manifest) { m.AnchorHash = strings.Repeat("e", 64) },
		"issuer":   func(m *renewalidentity.Manifest) { m.IssuerFingerprint = strings.Repeat("e", 64) },
		"current-bytes": func(m *renewalidentity.Manifest) {
			m.CertificateDER = bytes.Clone(m.CertificateDER)
			m.CertificateDER[len(m.CertificateDER)-1] ^= 1
		},
		"future-manager-clock": func(m *renewalidentity.Manifest) { m.LastServerNow = time.Now().Add(time.Hour).Unix() },
		"authority-expired":    func(m *renewalidentity.Manifest) { m.AuthorityExpiresAt = time.Now().Unix() },
		"current-expired":      func(m *renewalidentity.Manifest) { m.Intent.NotAfter = time.Now().Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			m := f.renewed
			change(&m)
			f.write(t, m)
			if _, err := Load(f.configPath); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	other := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	bad := f.renewed
	bad.CertificateDER = other.renewed.CertificateDER
	bad.Intent = other.renewed.Intent
	f.write(t, bad)
	if _, err := Load(f.configPath); err == nil {
		t.Fatal("different SPKI accepted")
	}
	f.write(t, f.renewed)
	valid, err := Load(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	valid.certificate.Certificate = [][]byte{f.initial.CertificateDER, f.issuer.Raw}
	if valid.valid() {
		t.Fatal("cached transport leaf detached from verified manifest")
	}
}

func TestRenewalSchemaNeverPromotesLegacyConfig(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	for _, version := range []string{ConfigVersion, GuidedConfigVersion, OperationalConfigVersion, PackageConfigVersion, CompleteConfigVersion, WindowsInventoryConfigVersion} {
		c := f.config
		c.SchemaVersion = version
		raw, _ := json.Marshal(c)
		var decoded Config
		if decodeConfig(raw, &decoded) == nil {
			t.Fatal("legacy schema accepted renewal field", version)
		}
		raw = bytes.Replace(raw, []byte(c.RenewalManifestFile), nil, 1)
		if decodeConfig(raw, &decoded) == nil {
			t.Fatal("legacy schema accepted empty renewal field", version)
		}
	}
	c := f.config
	c.Profile = "http-test"
	c.ServerCAFile = ""
	c.InsecureHTTPAcknowledged = true
	c.ManagerOrigin = "http://fixture.invalid"
	if c.Validate() == nil {
		t.Fatal("plaintext renewal admitted")
	}
	c = f.config
	c.RenewalManifestFile = ""
	if c.Validate() == nil {
		t.Fatal("implicit manifest fallback")
	}
	c = f.config
	c.CollectionProfile = ""
	if c.Validate() == nil {
		t.Fatal("implicit basic profile")
	}
}

func TestRenewalWindowsSoftwareHistoryRetainsExactGrantAndPack(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, false)
	before := f.material(t, f.initial)
	after := f.material(t, f.renewed)
	if before.binding != after.binding || journalLeaf(before) != journalLeaf(after) {
		t.Fatal("Windows identity changed")
	}
	configRaw, _ := os.ReadFile(f.configPath)
	readyRaw, _ := os.ReadFile(filepath.Join(filepath.Dir(f.configPath), "ready.json"))
	if validateUpdatesActivatedBytes(configRaw, readyRaw, after) != nil {
		t.Fatal("Windows immutable ready rejected")
	}
	at := time.Now().UTC().Add(-time.Minute)
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, HistoryScope: windowsfullsoftware.HistoryScope, SenderBinding: before.binding, GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: at}
	store := &fullSoftwareConsentMemory{files: map[string][]byte{}}
	if err := windowsfullsoftware.InitializeState(store, before.config.AgentID, before.binding); err != nil {
		t.Fatal(err)
	}
	consentRaw, err := windowsfullsoftware.EncodeConsent(c)
	if err != nil {
		t.Fatal(err)
	}
	store.Write("consent.json", consentRaw)
	state, err := windowsfullsoftware.OpenState(store, before.config.AgentID, before.binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.Reserve(c, at); err != nil {
		t.Fatal(err)
	}
	if err = state.Finish(windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullsoftware.Row{}}, nil, at); err != nil {
		t.Fatal(err)
	}
	pending, status, err := state.Next(c, at)
	if err != nil || status != "pending" {
		t.Fatal("pending fixture", status, err)
	}
	floor := state.Floor()
	state.Close()
	files := map[string][]byte{}
	for name, raw := range store.files {
		files[name] = bytes.Clone(raw)
	}
	state, err = windowsfullsoftware.OpenState(store, after.config.AgentID, after.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	current, err := windowsfullsoftware.DecodeConsent(store.files["consent.json"])
	if err != nil || current != c {
		t.Fatal("history consent changed")
	}
	retry, status, err := state.Next(current, at.Add(time.Second))
	if err != nil || status != "pending" || !bytes.Equal(pending, retry) || state.Floor() != floor {
		t.Fatal("software retry authority changed", status, err)
	}
	for name, raw := range files {
		if !bytes.Equal(raw, store.files[name]) {
			t.Fatal("software state rewritten", name)
		}
	}
	sender := &fullSoftwareSender{material: after, now: func() time.Time { return time.Unix(f.renewed.Intent.NotAfter, 0) }}
	if sender.validMaterial() {
		t.Fatal("current renewed leaf expiry bypassed")
	}
}

func renewalScopeReader[T any](read func(Material, windowsContextConsentDependencies) (T, bool)) func(Material, windowsContextConsentDependencies) (any, bool) {
	return func(m Material, d windowsContextConsentDependencies) (any, bool) { return read(m, d) }
}
func renewalIndependentScopeReader[T any](decode func([]byte) (T, error)) func(Material, windowsContextConsentDependencies) (any, bool) {
	return func(m Material, d windowsContextConsentDependencies) (any, bool) {
		if !currentWindowsContextMaterial(m, d.reload) {
			return nil, false
		}
		store, e := d.open("", windowsstate.Options{})
		if e != nil {
			return nil, false
		}
		defer store.Close()
		raw, e := store.Read("consent.json")
		if e != nil {
			return nil, false
		}
		var binding struct {
			SenderBinding string `json:"senderBinding"`
		}
		if json.Unmarshal(raw, &binding) != nil || binding.SenderBinding != m.binding {
			return nil, false
		}
		c, e := decode(raw)
		return c, e == nil
	}
}

func TestRenewalWindowsAllTwentyScopesRetainExactReceipts(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, false)
	before, after := f.material(t, f.initial), f.material(t, f.renewed)
	at := time.Now().UTC().Add(-time.Minute)
	type scoped struct {
		value any
		read  func(Material, windowsContextConsentDependencies) (any, bool)
	}
	entries := []scoped{
		{eventConsentFixture(before), renewalScopeReader(readWindowsEventConsentWithDependencies)},
		{volumeConsentFixture(before), renewalScopeReader(readWindowsVolumeConsentWithDependencies)},
		{processConsentFixture(before), renewalScopeReader(readWindowsProcessMetricsConsentWithDependencies)},
		{networkConsentFixture(before), renewalScopeReader(readWindowsNetworkConsentWithDependencies)},
		{serviceStartupConsentFixture(before), renewalScopeReader(readWindowsServiceStartupConsentWithDependencies)},
		{adapterConsentFixture(before), renewalScopeReader(readWindowsAdapterContextConsentWithDependencies)},
		{securityConsentFixture(before), renewalScopeReader(readWindowsSecurityPostureConsentWithDependencies)},
		{sessionConsentFixture(before), renewalScopeReader(readWindowsSessionContextConsentWithDependencies)},
		{hardwareConsentFixture(before), renewalScopeReader(readWindowsHardwareContextConsentWithDependencies)},
		{storageConsentFixture(before), renewalScopeReader(readWindowsStorageContextConsentWithDependencies)},
		{coverageConsentFixture(before), renewalScopeReader(readWindowsSecurityCoverageConsentWithDependencies)},
		{resourceConsentFixture(before), renewalScopeReader(readWindowsResourceContextConsentWithDependencies)},
		{storageIOConsentFixture(before), renewalScopeReader(readWindowsStorageIOConsentWithDependencies)},
		{patchConsentFixture(before), renewalIndependentScopeReader(func(raw []byte) (windowspatchcontext.Consent, error) {
			return windowspatchcontext.DecodeConsent(raw, before.binding)
		})},
		{windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: before.binding, GrantID: strings.Repeat("1", 32), Revision: 1, Enabled: true, ChangedAt: at}, renewalIndependentScopeReader(windowsfullservices.DecodeConsent)},
		{windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: before.binding, GrantID: strings.Repeat("2", 32), Revision: 1, Enabled: true, ChangedAt: at}, renewalIndependentScopeReader(windowsfullprocesses.DecodeConsent)},
		{windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: before.binding, GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: at}, renewalIndependentScopeReader(windowsnetworkcontext.DecodeConsent)},
		{windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, HistoryScope: windowsfullsoftware.HistoryScope, SenderBinding: before.binding, GrantID: strings.Repeat("4", 32), Revision: 1, Enabled: true, ChangedAt: at}, renewalIndependentScopeReader(windowsfullsoftware.DecodeConsent)},
	}
	rawByScope := map[string][]byte{}
	readByScope := map[string]func(Material, windowsContextConsentDependencies) (any, bool){}
	for _, entry := range entries {
		raw, err := json.Marshal(entry.value)
		if err != nil {
			t.Fatal(err)
		}
		var scope struct {
			Scope string `json:"scope"`
		}
		if json.Unmarshal(raw, &scope) != nil || scope.Scope == "" {
			t.Fatal("scope fixture")
		}
		rawByScope[scope.Scope] = raw
		readByScope[scope.Scope] = entry.read
	}
	rawByScope[windowsfullsoftware.HistoryScope] = rawByScope[windowsfullsoftware.Scope]
	readByScope[windowsfullsoftware.HistoryScope] = readByScope[windowsfullsoftware.Scope]
	consent := WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV13, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: WindowsReadAdminScopesV13(), Acknowledged: true}
	if len(consent.Scopes) != 20 || len(rawByScope) != 19 {
		t.Fatal("twenty-scope coverage incomplete")
	}
	digest := func(m Material) []WindowsCapabilityGrantDigest {
		t.Helper()
		out, err := windowsCapabilityGrantDigests(consent, func(scope string) (any, bool) {
			read, ok := readByScope[scope]
			if !ok {
				t.Fatal("scope silently dropped", scope)
			}
			raw := rawByScope[scope]
			return read(m, windowsContextConsentDependencies{reload: func(string) (Material, error) { return m, nil }, open: func(string, windowsstate.Options) (windowsContextConsentStore, error) {
				return &adapterContextConsentMemory{raw: bytes.Clone(raw)}, nil
			}})
		})
		if err != nil {
			t.Fatal("fresh exact grants rejected", err)
		}
		return out
	}
	original := digest(before)
	renewed := digest(after)
	if len(original) != 19 || !reflect.DeepEqual(original, renewed) {
		t.Fatal("renewal replaced/dropped scope receipt or history grant")
	}
}

func TestRenewalProfilesKeepExactFrameShapesAndCreateOnlyState(t *testing.T) {
	profiles := []struct {
		collection, frame           string
		managed, packages, complete bool
	}{
		{enrollmentcrypto.CollectionProfile, FrameVersion, false, false, false},
		{enrollmentcrypto.CollectionProfileOperational, FrameOperationalVersion, true, false, false},
		{enrollmentcrypto.CollectionProfilePackages, FramePackagesVersion, true, true, false},
		{enrollmentcrypto.CollectionProfileComplete, FrameOperationalVersion, true, false, true},
	}
	for _, tc := range profiles {
		t.Run(tc.collection, func(t *testing.T) {
			fixture := newRenewalMaterialFixture(t, tc.collection, false)
			c := fixture.config
			if c.Validate() != nil || !c.guided() || c.managed() != tc.managed || c.packages() != tc.packages || c.complete() != tc.complete {
				t.Fatal("renewal profile dispatch")
			}
			f, raw, err := collectFrameWithSources(context.Background(), c, 1, unavailableOperations, unavailablePackages, syntheticPackageBasic)
			if err != nil || f.SchemaVersion != tc.frame || (f.Operational != nil) != tc.managed || (f.Packages != nil) != tc.packages {
				t.Fatal("renewal changed frame collection scope", err)
			}
			if _, err = decodeFrameForConfig(raw, 1, c); err != nil {
				t.Fatal("own pending frame rejected", err)
			}
			if InitializeGuidedState(c) != nil {
				t.Fatal("fresh renewal state rejected")
			}
			before, err := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if InitializeGuidedState(c) == nil {
				t.Fatal("renewable identity adopted already initialized state")
			}
			after, err := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("repeated initialize changed floor")
			}
		})
	}
}

func TestRenewalLinuxReadScopesAndHelperAuthorityRemainOriginal(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	before, after := f.material(t, f.initial), f.material(t, f.renewed)
	if InitializeGuidedState(f.config) != nil {
		t.Fatal("fixture state")
	}
	consentFixture(t, before)
	if _, ok := readEndpointConsent(after); !ok {
		t.Fatal("hostname/interface grant dropped")
	}
	if completeUpdatesConsentFor(before) != completeUpdatesConsentFor(after) || completeUpdatesStateBinding(before) != completeUpdatesStateBinding(after) || systemStateBinding(before) != systemStateBinding(after) || overviewConsentFor(before) != overviewConsentFor(after) {
		t.Fatal("Linux read scope or floor binding changed")
	}
	endpointRaw, err := os.ReadFile(endpointConsentPath(before))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = endpointidentity.DecodeLocalConsent(endpointRaw, after.binding); err != nil {
		t.Fatal("identity consent rewritten")
	}
	p := socketowner.Policy{Version: socketowner.PolicyVersion, Scope: socketowner.Scope, SenderBinding: before.binding, ManagerOrigin: before.config.ManagerOrigin, TransportProfile: "tls", CollectionProfile: before.config.CollectionProfile, AgentUID: 1001, AgentGID: 1001, HelperUID: 1002, HelperGID: 1002, Epoch: strings.Repeat("e", 64), Enabled: true, MetadataAcknowledged: true, PtraceRiskAcknowledged: true}
	local := SocketOwnerConsent{Version: SocketOwnerConsentVersion, EndpointID: before.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(before), Policy: p}
	if !validateSocketOwnerConsent(local, before, 1001, 1001) || !validateSocketOwnerConsent(local, after, 1001, 1001) {
		t.Fatal("same-key renewal lost separate socket helper grant")
	}
	policy := journalpolicy.Policy{SchemaVersion: journalpolicy.VersionV4, Revision: 1, Generation: strings.Repeat("f", 64), Scope: journalpolicy.ScopeV4, BrowsingContract: journalview.BrowseContract, ServiceAuthorization: journalpolicy.AllSystemServices, CollectionProfile: journalpolicy.CollectionProfile, SenderBinding: before.binding, ManagerOrigin: before.config.ManagerOrigin, TransportProfile: "tls", AgentUID: 1001, HelperUID: 1002, AllowedUnits: []string{}, MaxPriority: 7, Enabled: true, ContentAcknowledged: true}
	generation, err := journalpolicy.PolicyGeneration(policy)
	if err != nil {
		t.Fatal(err)
	}
	jl := journalLocal{policy: policy, generation: generation}
	now := time.Now().UTC().Truncate(time.Microsecond)
	query := journalview.Query{Unit: "example.service", BrowseMode: journalview.BrowseMode, Start: time.Unix(0, 0).UTC(), End: now, MaxPriority: 6}
	permit, err := journalpolicy.AuthorizeBound(policy, journalContext(before, jl), query, generation, now)
	if err != nil {
		t.Fatal(err)
	}
	if permit.Recheck(policy, journalContext(after, jl), now) != nil || journalCurrent(before, permit.PolicyDigest()) != journalCurrent(after, permit.PolicyDigest()) {
		t.Fatal("retained journal permit/consume-once identity changed")
	}
	changed := policy
	changed.Enabled = false
	if permit.Recheck(changed, journalContext(after, jl), now) == nil {
		t.Fatal("renewal revived disabled helper grant")
	}
}

func TestRenewalBindingMatchesExistingScopeWireDomains(t *testing.T) {
	for _, tc := range []struct{ collection, legacy string }{
		{enrollmentcrypto.CollectionProfile, GuidedConfigVersion},
		{enrollmentcrypto.CollectionProfileOperational, OperationalConfigVersion},
		{enrollmentcrypto.CollectionProfilePackages, PackageConfigVersion},
		{enrollmentcrypto.CollectionProfileComplete, CompleteConfigVersion},
		{enrollmentcrypto.CollectionProfileWindowsInventory, WindowsInventoryConfigVersion},
	} {
		t.Run(tc.collection, func(t *testing.T) {
			f := newRenewalMaterialFixture(t, tc.collection, false)
			legacy := f.config
			legacy.SchemaVersion = tc.legacy
			legacy.RenewalManifestFile = ""
			if tc.collection == enrollmentcrypto.CollectionProfile {
				legacy.CollectionProfile = ""
			}
			if senderBinding(legacy, f.anchor) != senderBinding(f.config, f.anchor) {
				t.Fatal("renewal changed scope wire binding domain")
			}
			if tc.collection == enrollmentcrypto.CollectionProfileWindowsInventory {
				m := f.material(t, f.renewed)
				for _, binding := range []string{
					windowsfullservices.SenderBinding("tls", m.config.ManagerOrigin, journalLeaf(m), m.config.AgentID),
					windowsfullsoftware.SenderBinding("tls", m.config.ManagerOrigin, journalLeaf(m), m.config.AgentID),
					windowsfullprocesses.SenderBinding("tls", m.config.ManagerOrigin, journalLeaf(m), m.config.AgentID),
					windowsnetworkcontext.SenderBinding("tls", m.config.ManagerOrigin, journalLeaf(m), m.config.AgentID),
				} {
					if binding != m.binding {
						t.Fatal("manager full generation scope admission would reject renewed sender")
					}
				}
			}
		})
	}
}

func TestRenewalQuiescedSenderStateNeedsNoLiveLeafAndNeverRecreates(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, true)
	f.write(t, f.renewed)
	if err := InitializeGuidedState(f.config); err != nil {
		t.Fatal(err)
	}
	// A lost activation reply may leave no usable current manifest. The caller
	// already authenticates the immutable anchor before this state-only check.
	if err := os.Remove(f.config.RenewalManifestFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f.configPath); err == nil {
		t.Fatal("missing transport manifest accepted")
	}
	paths := []string{filepath.Join(f.config.StateDirectory, "state.json"), filepath.Join(inventoryStateDirectory(f.config), "ledger.json"), filepath.Join(systemStateDirectory(f.config), "system-state.json")}
	original := map[string][]byte{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		original[path] = raw
	}
	if err := ValidateRenewalSenderState(f.config, f.anchor.Raw); err != nil {
		t.Fatal("expired original anchor blocked state-only reconciliation", err)
	}
	for _, path := range paths {
		if err := os.Rename(path, path+".preserved"); err != nil {
			t.Fatal(err)
		}
		if err := ValidateRenewalSenderState(f.config, f.anchor.Raw); err != ErrState {
			t.Fatal("lost used ledger admitted", filepath.Base(path), err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("missing used ledger recreated")
		}
		if err := os.Rename(path+".preserved", path); err != nil {
			t.Fatal(err)
		}
	}
	foreign := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileComplete, false)
	if err := ValidateRenewalSenderState(f.config, foreign.anchor.Raw); err == nil {
		t.Fatal("foreign anchor adopted existing state")
	}
	legacy := f.config
	legacy.SchemaVersion = CompleteConfigVersion
	legacy.RenewalManifestFile = ""
	if err := ValidateRenewalSenderState(legacy, f.anchor.Raw); err != ErrConfiguration {
		t.Fatal("legacy configuration promoted")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, original[path]) {
			t.Fatal("read-only reconciliation changed ledger", filepath.Base(path))
		}
	}
	if err := ValidateRenewalSenderState(f.config, []byte("malformed public certificate")); err != ErrConfiguration {
		t.Fatal("malformed anchor accepted")
	}
}
