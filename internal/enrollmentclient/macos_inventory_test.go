package enrollmentclient

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
	"localrmm/internal/agentloop"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/lanclient"
	inventory "localrmm/internal/macosinventory"
	sender "localrmm/internal/macosinventorysender"
	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Entirely in-memory disposable public/issuer/leaf fixtures. No listener,
// native provider, persistent endpoint key, invitation, grant or service exists.
func macOSInventoryFixture(t *testing.T) (*session, *enrollmentissuer.Issuer, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := func(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
	rk, ik, ak := key(1), key(2), key(3)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "inert root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rk.Public(), rk)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rd)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "inert issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	id, e := x509.CreateCertificate(rand.Reader, intermediate, root, ik.Public(), rk)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := enrollmentissuer.New(id, rd, ik, fingerprint(id), now)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := x509.MarshalPKIXPublicKey(ak.Public())
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ak)
	pemCert := func(b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})) }
	idFor := func(p string, n byte) string { return p + "_" + strings.Repeat(string(n), 32) }
	b := Bootstrap{SchemaVersion: BootstrapVersion, ManagerInstanceID: idFor("manager", '1'), Profile: "tls", EnrollmentOrigin: "https://fixture.invalid", AgentOrigin: "https://fixture.invalid", CollectionProfile: inventory.Scope, InvitationID: idFor("invite", '2'), ServerCAPEM: pemCert(rd), IssuerRootPEM: pemCert(rd), IssuerPEM: pemCert(id)}
	intent := enrollmentcrypto.Intent{ManagerInstanceID: b.ManagerInstanceID, Profile: "tls", Origin: b.EnrollmentOrigin, CollectionProfile: inventory.Scope, InvitationID: b.InvitationID, ClaimID: idFor("claim", '3'), RequestID: idFor("request", '4'), DeviceID: idFor("agent", '5'), IntentID: idFor("intent", '6'), KeyFingerprint: fingerprint(pub), PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(pub), CSRHash: fingerprint(csr), ClaimHash: strings.Repeat("a", 64), IssuerFingerprint: fingerprint(id), SerialHex: strings.Repeat("7", 32), TemplateVersion: enrollmentcrypto.TemplateVersion, KeyGeneration: 1, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(7*24*time.Hour - time.Minute).Unix()}
	cert, e := issuer.Sign(context.Background(), intent, now)
	if e != nil {
		t.Fatal(e)
	}
	der := cert.DER()
	anchor, _ := x509.ParseCertificate(der)
	binding, e := sender.OriginalBinding(b.AgentOrigin, intent.DeviceID, anchor)
	if e != nil {
		t.Fatal(e)
	}
	grant := strings.Repeat("b", 32)
	consent, e := inventory.EncodeConsent(inventory.Consent{SchemaVersion: inventory.ConsentVersion, Scope: inventory.Scope, SenderBinding: binding.SenderBinding, GrantID: grant, Enabled: true}, binding.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	enable, e := wire.EncodeControl(wire.Control{SchemaVersion: wire.ControlVersion, Binding: binding, GrantID: grant, GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: now})
	if e != nil {
		t.Fatal(e)
	}
	s := &session{&sessionData{opts: Options{StateDirectory: filepath.Join(t.TempDir(), "unused"), inventoryEnrollment: true}, key: ak, publicDER: pub, csr: csr, issuerDER: id, l: ledger{&ledgerData{Version: ledgerVersion, Bootstrap: b, ClaimID: intent.ClaimID, ClaimHash: intent.ClaimHash, LastRevision: 1, ClaimConfirmed: true, Intent: intent, CertificateDER: base64.RawStdEncoding.EncodeToString(der), ActivationAttempted: true, Activated: true, MacOSInventory: &macOSInventoryEnrollment{Version: macOSInventoryEnrollmentVersion, Acknowledged: true, GrantID: grant, Consent: base64.RawStdEncoding.EncodeToString(consent), OriginalEnable: base64.RawStdEncoding.EncodeToString(enable)}}}}}
	return s, issuer, now
}
func TestMacOSInventoryExplicitApprovalBeforePrivateState(t *testing.T) {
	s, _, _ := macOSInventoryFixture(t)
	b := s.l.Bootstrap
	o := s.opts
	calls := 0
	o.ApproveMacOSInventory = func(disclosure string) (bool, error) {
		calls++
		if !strings.Contains(disclosure, "24 hours") || !strings.Contains(disclosure, "numeric local addresses") {
			t.Fatal("incomplete disclosure")
		}
		return false, nil
	}
	if e := approveMacOSInventory(context.Background(), b, o, "darwin"); !errors.Is(e, ErrInput) || calls != 1 {
		t.Fatal("unchecked scope admitted", e)
	}
	if _, e := os.Stat(o.StateDirectory); !os.IsNotExist(e) {
		t.Fatal("approval created private state")
	}
	for _, platform := range []string{"linux", "windows", ""} {
		calls = 0
		if e := approveMacOSInventory(context.Background(), b, o, platform); e == nil || calls != 0 {
			t.Fatal("non-Mac approval callback", platform)
		}
	}
	calls = 0
	o.ApproveMacOSInventory = func(string) (bool, error) { calls++; return true, nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := approveMacOSInventory(ctx, b, o, "darwin"); e == nil || calls != 0 {
		t.Fatal("cancelled approval advanced")
	}
	o.ApproveMacOSInventory = func(string) (bool, error) { cancel(); return true, nil }
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if e := approveMacOSInventory(ctx, b, o, "darwin"); !errors.Is(e, context.Canceled) {
		t.Fatal("approval cancellation ignored")
	}
	if _, e := Run(context.Background(), b, o); !errors.Is(e, ErrBootstrap) {
		t.Fatal("generic enrollment widened")
	}
	o.ApproveMacOSInventory = func(string) (bool, error) { return true, nil }
	if e := approveMacOSInventory(context.Background(), b, o, "darwin"); e != nil {
		t.Fatal("explicit approval rejected", e)
	}
}
func TestMacOSInventoryOriginalGrantAndDistinctHandoff(t *testing.T) {
	s, _, _ := macOSInventoryFixture(t)
	c, files, _, e := s.handoff()
	defer clearArtifacts(files)
	if e != nil || c.SchemaVersion != lanclient.MacOSInventoryConfigVersion || c.Validate() == nil {
		t.Fatal("generic schema accepted inventory", e)
	}
	for _, f := range files {
		if f.name == "agent.json" {
			if _, e := lanclient.ParseMacOSInventoryConfig(f.raw, filepath.Join(s.opts.StateDirectory, "agent.json")); e != nil {
				t.Fatal("explicit config invalid", e)
			}
		}
	}
	original := *s.l.MacOSInventory
	for _, edit := range []func(){func() { s.l.MacOSInventory.Acknowledged = false }, func() { s.l.MacOSInventory.GrantID = strings.Repeat("c", 32) }, func() { s.l.Bootstrap.AgentOrigin = "https://other.invalid" }, func() { s.opts.inventoryEnrollment = false }} {
		s, _, _ = macOSInventoryFixture(t)
		edit()
		if _, _, _, e = s.macOSInventoryOriginal(); e == nil {
			t.Fatal("altered provenance admitted")
		}
	}
	s, _, _ = macOSInventoryFixture(t)
	s.l.MacOSInventory = &original
	s.l.Bootstrap.CollectionProfile = enrollmentcrypto.CollectionProfile
	if s.validateMacOSInventoryLedger() == nil {
		t.Fatal("basic ledger adopted inventory")
	}
}
func TestMacOSInventoryInitializationFenceNeverRecreatesUsedState(t *testing.T) {
	for _, fail := range []string{"used", "directory", "fresh", ""} {
		order := []string{}
		started := false
		step := func(name string) func() error {
			return func() error {
				order = append(order, name)
				if name == "used" {
					started = true
				}
				if fail == name {
					return ErrState
				}
				return nil
			}
		}
		e := initializeMacOSInventoryOnce(false, step("used"), step("directory"), step("fresh"), step("existing"))
		if (e != nil) != (fail != "") || !started || order[0] != "used" {
			t.Fatal("initialization order", order, e)
		}
		fresh := 0
		existing := 0
		e = initializeMacOSInventoryOnce(started, func() error { t.Fatal("used fence rewritten"); return nil }, func() error { t.Fatal("used directory recreated"); return nil }, func() error { fresh++; return nil }, func() error { existing++; return ErrState })
		if e == nil || fresh != 0 || existing != 1 {
			t.Fatal("missing/interrupted used state recreated")
		}
	}
}

type macOSInventoryFakeRunner struct {
	maintain, cycles int
	failure          error
}

func (f *macOSInventoryFakeRunner) Maintain(context.Context) (state.Status, error) {
	f.maintain++
	return state.Status{}, nil
}
func (f *macOSInventoryFakeRunner) Cycle(context.Context) error { f.cycles++; return f.failure }
func TestMacOSInventoryLoopMaintainsExpiredAuthorityAndFixedCadence(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		f := &macOSInventoryFakeRunner{failure: sender.ErrAuthority}
		waits := 0
		summary, e := runMacOSInventoryLoopWithWait(ctx, f, maintenance, nil, func(ctx context.Context, d time.Duration) error {
			waits++
			if d != time.Minute {
				t.Fatal("wrong cadence")
			}
			if waits == 3 {
				cancel()
				return ctx.Err()
			}
			return nil
		})
		if !errors.Is(e, context.Canceled) || f.maintain != 3 || summary.Attempts != 3 || maintenance && f.cycles != 0 || !maintenance && f.cycles != 3 {
			t.Fatal("authority failure stopped retention", summary, e)
		}
	}
}
func TestMacOSInventoryLoopCancellationAndObserverFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &macOSInventoryFakeRunner{}
	_, e := runMacOSInventoryLoopWithWait(ctx, f, false, func(agentloop.Event) error { cancel(); return nil }, func(ctx context.Context, d time.Duration) error { return ctx.Err() })
	if !errors.Is(e, context.Canceled) || f.cycles != 1 || f.maintain != 1 {
		t.Fatal("cancellation performed more work")
	}
	f = &macOSInventoryFakeRunner{}
	_, e = runMacOSInventoryLoopWithWait(context.Background(), f, false, func(agentloop.Event) error { return errors.New("private text") }, func(context.Context, time.Duration) error { t.Fatal("observer failure waited"); return nil })
	if !errors.Is(e, agentloop.ErrObserver) {
		t.Fatal("raw observer failure")
	}
}
func TestMacOSInventoryLegacyLedgerBytesStayUnchanged(t *testing.T) {
	l := ledgerData{Version: ledgerVersion}
	raw, e := json.Marshal(ledgerDisk(l))
	if e != nil || bytes.Contains(raw, []byte("macOSInventory")) {
		t.Fatal("legacy ledger acquired scope field")
	}
	var decoded ledger
	if strictJSON(raw, &decoded) != nil || decoded.MacOSInventory != nil {
		t.Fatal("legacy read changed")
	}
}

func TestMacOSInventoryReopenedTrustAndExhaustedAuthority(t *testing.T) {
	s, _, now := macOSInventoryFixture(t)
	if e := s.initializeMacOSInventoryTrust(); e != nil {
		t.Fatal(e)
	}
	expected, e := enrollmentcrypto.ComparisonCode(s.l.Bootstrap.ManagerInstanceID, s.l.Bootstrap.InvitationID, s.l.ClaimID, fingerprint(s.publicDER))
	if e != nil || s.trust.ComparisonCode != expected || expected == "" {
		t.Fatal("reopened status comparison lost")
	}
	s.l.Bootstrap.SchemaVersion = RenewableBootstrapVersion
	s.l.Bootstrap.RenewalPolicy = "same-key-v1"
	m, e := s.initialRenewalManifest()
	if e != nil {
		t.Fatal(e)
	}
	if s.macOSInventoryManifestExhausted(m, now) || !s.macOSInventoryManifestExhausted(m, time.Unix(m.AuthorityExpiresAt, 0).UTC()) {
		t.Fatal("historical exhausted authority classified as corruption")
	}
	m.CollectionProfile = "basic-readonly-v1"
	if s.macOSInventoryManifestExhausted(m, time.Unix(m.AuthorityExpiresAt, 0).UTC()) {
		t.Fatal("foreign manifest classified as expiry")
	}
}
func TestMacOSInventoryPendingExpiryKeepsMaintenanceAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &macOSInventoryFakeRunner{failure: state.ErrExpired}
	waits := 0
	_, e := runMacOSInventoryLoopWithWait(ctx, f, false, nil, func(ctx context.Context, d time.Duration) error {
		waits++
		if waits == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	})
	if !errors.Is(e, context.Canceled) || waits != 2 || f.maintain != 2 {
		t.Fatal("original pending expiry stopped maintenance", e)
	}
}

type macOSInventoryMemory struct{ raw []byte }

func (m *macOSInventoryMemory) CreateFresh(next []byte) error {
	if len(m.raw) != 0 {
		return state.ErrConflict
	}
	m.raw = bytes.Clone(next)
	return nil
}
func (m *macOSInventoryMemory) Commit(before, next []byte) error {
	if !bytes.Equal(m.raw, before) {
		return state.ErrConflict
	}
	m.raw = bytes.Clone(next)
	return nil
}
func TestMacOSInventoryRenewalKeepsExactPendingBytesAndFloors(t *testing.T) {
	s, issuer, now := macOSInventoryFixture(t)
	s.l.Bootstrap.SchemaVersion = RenewableBootstrapVersion
	s.l.Bootstrap.RenewalPolicy = "same-key-v1"
	_, _, enable, e := s.macOSInventoryOriginal()
	if e != nil {
		t.Fatal(e)
	}
	m, e := s.initialRenewalManifest()
	if e != nil {
		t.Fatal(e)
	}
	disk := &macOSInventoryMemory{}
	st, e := state.InitializeFresh(disk, enable, now)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := wire.ReceiptFor(enable, now)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := wire.EncodeReceipt(receipt, enable)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.AcknowledgeControl(ack, now); e != nil {
		t.Fatal(e)
	}
	capture := time.Unix(m.AnchorIntent.NotAfter, 0).UTC().Add(-30 * time.Minute)
	lease, e := st.Reserve(capture)
	if e != nil {
		t.Fatal(e)
	}
	control, _ := wire.DecodeControl(enable)
	consent, _ := inventory.DecodeConsent(mustDecodeInventory64(t, s.l.MacOSInventory.Consent), control.Binding.SenderBinding)
	snap := inventory.Empty(inventory.Request{Consent: consent, SenderBinding: control.Binding.SenderBinding, GenerationID: lease.GenerationID(), CollectedAt: lease.CollectedAt()}, inventory.ErrUnavailable.Error())
	report, e := wire.BuildReport(control, lease.Sequence(), snap)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := wire.EncodeReport(report)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.Stage(lease, pending, capture); e != nil {
		t.Fatal(e)
	}
	before := bytes.Clone(disk.raw)
	st.Close()
	next := m
	next.Intent = m.Intent
	next.Intent.RequestID = "request_" + strings.Repeat("8", 32)
	next.Intent.IntentID = "intent_" + strings.Repeat("9", 32)
	next.Intent.SerialHex = strings.Repeat("8", 32)
	next.Intent.NotBefore = capture.Add(-time.Minute).Unix()
	next.Intent.NotAfter = capture.Add(7*24*time.Hour - time.Minute).Unix()
	issued, e := issuer.Sign(context.Background(), next.Intent, capture)
	if e != nil {
		t.Fatal(e)
	}
	next.CertificateDER = issued.DER()
	next.CredentialGeneration = 2
	next.Revision++
	next.LastServerNow = capture.Unix()
	anchor, _ := x509.ParseCertificate(m.CertificateDER)
	iss, _ := x509.ParseCertificate(s.issuerDER)
	reopen := time.Unix(m.AnchorIntent.NotAfter, 0).UTC().Add(time.Minute)
	if _, e = next.Validate(anchor, iss, m.AgentOrigin, m.CollectionProfile, m.DeviceID, reopen); e != nil {
		t.Fatal("same-key successor invalid", e)
	}
	// Credential publication owns neither the independent checkpoint nor its
	// enable/grant binding; it does not pass the successor leaf into Restore.
	if !bytes.Equal(before, disk.raw) {
		t.Fatal("credential changed checkpoint")
	}
	restored, e := state.Restore(disk, enable, disk.raw, reopen)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	retry, e := restored.PendingReport(reopen)
	if e != nil || !bytes.Equal(retry, pending) {
		t.Fatal("renewal regenerated pending bytes", e)
	}
	status, e := restored.Inspect(reopen)
	if e != nil || status.Floor != lease.Sequence() {
		t.Fatal("renewal reset floor", status, e)
	}
	if _, e := restored.Reserve(reopen); e == nil {
		t.Fatal("pending report recaptured")
	}
}
func mustDecodeInventory64(t *testing.T, s string) []byte {
	t.Helper()
	raw, e := base64.RawStdEncoding.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestMacOSInventoryArtifactPublicationInterruption(t *testing.T) {
	raw := []byte("inert exact artifact")
	for _, tc := range []struct {
		name           string
		l              ledgerData
		missing, allow bool
	}{
		{"ready.json", ledgerData{}, true, true},
		{"ready.json", ledgerData{SenderInitializationStarted: true}, true, true},
		{"ready.json", ledgerData{SenderInitializationStarted: true, HandoffPrepared: true}, true, false},
		{"agent.json", ledgerData{}, false, false},
		{"agent.json", ledgerData{SenderInitializationStarted: true}, false, true},
		{"ready.json", ledgerData{SenderInitializationStarted: true}, false, false},
		{"ready.json", ledgerData{SenderInitializationStarted: true, HandoffPrepared: true}, false, true},
		{lanclient.MacOSInventoryConsentName, ledgerData{SenderInitializationStarted: true}, true, false},
		{lanclient.MacOSInventoryEnableName, ledgerData{SenderInitializationStarted: true}, true, false},
	} {
		var e error
		if tc.missing {
			e = os.ErrNotExist
		}
		if got := validateMacOSInventoryArtifact(tc.l, tc.name, raw, e, raw); (got == nil) != tc.allow {
			t.Fatal("interrupted artifact admitted or repaired", tc.name, tc.missing, got)
		}
	}
	if e := validateMacOSInventoryArtifact(ledgerData{SenderInitializationStarted: true}, "agent.json", []byte("different"), nil, raw); e == nil {
		t.Fatal("replaced artifact admitted")
	}
}
