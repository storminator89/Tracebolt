//go:build linux

package actionsetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
)

// All keys, certificates, verifiers, identities and files in these tests are
// invented fixtures under t.TempDir. No production apply, localEffects, Docker,
// systemd, host credential provisioning or target-service adapter is invoked.
type managerSetupFixture struct {
	dir, lanPath, enrollmentPath, database string
	lan                                    lanconfig.Material
	enrollment                             enrollmentconfig.Material
	identity                               enrollmentstate.Snapshot
	now                                    time.Time
}

func managerFixtureID(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }
func managerFixtureKey(n byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
}
func managerFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode fixture", err)
	}
	return body
}
func managerFixtureWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal("write fixture", err)
	}
}
func managerFixtureCertificate(t *testing.T, template, parent *x509.Certificate, public ed25519.PublicKey, key ed25519.PrivateKey) ([]byte, *x509.Certificate) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		t.Fatal("create synthetic certificate", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse synthetic certificate", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}
func managerFixturePrivatePEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode synthetic key", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newManagerSetupFixture(t *testing.T, profile string) managerSetupFixture {
	t.Helper()
	f := managerSetupFixture{dir: t.TempDir(), now: time.Unix(1800000010, 0).UTC()}
	start := f.now.Add(-10 * time.Second)
	rootKey, issuerKey := managerFixtureKey(21), managerFixtureKey(22)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic setup root"}, NotBefore: start.Add(-time.Hour), NotAfter: start.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("setup-root-fixture")}
	rootPEM, root := managerFixtureCertificate(t, rootTemplate, rootTemplate, rootKey.Public().(ed25519.PublicKey), rootKey)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic setup issuer"}, NotBefore: start.Add(-time.Hour), NotAfter: start.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("setup-issuer-fixture")}
	issuerPEM, issuer := managerFixtureCertificate(t, issuerTemplate, root, issuerKey.Public().(ed25519.PublicKey), rootKey)
	hash := sha256.Sum256(issuer.Raw)
	ec := enrollmentconfig.Config{SchemaVersion: enrollmentconfig.SchemaVersion, Profile: profile, InstanceID: managerFixtureID("manager", 1), CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerCertificateFile: filepath.Join(f.dir, "issuer.pem"), IssuerPrivateKeyFile: filepath.Join(f.dir, "issuer.key"), IssuerRootFile: filepath.Join(f.dir, "root.pem"), ExpectedIssuerFingerprint: hex.EncodeToString(hash[:])}
	managerFixtureWrite(t, ec.IssuerCertificateFile, issuerPEM)
	managerFixtureWrite(t, ec.IssuerRootFile, rootPEM)
	managerFixtureWrite(t, ec.IssuerPrivateKeyFile, managerFixturePrivatePEM(t, issuerKey))
	state := filepath.Join(f.dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if profile == lanconfig.TLS {
		scheme = "https"
	}
	lc := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: profile, OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444", OperatorOrigin: scheme + "://127.0.0.1:8443", AgentOrigin: scheme + "://127.0.0.1:8444", AgentClientCAFile: ec.IssuerCertificateFile, OperatorAuthFile: filepath.Join(f.dir, "operators.json"), StateDirectory: state, WebDirectory: filepath.Join(f.dir, "web"), InsecureHTTPAcknowledged: profile == lanconfig.HTTPTest}
	if profile == lanconfig.TLS {
		serverKey := managerFixtureKey(23)
		serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Synthetic setup server"}, NotBefore: start.Add(-time.Hour), NotAfter: start.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		serverPEM, _ := managerFixtureCertificate(t, serverTemplate, root, serverKey.Public().(ed25519.PublicKey), rootKey)
		lc.TLSCertificateFile, lc.TLSPrivateKeyFile = filepath.Join(f.dir, "server.pem"), filepath.Join(f.dir, "server.key")
		ec.BootstrapServerCAFile = ec.IssuerRootFile
		managerFixtureWrite(t, lc.TLSCertificateFile, serverPEM)
		managerFixtureWrite(t, lc.TLSPrivateKeyFile, managerFixturePrivatePEM(t, serverKey))
	}
	// Syntactically valid, deliberately non-login fixture verifiers. The unsorted
	// accounts check that every maintenance operator, and no reader, is planned.
	verifier := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("synthetic-salt-12")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	operators := []map[string]any{}
	for _, op := range []struct {
		n       int
		name    string
		restart bool
	}{{3, "maintenance-three", true}, {2, "reader-two", false}, {1, "maintenance-one", true}} {
		capabilities := []string{"read"}
		if op.restart {
			capabilities = append(capabilities, "restart_service")
		}
		operators = append(operators, map[string]any{"id": managerFixtureID("operator", op.n), "username": op.name, "passwordHash": verifier, "capabilities": capabilities})
	}
	managerFixtureWrite(t, lc.OperatorAuthFile, managerFixtureJSON(t, map[string]any{"schemaVersion": "tracebolt.operator-auth.v2", "profile": profile, "operators": operators}))
	f.lanPath, f.enrollmentPath = filepath.Join(f.dir, "lan.json"), filepath.Join(f.dir, "enrollment.json")
	managerFixtureWrite(t, f.lanPath, managerFixtureJSON(t, lc))
	managerFixtureWrite(t, f.enrollmentPath, managerFixtureJSON(t, ec))
	var err error
	f.lan, err = lanconfig.Load(f.lanPath)
	if err != nil {
		t.Fatal("load protected LAN fixture", err)
	}
	f.enrollment, err = enrollmentconfig.Load(f.enrollmentPath, f.lan, f.now)
	if err != nil {
		t.Fatal("load protected enrollment fixture", err)
	}
	f.database = filepath.Join(state, enrollmentconfig.DatabaseFile)
	s, err := enrollmentstore.Open(f.database, f.enrollment.StoreConfig(), issuer.Raw)
	if err != nil {
		t.Fatal("open synthetic enrollment store", err)
	}
	t.Cleanup(func() { s.Close() })
	f.identity = activateManagerSetupFixture(t, s, f.enrollment, start)
	if err = s.Close(); err != nil {
		t.Fatal("close fixture writer before read-only inspection", err)
	}
	return f
}

func activateManagerSetupFixture(t *testing.T, s *enrollmentstore.Store, en enrollmentconfig.Material, start time.Time) enrollmentstate.Snapshot {
	t.Helper()
	ctx := context.Background()
	key := managerFixtureKey(24)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-fixture"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	binding := en.StoreConfig().Binding
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32))
	secretHash, err := enrollmentcrypto.InvitationHash(secret)
	if err != nil {
		t.Fatal(err)
	}
	challenge := enrollmentcrypto.ChallengeContext{ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, Origin: binding.Origin, CollectionProfile: binding.CollectionProfile, InvitationID: managerFixtureID("invite", 1), ClaimID: managerFixtureID("claim", 1), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32)), ExpiresAt: start.Unix() + 120}
	snap, err := s.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: challenge.InvitationID, RequestID: managerFixtureID("request", 1), InvitationHash: hex.EncodeToString(secretHash[:]), Platform: "linux", Now: start.Unix()})
	if err != nil {
		t.Fatal("create synthetic invitation", err)
	}
	control := func(n int) enrollmentstate.Control {
		return enrollmentstate.Control{InvitationID: snap.InvitationID, RequestID: managerFixtureID("request", n), ExpectedRevision: snap.Revision, Now: snap.UpdatedAt + 1}
	}
	c := control(2)
	message, err := enrollmentcrypto.ClaimSigningMessage(challenge, c.RequestID, csr, secret, time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	claimBody := managerFixtureJSON(t, map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": binding.InstanceID, "profile": binding.Profile, "origin": binding.Origin, "collectionProfile": binding.CollectionProfile, "invitationId": challenge.InvitationID, "claimId": challenge.ClaimID, "requestId": c.RequestID, "challenge": challenge.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	claim, err := enrollmentcrypto.VerifyClaim(claimBody, challenge, time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	snap, err = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: c, ClaimID: challenge.ClaimID}, claim)
	if err != nil {
		t.Fatal("claim synthetic invitation", err)
	}
	snap, err = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: control(3), DeviceID: managerFixtureID("agent", 1), KeyFingerprint: snap.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal("approve synthetic identity", err)
	}
	snap, err = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: control(4), IntentID: managerFixtureID("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: start.Unix(), NotAfter: start.Add(24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal("record synthetic issuance", err)
	}
	intent, err := s.SigningIntent(ctx, snap.InvitationID, snap.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := en.Issuer().Sign(ctx, intent, time.Unix(snap.UpdatedAt, 0))
	if err != nil {
		t.Fatal("sign synthetic leaf", err)
	}
	snap, err = s.CommitIssued(ctx, control(5), cert)
	if err != nil {
		t.Fatal("commit synthetic leaf", err)
	}
	c = control(6)
	challenge.ExpiresAt = c.Now + 120
	message, err = enrollmentcrypto.ActivationSigningMessage(challenge, cert.Intent(), c.RequestID, cert.CertificateHash(), time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	activationBody := managerFixtureJSON(t, map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": binding.InstanceID, "profile": binding.Profile, "origin": binding.Origin, "deviceId": intent.DeviceID, "intentId": intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": c.RequestID, "challenge": challenge.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	proof, err := enrollmentcrypto.VerifyActivation(activationBody, cert, challenge, time.Unix(c.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	snap, err = s.Activate(ctx, c, proof)
	if err != nil || snap.State != enrollmentstate.Activated {
		t.Fatal("activate synthetic endpoint", err)
	}
	return snap
}

// These deliberately simple Effects write only the caller's temporary fixture
// tree and use the real create-only database transaction. They cannot start a
// process or access a native launcher, and never invoke localEffects.
type managerIntegrationEffects struct {
	root                       string
	creates, keys, initializes int
}

func (f *managerIntegrationEffects) inFixture(path string) bool {
	rel, err := filepath.Rel(f.root, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func (f *managerIntegrationEffects) Create(path string, body []byte) error {
	if !f.inFixture(path) {
		return errors.New("outside fixture")
	}
	f.creates++
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	return errors.Join(err, file.Close())
}
func (f *managerIntegrationEffects) Mkdir(path string) error {
	if !f.inFixture(path) {
		return errors.New("outside fixture")
	}
	return os.Mkdir(path, 0700)
}
func (f *managerIntegrationEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	f.keys++
	key := managerFixtureKey(25)
	return key.Public().(ed25519.PublicKey), key, nil
}
func (f *managerIntegrationEffects) Initialize(ctx context.Context, m material, key ed25519.PublicKey, now time.Time) error {
	path := filepath.Join(m.plan.StateDirectory, enrollmentconfig.DatabaseFile)
	if !f.inFixture(path) {
		return errors.New("outside fixture")
	}
	f.initializes++
	s, err := enrollmentstore.Open(path, m.enrollment.StoreConfig(), m.enrollment.Issuer().IssuerDER())
	if err != nil {
		return err
	}
	err = s.SetupServiceActionsCreateOnly(ctx, key, m.plan.EndpointID, m.plan.IncarnationDigest, now)
	return errors.Join(err, s.Close())
}

type managerFixtureFile struct {
	Body     []byte
	Mode     fs.FileMode
	Modified time.Time
	UID, GID uint32
	Inode    uint64
}

func managerFixtureTree(t *testing.T, dir string) map[string]managerFixtureFile {
	t.Helper()
	out := map[string]managerFixtureFile{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		item := managerFixtureFile{Mode: info.Mode(), Modified: info.ModTime(), UID: stat.Uid, GID: stat.Gid, Inode: stat.Ino}
		if !entry.IsDir() {
			if !info.Mode().IsRegular() {
				return errors.New("unexpected fixture file type")
			}
			item.Body, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[rel] = item
		return nil
	})
	if err != nil {
		t.Fatal("snapshot fixture tree", err)
	}
	return out
}

func managerFixtureEnrollmentBytes(t *testing.T, f managerSetupFixture) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	// The fixture writer is closed: immutable read-only access avoids creating
	// SQLite sidecars while checking the pre-existing enrollment bytes.
	u := url.URL{Scheme: "file", Path: f.database, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ledger, credential []byte
	if err = db.QueryRow(`SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.identity.InvitationID).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(credential, &fields); err != nil {
		t.Fatal(err)
	}
	return ledger, fields
}

func TestManagerSetupLoadedFixturePlanApplyStatusPreservesOriginals(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			f := newManagerSetupFixture(t, profile)
			ctx := context.Background()
			before := managerFixtureTree(t, f.dir)
			ledgerBefore, credentialBefore := managerFixtureEnrollmentBytes(t, f)
			p, err := PlanManager(ctx, f.lanPath, f.enrollmentPath, f.identity.Approval.DeviceID, f.now)
			if err != nil {
				t.Fatal("plan actual protected fixture", err)
			}
			wantOperators := []Operator{{managerFixtureID("operator", 1), "maintenance-one"}, {managerFixtureID("operator", 3), "maintenance-three"}}
			if p.ManagerID != f.identity.Binding.InstanceID || p.ManagerOrigin != f.lan.Config.AgentOrigin || p.EndpointID != f.identity.Approval.DeviceID || p.IncarnationDigest != "sha256:"+f.identity.Issuance.CertificateHash || p.TransportProfile != actionmanager.Profile(profile) || p.HTTPTestAcknowledged != (profile == lanconfig.HTTPTest) || p.UID != os.Geteuid() || p.GID != os.Getegid() || p.Digest != p.calculatedDigest() || !actionpermit.ValidDigest(p.InputDigest) || !reflect.DeepEqual(p.Operators, wantOperators) {
				t.Fatal("plan lost loaded identity, transport, authority or digest binding")
			}
			if _, err = StatusManager(ctx, f.lanPath, f.enrollmentPath, p.EndpointID, f.now); !errors.Is(err, ErrSetup) {
				t.Fatal("fresh fixture reported completed setup", err)
			}
			m, err := load(ctx, f.lanPath, f.enrollmentPath, p.EndpointID, f.now, true)
			if err != nil || !reflect.DeepEqual(m.plan, p) {
				t.Fatal("apply material differs from public plan", err)
			}
			if !reflect.DeepEqual(before, managerFixtureTree(t, f.dir)) {
				t.Fatal("planning/status/load changed fixture files, database, modes or sidecars")
			}
			fx := &managerIntegrationEffects{root: f.dir}
			bundle, err := apply(ctx, m, p, fx, f.now)
			if err != nil || fx.keys != 1 || fx.initializes != 1 || fx.creates != 6 {
				t.Fatal("fixture apply did not complete exactly one setup", err)
			}
			wantBundle := NewBundle(p, managerFixtureKey(25).Public().(ed25519.PublicKey))
			if bundle != wantBundle {
				t.Fatal("public bundle differs from fixture key and reviewed plan")
			}
			after := managerFixtureTree(t, f.dir)
			for path, item := range before {
				if item.Mode.IsRegular() && filepath.Join(f.dir, path) != f.database && !reflect.DeepEqual(item, after[path]) {
					t.Fatal("apply altered original protected input", path)
				}
			}
			ledgerAfter, credentialAfter := managerFixtureEnrollmentBytes(t, f)
			if _, ok := credentialBefore["serviceActionSetup"]; ok || credentialAfter["serviceActionSetup"] == nil {
				t.Fatal("create-only credential marker missing or pre-existing")
			}
			delete(credentialAfter, "serviceActionSetup")
			if !bytes.Equal(ledgerBefore, ledgerAfter) || !reflect.DeepEqual(credentialBefore, credentialAfter) {
				t.Fatal("setup changed enrollment lifecycle, certificate, delivery or replay state")
			}
			inspection, err := enrollmentstore.InspectServiceActionSetup(ctx, f.database, f.enrollment.Issuer().IssuerDER(), p.EndpointID, f.now)
			if err != nil || inspection.Status != enrollmentstore.ServiceActionSetupFenced || inspection.Identity != f.identity || inspection.Config != f.enrollment.StoreConfig() || !bytes.Equal(inspection.PublicKey, managerFixtureKey(25).Public().(ed25519.PublicKey)) {
				t.Fatal("real database fenced identity does not match bundle", err)
			}
			for i := 0; i < 2; i++ {
				got, err := StatusManager(ctx, f.lanPath, f.enrollmentPath, p.EndpointID, f.now)
				if err != nil || got != bundle {
					t.Fatal("completed read-only status rejected generated artifacts", err)
				}
			}
			if _, err = PlanManager(ctx, f.lanPath, f.enrollmentPath, p.EndpointID, f.now); !errors.Is(err, ErrSetup) {
				t.Fatal("completed fixture eligible for fresh setup", err)
			}
			if _, err = apply(ctx, m, p, fx, f.now); !errors.Is(err, ErrSetup) || fx.keys != 1 || fx.initializes != 1 {
				t.Fatal("repeat apply generated another key or initialized again", err)
			}
			if !reflect.DeepEqual(after, managerFixtureTree(t, f.dir)) {
				t.Fatal("completed status or blocked repeat mutated files/database/sidecars")
			}
			updated, err := lanconfig.Load(LANPath(p.StateDirectory))
			wantLAN := f.lan.Config
			wantLAN.ServiceActionsConfigFile = setupPath(p.StateDirectory, "commands.json")
			if err != nil || updated.Config != wantLAN {
				t.Fatal("generated LAN sibling does not load with original configuration preserved", err)
			}
		})
	}
}

func TestManagerSetupLoadedFixturePlanRefusalsAreReadOnly(t *testing.T) {
	for _, name := range []string{"manager-binding", "collection-profile", "no-maintenance-operator", "configured-actions", "unknown-endpoint", "expired-identity", "missing-database"} {
		t.Run(name, func(t *testing.T) {
			f := newManagerSetupFixture(t, lanconfig.HTTPTest)
			device, now := f.identity.Approval.DeviceID, f.now
			switch name {
			case "manager-binding", "collection-profile":
				raw, err := os.ReadFile(f.enrollmentPath)
				if err != nil {
					t.Fatal(err)
				}
				var config enrollmentconfig.Config
				if err = json.Unmarshal(raw, &config); err != nil {
					t.Fatal(err)
				}
				if name == "manager-binding" {
					config.InstanceID = managerFixtureID("manager", 2)
				} else {
					config.CollectionProfile = enrollmentcrypto.CollectionProfile
				}
				managerFixtureWrite(t, f.enrollmentPath, managerFixtureJSON(t, config))
			case "no-maintenance-operator":
				raw, err := os.ReadFile(f.lan.Config.OperatorAuthFile)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.ReplaceAll(raw, []byte(`,"restart_service"`), nil)
				managerFixtureWrite(t, f.lan.Config.OperatorAuthFile, raw)
				if _, err = lanconfig.Load(f.lanPath); err != nil {
					t.Fatal("reader-only fixture must remain valid LAN config", err)
				}
			case "configured-actions":
				config := f.lan.Config
				config.ServiceActionsConfigFile = filepath.Join(f.dir, "existing-commands.json")
				managerFixtureWrite(t, f.lanPath, managerFixtureJSON(t, config))
			case "unknown-endpoint":
				device = managerFixtureID("agent", 2)
			case "expired-identity":
				now = time.Unix(f.identity.Intent.NotAfter, 0).UTC()
			case "missing-database":
				if err := os.Rename(f.database, f.database+".fixture-retained"); err != nil {
					t.Fatal(err)
				}
			}
			before := managerFixtureTree(t, f.dir)
			if _, err := PlanManager(context.Background(), f.lanPath, f.enrollmentPath, device, now); !errors.Is(err, ErrSetup) {
				t.Fatal("invalid or incompatible loaded fixture planned", err)
			}
			if !reflect.DeepEqual(before, managerFixtureTree(t, f.dir)) {
				t.Fatal("rejected plan created or changed fixture state")
			}
		})
	}
}

func TestManagerSetupLoadedFixtureStatusRejectsChangedArtifactsWithoutRepair(t *testing.T) {
	for _, name := range []string{"changed-source-bytes", "missing-intent", "missing-completion", "changed-command-key", "changed-command-config", "changed-lan-sibling", "changed-public-bundle", "changed-completion", "wrong-endpoint"} {
		t.Run(name, func(t *testing.T) {
			f := newManagerSetupFixture(t, lanconfig.HTTPTest)
			ctx := context.Background()
			device := f.identity.Approval.DeviceID
			m, err := load(ctx, f.lanPath, f.enrollmentPath, device, f.now, true)
			if err != nil {
				t.Fatal(err)
			}
			fx := &managerIntegrationEffects{root: f.dir}
			if _, err = apply(ctx, m, m.plan, fx, f.now); err != nil {
				t.Fatal("fixture apply", err)
			}
			state := f.lan.Config.StateDirectory
			switch name {
			case "changed-source-bytes":
				raw, err := os.ReadFile(f.lanPath)
				if err != nil {
					t.Fatal(err)
				}
				// A semantically identical edit still breaks exact provenance.
				managerFixtureWrite(t, f.lanPath, append(raw, '\n'))
				if _, err = lanconfig.Load(f.lanPath); err != nil {
					t.Fatal("changed-byte fixture must remain valid LAN config", err)
				}
			case "missing-intent", "missing-completion":
				path := IntentPath(state)
				if name == "missing-completion" {
					path = CompletePath(state)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "changed-command-key":
				key := managerFixtureKey(25)
				key[len(key)-1] ^= 1
				managerFixtureWrite(t, setupPath(state, "command.key"), key)
			case "changed-command-config":
				managerFixtureWrite(t, setupPath(state, "commands.json"), []byte(`{}`))
			case "changed-lan-sibling":
				managerFixtureWrite(t, LANPath(state), []byte(`{}`))
			case "changed-public-bundle":
				managerFixtureWrite(t, setupPath(state, "bundle.json"), []byte(`{}`))
			case "changed-completion":
				managerFixtureWrite(t, CompletePath(state), []byte(`{}`))
			case "wrong-endpoint":
				device = managerFixtureID("agent", 2)
			}
			before := managerFixtureTree(t, f.dir)
			if _, err = StatusManager(ctx, f.lanPath, f.enrollmentPath, device, f.now); !errors.Is(err, ErrSetup) {
				t.Fatal("changed completed fixture reported valid", err)
			}
			if _, err = PlanManager(ctx, f.lanPath, f.enrollmentPath, device, f.now); !errors.Is(err, ErrSetup) {
				t.Fatal("damaged completed fixture eligible for fresh setup", err)
			}
			if !reflect.DeepEqual(before, managerFixtureTree(t, f.dir)) {
				t.Fatal("status or plan repaired or changed rejected fixture state")
			}
		})
	}
}
