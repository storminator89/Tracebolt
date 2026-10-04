// Disposable, loopback-only fixture for real operator/store/catalog/review APIs.
// Every device observation and catalog is invented. No collector/package command
// is run. Stdin controls synthetic state; it is never an HTTP test backdoor.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

const fixturePassword = "TRACEBOLT_CONDITIONAL_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

var phase = "setup"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func id(prefix string) string {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	must(e)
	return prefix + hex.EncodeToString(b)
}
func jsonBytes(v any) []byte { b, e := json.Marshal(v); must(e); return b }
func ptr[T any](v T) *T      { return &v }

type fixture struct {
	service *enrollmentservice.Service
	store   *enrollmentstore.Store
	offset  atomic.Int64
	devices map[string]enrollmentstate.Snapshot
	seq     map[string]uint64
}

func (f *fixture) now() time.Time { return time.Now().UTC().Add(time.Duration(f.offset.Load())) }
func (f *fixture) seed(active bool) enrollmentstate.Snapshot {
	ctx := context.Background()
	created, e := f.service.CreateInvitation(ctx, id("request_"), "linux")
	must(e)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	defer clear(key)
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Invented browser fixture"}}, key)
	must(e)
	claimID := id("claim_")
	c, e := f.service.Challenge("127.0.0.1", created.Snapshot().InvitationID, claimID, "claim")
	must(e)
	request := id("request_")
	message, e := enrollmentcrypto.ClaimSigningMessage(c.Context, request, csr, created.Secret(), f.now())
	must(e)
	common := func(c enrollmentservice.Challenge) map[string]string {
		return map[string]string{"managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "challenge": c.Context.Challenge}
	}
	body := common(c)
	body["schemaVersion"] = enrollmentcrypto.ClaimVersion
	body["requestId"] = request
	body["invitationSecret"] = created.Secret()
	body["csr"] = base64.RawStdEncoding.EncodeToString(csr)
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	raw := jsonBytes(body)
	s, e := f.service.Claim(ctx, c.Context.Challenge, raw)
	clear(raw)
	delete(body, "invitationSecret")
	must(e)
	s, e = f.service.Approve(ctx, s.InvitationID, id("request_"), s.Claim.KeyFingerprint, s.Revision)
	must(e)
	if !active {
		return s
	}
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "status")
	must(e)
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	must(e)
	fp := sha256.Sum256(der)
	request = id("request_")
	message, e = enrollmentcrypto.StatusSigningMessage(c.Context, "status", request, der, f.now())
	must(e)
	body = common(c)
	body["schemaVersion"] = enrollmentcrypto.StatusVersion
	body["purpose"] = "status"
	body["requestId"] = request
	body["keyFingerprint"] = hex.EncodeToString(fp[:])
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	s, e = f.service.Status(ctx, c.Context.Challenge, jsonBytes(body))
	must(e)
	cert, e := f.store.CertificateForVerification(ctx, s.InvitationID)
	must(e)
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "activation")
	must(e)
	request = id("request_")
	message, e = enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), request, cert.CertificateHash(), f.now())
	must(e)
	body = map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))}
	s, e = f.service.Activate(ctx, c.Context.Challenge, jsonBytes(body))
	must(e)
	return s
}
func healthy(m *operational.SectionMeta, n int) {
	m.Quality = operational.Healthy
	m.Reason = operational.ReasonNone
	m.Complete = true
	m.CountExact = true
	m.ObservedCount = uint64(n)
}
func (f *fixture) sample(which, mode string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	at := f.now()
	op := operational.Empty(at, operational.ReasonSourceMissing)
	if mode != "unknown" {
		healthy(&op.Sections.Services.Meta, 2)
		op.Sections.Services.Items = []operational.Service{{Name: "qa-fixture-alpha.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}, {Name: "qa-fixture-beta.service", LoadState: "loaded", ActiveState: "active", SubState: "running"}}
		healthy(&op.Sections.Software.Meta, 2)
		op.Sections.Software.Items = []operational.Software{{Name: "qa-fixture-binary", Version: "9.0-1", Architecture: "amd64", Manager: "dpkg"}, {Name: "qa-fixture-other", Version: "3.0-1", Architecture: "amd64", Manager: "dpkg"}}
		healthy(&op.Sections.Network.Meta, 1)
		op.Sections.Network.Items = []operational.NetworkInterface{{Name: "fixture0", State: "up", MTU: ptr(uint64(1500)), RXBytes: ptr(uint64(4096)), TXBytes: ptr(uint64(2048)), RXErrors: ptr(uint64(0)), TXErrors: ptr(uint64(0)), IPv4Count: ptr(uint64(1)), IPv6Count: ptr(uint64(0))}}
		healthy(&op.Sections.Processes.Meta, 1)
		op.Sections.Processes.Items = []operational.Process{{PID: 42, ParentPID: ptr(uint64(1)), CPUTimeSeconds: ptr(float64(1.5)), Name: "qa-fixture-worker", State: "sleeping", RSSBytes: ptr(uint64(8192)), Threads: ptr(uint64(2))}}
	}
	if mode == "partial" {
		op.Sections.Services.Meta.Complete = false
		op.Sections.Services.Meta.Truncated = true
		op.Sections.Services.Meta.Reason = operational.ReasonItemLimit
		op.Sections.Services.Meta.ObservedCount = 200
	}
	phase = "validate synthetic operational"
	if e := operational.Validate(op); e != nil {
		return e
	}
	packages := linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: op.GenerationID, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: ptr("debian"), VersionID: ptr("13"), VersionCodename: ptr("trixie")}}, Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true, ObservedCount: ptr(uint64(2)), InstalledCount: ptr(uint64(2)), Items: []linuxpackages.PackageRow{{Name: "qa-fixture-binary", Version: "9.0-1", Architecture: "amd64", SourcePackage: "qa-fixture-source", SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}, {Name: "qa-fixture-other", Version: "3.0-1", Architecture: "amd64", SourcePackage: "qa-fixture-source", SourceVersion: "3.0-1", SourceMapping: "source-field", InstallState: "installed"}}}}
	switch mode {
	case "healthy":
	case "partial":
		packages.Inventory.Complete = false
		packages.Inventory.Truncated = true
		packages.Inventory.Reason = linuxpackages.ReasonItemLimit
		packages.Inventory.ObservedCount = ptr(uint64(20))
		packages.Inventory.InstalledCount = ptr(uint64(20))
	case "unknown":
		packages.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}
		packages.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing, Items: []linuxpackages.PackageRow{}}
	case "unsupported":
		packages.Release.Fields = linuxpackages.ReleaseFields{ID: ptr("ubuntu"), VersionID: ptr("24.04"), VersionCodename: ptr("noble")}
	case "source-mismatch":
		packages.Inventory.Items[0].SourcePackage = "qa-other-source"
	case "comparison-unavailable":
		packages.Inventory.Items[0].SourceVersion = "2147483648:1"
	default:
		return errors.New("unsupported fixture mode")
	}
	phase = "validate synthetic packages"
	if e := linuxpackages.Validate(packages); e != nil {
		return e
	}
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Invented browser fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Invented Debian fixture", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at, Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	next := f.seq[which] + 1
	frame := lanstore.Frame{SchemaVersion: lanstore.FramePackagesVersion, Sequence: next, Observation: b, Operational: &op, Packages: &packages}
	raw := jsonBytes(frame)
	phase = "validate synthetic frame"
	if _, e := lanstore.ValidateFrame(raw, at); e != nil {
		return e
	}
	phase = "commit synthetic observation"
	if _, e := f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at); e != nil {
		return e
	}
	f.seq[which] = next
	return nil
}
func run() {
	listen := flag.String("listen", "127.0.0.1:19892", "loopback-only fixture")
	dir := flag.String("state", "", "private disposable state")
	web := flag.String("web", "", "built UI directory")
	flag.Parse()
	host, portText, e := net.SplitHostPort(*listen)
	must(e)
	if host != "127.0.0.1" || *dir == "" || *web == "" {
		panic("invalid fixture")
	}
	port, e := strconv.Atoi(portText)
	must(e)
	phase = "issuer"
	issuer, e := makeIssuer(time.Now().UTC())
	must(e)
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://" + *listen, CollectionProfile: enrollmentcrypto.CollectionProfilePackages, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit = 25
	cfg.InvitationLimit = 25
	cfg.PendingLimit = 25
	phase = "store"
	state, e := enrollmentstore.Open(filepath.Join(*dir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
	must(e)
	defer state.Close()
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}, seq: map[string]uint64{}}
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "seed identities"
	f.devices["alpha"] = f.seed(true)
	f.devices["beta"] = f.seed(true)
	f.devices["awaiting"] = f.seed(false)
	phase = "synthetic observations"
	must(f.sample("alpha", "healthy"))
	must(f.sample("beta", "healthy"))
	phase = "operator"
	appStore, e := store.Open(filepath.Join(*dir, "app.db"))
	must(e)
	defer appStore.Close()
	app, e := api.New(appStore, port, *web, model.Device{})
	must(e)
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: 5 * time.Minute})
	must(e)
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IssuerDER()}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}))
	registry, e := lantrust.NewRegistry(context.Background(), []byte(issuerPEM), lantrust.NewMemoryStore())
	must(e)
	handler, e := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: cfg.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: f.service, EnrollmentBootstrap: api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: cfg.Binding.InstanceID, Profile: "http-test", EnrollmentOrigin: cfg.Binding.Origin, AgentOrigin: "http://127.0.0.1:19893", CollectionProfile: cfg.Binding.CollectionProfile, ServerCAPEM: "", IssuerRootPEM: rootPEM, IssuerPEM: issuerPEM}, Devices: func() ([]model.Device, error) {
		devices, err := f.service.Devices(context.Background(), f.now())
		for i := range devices {
			for label, identity := range f.devices {
				if devices[i].ID == identity.Approval.DeviceID {
					devices[i].Name = "QA synthetic fixture " + label
				}
			}
		}
		return devices, err
	}})
	must(e)
	phase = "listen"
	listener, e := net.Listen("tcp", *listen)
	must(e)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4096)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var c struct {
			Action  string `json:"action"`
			Device  string `json:"device"`
			Mode    string `json:"mode"`
			Seconds int64  `json:"seconds"`
		}
		must(json.Unmarshal(scanner.Bytes(), &c))
		phase = "fixture control"
		ok := true
		switch c.Action {
		case "info":
		case "sample":
			ok = f.sample(c.Device, c.Mode) == nil
		case "advance":
			if c.Seconds < 0 || c.Seconds > 90000 {
				ok = false
			} else {
				f.offset.Add(int64(time.Duration(c.Seconds) * time.Second))
			}
		case "revoke":
			s, exists := f.devices[c.Device]
			if !exists {
				ok = false
			} else {
				_, e := f.service.Terminate(context.Background(), s.InvitationID, id("request_"), s.Revision, enrollmentstate.Revoked)
				ok = e == nil

			}
		default:
			ok = false
		}
		ids := map[string]string{}
		for label, s := range f.devices {
			ids[label] = s.Approval.DeviceID
		}
		must(encoder.Encode(map[string]any{"ok": ok, "devices": ids}))
	}
	must(scanner.Err())
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Conditional browser fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
