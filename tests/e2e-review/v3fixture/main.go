// Disposable, loopback-only fixture for real operator/package/system inventory APIs.
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
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

const fixturePassword = "TRACEBOLT_V3_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

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
func (f *fixture) packages(which, mode string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	at := f.now()
	key := which + ":packages"
	seq := f.seq[key] + 1
	generation, e := inventorywire.GenerationID(identity.Approval.DeviceID, seq)
	if e != nil {
		return e
	}
	if mode == "failure" {
		// A live partial transfer must be explicitly aborted before a later source attempt.
		current, err := f.store.InventoryView(context.Background(), identity.Approval.DeviceID, at)
		if err != nil {
			return err
		}
		if current.Transfer != nil && current.Transfer.State == "pending" {
			digest, err := fullinventory.ManifestDigest(current.Transfer.Manifest)
			if err != nil {
				return err
			}
			binding := enrollmentstore.InventoryBinding{Sequence: current.Sequence, GenerationID: current.Transfer.Manifest.GenerationID, ManifestHash: digest}
			if err = f.store.InventoryAbort(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, binding, at); err != nil {
				return err
			}
		}
		_, e = f.store.InventoryFailure(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, enrollmentstore.InventoryFailureReport{Sequence: seq, GenerationID: generation, AttemptedAt: at, Reason: "source_missing"}, at)
		if e == nil {
			f.seq[key] = seq
		}
		return e
	}
	n := 2052
	if mode == "empty" {
		n = 0
	}
	rows := make([]linuxpackages.PackageRow, n)
	for i := range rows {
		name := fmt.Sprintf("qa-package-%06d", i)
		version := "9.0-1"
		if mode == "replace" {
			version = "10.0-1"
		}
		state := "installed"
		if i == 1 {
			state = "incomplete"
		}
		rows[i] = linuxpackages.PackageRow{Name: name, Version: version, Architecture: "amd64", SourcePackage: fmt.Sprintf("qa-source-%06d", i), SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: state}
	}
	manifest, chunks, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Rows: rows, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if e != nil {
		return e
	}
	digest, e := fullinventory.ManifestDigest(manifest)
	if e != nil {
		return e
	}
	binding := enrollmentstore.InventoryBinding{Sequence: seq, GenerationID: generation, ManifestHash: digest}
	ctx := context.Background()
	if _, e = f.store.InventoryBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); e != nil {
		return e
	}
	for i, chunk := range chunks {
		if _, e = f.store.InventoryAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, at); e != nil {
			return e
		}
		if mode == "pending" && i == 0 {
			f.seq[key] = seq
			return nil
		}
	}
	if _, e = f.store.InventoryFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at); e != nil {
		return e
	}
	f.seq[key] = seq
	return nil
}
func (f *fixture) system(which, mode string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	at := f.now()
	key := which + ":system"
	seq := f.seq[key] + 1
	generation, e := systemwire.GenerationID(identity.Approval.DeviceID, seq)
	if e != nil {
		return e
	}
	snapshot := systeminventory.Empty(generation, at, systeminventory.ReasonPermissionDenied)
	if mode != "failed" {
		n := 2052
		sockets := 30
		if mode == "empty" {
			n = 0
			sockets = 0
		}
		rows := make([]systeminventory.Service, n)
		for i := range rows {
			active, sub := "active", "running"
			if i%3 == 0 {
				active, sub = "failed", "failed"
			}
			enabled := "disabled"
			if i%2 == 0 {
				enabled = "enabled"
			}
			rows[i] = systeminventory.Service{Name: fmt.Sprintf("qa-service-%06d.service", i), Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: active, SubState: sub}, Enablement: ptr(enabled)}
			if i == 0 {
				rows[i].Runtime = nil
			}
		}
		meta := func(n int) systeminventory.SectionMeta {
			return systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: ptr(uint64(n)), CountExact: true}
		}
		snapshot.Services = systeminventory.ServiceSection{Meta: meta(n), Items: rows}
		socketRows := make([]systeminventory.Socket, 0, sockets)
		for i := 0; i < sockets; i++ {
			row := systeminventory.Socket{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: uint16(10000 + i)}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionUnavailable, Reason: systeminventory.ReasonNoMatch}}
			if i >= 20 {
				row.Protocol = "udp"
				row.Kind = "bound"
				row.State = "bound"
			} else if i%2 == 1 {
				row.Kind = "connection"
				row.State = "established"
				row.Remote = systeminventory.Endpoint{Address: "192.0.2.5", Port: 443}
			}
			if i == 0 {
				row.Owners = []systeminventory.Owner{{PID: 42, ProcessName: ptr("qa-fixture-worker"), NameReason: systeminventory.ReasonNone}}
				row.Attribution = systeminventory.Attribution{Coverage: systeminventory.AttributionObserved, Reason: systeminventory.ReasonNone}
			}
			socketRows = append(socketRows, row)
		}
		snapshot.Sockets = systeminventory.SocketSection{Meta: meta(sockets), Items: socketRows}
	}
	raw, e := systemwire.Encode(seq, snapshot)
	if e != nil {
		return e
	}
	_, e = f.store.SaveSystemObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	if e == nil {
		f.seq[key] = seq
	}
	return e
}
func (f *fixture) sample(which, mode string) error {
	f.offset.Add(int64(time.Second))
	switch mode {
	case "healthy", "empty", "replace":
		if e := f.packages(which, mode); e != nil {
			return e
		}
		return f.system(which, mode)
	case "pending", "failure":
		return f.packages(which, mode)
	case "system-failed":
		return f.system(which, "failed")
	default:
		return errors.New("unsupported fixture mode")
	}
}
func run() {
	listen := flag.String("listen", "127.0.0.1:19894", "loopback-only fixture")
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
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://" + *listen, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit = 25
	cfg.InvitationLimit = 25
	cfg.PendingLimit = 25
	phase = "store"
	state, e := enrollmentstore.Open(filepath.Join(*dir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
	must(e)
	defer state.Close()
	// Match current manager schema setup only; no endpoint collection grant.
	must(state.InitializeCompleteUpdates(context.Background()))
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}, seq: map[string]uint64{}}
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "seed identities"
	f.devices["alpha"] = f.seed(true)
	f.devices["beta"] = f.seed(true)
	f.devices["awaiting"] = f.seed(true)
	phase = "synthetic observations"
	must(f.sample("alpha", "healthy"))
	must(f.sample("beta", "empty"))
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
					devices[i].Name = "QA synthetic v3 " + label
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
			fmt.Fprintln(os.Stderr, "V3 browser fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
