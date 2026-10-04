// Disposable, loopback-only fixture for real operator endpoint-identity APIs.
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
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lantrust"
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

const fixturePassword = "TRACEBOLT_ENDPOINT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

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
func (f *fixture) sample(which, mode string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	f.offset.Add(int64(time.Second))
	at := f.now()
	seq := f.seq[which] + 1
	generation, e := systemwire.GenerationID(identity.Approval.DeviceID, seq)
	if e != nil {
		return e
	}
	system := systeminventory.Empty(generation, at, systeminventory.ReasonNotCollected)
	var raw []byte
	if mode == "ordinary" {
		raw, e = systemwire.Encode(seq, system)
	} else {
		endpoint := endpointidentity.Empty(generation, at, endpointidentity.ReasonPermissionDenied)
		meta := func(n int) endpointidentity.SectionMeta {
			return endpointidentity.SectionMeta{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, ObservedCount: ptr(uint32(n)), CountExact: true}
		}
		family := func(name, address string) endpointidentity.AddressSection {
			return endpointidentity.AddressSection{Meta: meta(1), Items: []endpointidentity.Address{{Family: name, Address: address, Scope: "other"}}}
		}
		empty := endpointidentity.AddressSection{Meta: meta(0), Items: []endpointidentity.Address{}}
		denied := endpointidentity.AddressSection{Meta: endpointidentity.SectionMeta{Coverage: endpointidentity.Failed, Reason: endpointidentity.ReasonPermissionDenied}, Items: []endpointidentity.Address{}}
		endpoint.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: ptr("qa-host-<lab>&" + which)}
		endpoint.Interfaces = endpointidentity.InterfaceSection{Meta: meta(2), Items: []endpointidentity.Interface{
			{Index: 2, Name: "qa-eth0", Up: true, Loopback: false, HardwareKind: "unknown", Addresses: endpointidentity.AddressSet{IPv4: family("ipv4", "192.0.2.19"), IPv6: family("ipv6", "2001:db8::19")}},
			{Index: 7, Name: "qa-vnet0", Up: false, Loopback: false, HardwareKind: "unknown", Addresses: endpointidentity.AddressSet{IPv4: family("ipv4", "198.51.100.24"), IPv6: family("ipv6", "::ffff:192.0.2.24")}},
		}}
		switch mode {
		case "complete":
		case "partial":
			endpoint.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Failed, Reason: endpointidentity.ReasonPermissionDenied}
			endpoint.Interfaces.Meta.Coverage = endpointidentity.Partial
			endpoint.Interfaces.Meta.Reason = endpointidentity.ReasonAddressUnavailable
			endpoint.Interfaces.Items[0].Addresses.IPv6 = empty
			endpoint.Interfaces.Items[1].Addresses.IPv6 = denied
		case "denied":
			endpoint = endpointidentity.Empty(generation, at, endpointidentity.ReasonPermissionDenied)
		case "empty":
			endpoint.Interfaces = endpointidentity.InterfaceSection{Meta: meta(0), Items: []endpointidentity.Interface{}}
		default:
			return errors.New("unsupported fixture mode")
		}
		raw, e = systemwire.EncodeEndpoint(seq, system, endpoint)
	}
	if e != nil {
		return e
	}
	_, e = f.store.SaveSystemObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	if e == nil {
		f.seq[which] = seq
	}
	return e
}
func run() {
	listen := flag.String("listen", "127.0.0.1:19895", "loopback-only fixture")
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
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}, seq: map[string]uint64{}}
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "seed identities"
	f.devices["alpha"] = f.seed(true)
	f.devices["beta"] = f.seed(true)
	f.devices["awaiting"] = f.seed(true)
	phase = "synthetic observations"
	must(f.sample("alpha", "complete"))
	must(f.sample("beta", "complete"))
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
					devices[i].Name = "QA synthetic endpoint " + label
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
			fmt.Fprintln(os.Stderr, "Endpoint browser fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
