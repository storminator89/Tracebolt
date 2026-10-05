// Disposable, loopback-only fixture for the real operator journal APIs.
// Every identity, observation and journal message is invented. No collector,
// journal source, helper, host permission or install command is invoked.
// Only stdin controls delivery and the trusted clock; no HTTP control exists.
package main

import (
	"bufio"
	"bytes"
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
	"io"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
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

const fixturePassword = "TRACEBOLT_JOURNAL_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

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

type fixture struct {
	service              *enrollmentservice.Service
	store                *enrollmentstore.Store
	offset               atomic.Int64
	alphaMetadataUpdated atomic.Bool
	devices              map[string]enrollmentstate.Snapshot
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

// seedSystem establishes current v3 systemAuthority from a typed invented frame.
// It does not run a collector or claim that any journal helper is installed.
func (f *fixture) seedSystem(which string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown_device")
	}
	at := f.now()
	generation, err := systemwire.GenerationID(identity.Approval.DeviceID, 1)
	if err != nil {
		return err
	}
	snapshot := systeminventory.Empty(generation, at, systeminventory.ReasonNotCollected)
	services := []systeminventory.Service{
		{Name: "invented-backup.service", Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "inactive", SubState: "dead"}},
		{Name: "invented.service", Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}},
		{Name: "invented:unsupported.service", Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}},
	}
	count := uint64(len(services))
	snapshot.Services = systeminventory.ServiceSection{
		Meta:  systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true},
		Items: services,
	}
	raw, err := systemwire.Encode(1, snapshot)
	if err != nil {
		return err
	}
	_, err = f.store.SaveSystemObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	return err
}

// deliver consumes only the browser/API-created pending request. This test seam
// replaces the endpoint reader with typed invented rows, and otherwise uses the
// production peek/claim/cache-accept path, exact identity and original expiry.
func (f *fixture) deliver(which, mode string) (map[string]any, error) {
	identity, ok := f.devices[which]
	if !ok {
		return nil, errors.New("unknown_device")
	}
	if mode != "complete" && mode != "partial" {
		return nil, errors.New("invalid_mode")
	}
	ctx := context.Background()
	d, err := f.store.PeekJournalRequest(ctx, identity.InvitationID, identity.Issuance.CertificateHash, f.now())
	if err != nil {
		return nil, err
	}
	policy := sha256.Sum256([]byte("invented-journal-browser-policy:" + which))
	claim := journalrequest.Claim{Identity: d.Identity, PolicyDigest: "sha256:" + hex.EncodeToString(policy[:])}
	rows := make([]journalview.Row, 205)
	for i := range rows {
		message := fmt.Sprintf("Synthetic %s journal row %03d: invented harmless event", which, i)
		switch i {
		case 0:
			message += " Needle[.*]"
		case 100:
			message += " nEeDlE[.*]"
		case 200:
			message += " NEEDLE[.*]"
		case 1:
			message += ` <img src=x onerror="window.__journalFixtureHTMLExecuted=true">`
		}
		// Align every invented timestamp to a valid microsecond inside the query.
		at := d.Query.Start.Add(time.Duration(i) * d.Query.End.Sub(d.Query.Start) / time.Duration(len(rows)-1)).Truncate(time.Microsecond)
		rows[i] = journalview.Row{Timestamp: at, Unit: d.Query.Unit, Priority: i % (d.Query.MaxPriority + 1), Message: message}
	}
	snapshot := journalview.Snapshot{SchemaVersion: journalview.SchemaVersion, Scope: journalview.Scope, Query: d.Query, ObservedAt: f.now(), Coverage: journalview.Complete, Reason: journalview.ReasonNone, Rows: rows, ObservedCount: uint64(len(rows)), CountExact: true, RedactionApplied: false, RedactionWarning: journalview.RedactionWarning}
	if mode == "partial" {
		snapshot.Coverage, snapshot.Reason, snapshot.CountExact = journalview.Partial, journalview.ReasonVisibilityRestricted, false
	}
	// Exercise the real typed serialization contract before consuming the grant.
	raw, err := journalwire.EncodeResult(journalwire.Result{Claim: claim, Snapshot: snapshot})
	if err != nil {
		return nil, err
	}
	result, err := journalwire.DecodeResult(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	grant, err := f.store.ClaimJournalRequest(ctx, identity.InvitationID, identity.Issuance.CertificateHash, claim, f.now())
	if err != nil {
		return nil, err
	}
	if grant.Description.Identity != d.Identity || grant.PolicyDigest != claim.PolicyDigest {
		return nil, errors.New("unexpected_grant")
	}
	receipt, err := f.service.JournalCache().Accept(ctx, identity.InvitationID, identity.Issuance.CertificateHash, identity.Approval.DeviceID, result, f.now())
	if err != nil {
		return nil, err
	}
	return map[string]any{"identity": receipt.Identity, "snapshotDigest": receipt.ResultDigest, "expiresAt": receipt.ExpiresAt, "observedAt": snapshot.ObservedAt, "capturedRows": len(rows), "coverage": snapshot.Coverage, "reason": snapshot.Reason}, nil
}

func controlError(err error) string {
	switch {
	case errors.Is(err, journalrequest.ErrNotFound):
		return "journal_not_found"
	case errors.Is(err, journalrequest.ErrNotReady):
		return "journal_not_ready"
	case errors.Is(err, journalrequest.ErrConflict):
		return "journal_conflict"
	case errors.Is(err, journalrequest.ErrConsumed):
		return "journal_consumed"
	case errors.Is(err, journalrequest.ErrExpired):
		return "journal_expired"
	case errors.Is(err, journalrequest.ErrCanceled):
		return "journal_canceled"
	default:
		return "fixture_control_failed"
	}
}

func run() {
	listen := flag.String("listen", "127.0.0.1:19897", "loopback-only fixture")
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
	if port < 1 || port > 65535 {
		panic("invalid fixture port")
	}
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
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}}
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "seed identities"
	f.devices["alpha"] = f.seed(true)
	f.devices["beta"] = f.seed(true)
	phase = "synthetic observations"
	must(f.seedSystem("alpha"))
	must(f.seedSystem("beta"))
	phase = "operator"
	appStore, e := store.Open(filepath.Join(*dir, "app.db"))
	must(e)
	defer appStore.Close()
	app, e := api.New(appStore, port, *web, model.Device{})
	must(e)
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: time.Hour})
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
					devices[i].Name = "QA synthetic journal " + label
					if label == "alpha" && f.alphaMetadataUpdated.Load() {
						devices[i].Name = "QA synthetic journal alpha refreshed"
					}
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
		phase = "fixture control"
		out := map[string]any{"ok": true}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&c)
		if err == nil {
			if _, end := decoder.Token(); end != io.EOF {
				err = errors.New("invalid_control")
			}
		}
		if err == nil {
			switch c.Action {
			case "info":
			case "deliver":
				var result map[string]any
				result, err = f.deliver(c.Device, c.Mode)
				for key, value := range result {
					out[key] = value
				}
			case "metadata":
				// A fixed invented display-name change only; no observation or clock update.
				if c.Device != "alpha" || c.Mode != "" || c.Seconds != 0 {
					err = errors.New("invalid_metadata_control")
				} else {
					f.alphaMetadataUpdated.Store(true)
				}
			case "advance":
				if c.Seconds < 0 || c.Seconds > 90000 {
					err = errors.New("invalid_advance")
				} else {
					f.offset.Add(int64(time.Duration(c.Seconds) * time.Second))
				}
			default:
				err = errors.New("unknown_action")
			}
		}
		if err != nil {
			out["ok"], out["error"] = false, controlError(err)
		}
		ids := map[string]string{}
		for label, s := range f.devices {
			ids[label] = s.Approval.DeviceID
		}
		out["devices"], out["serverNow"] = ids, f.now()
		must(encoder.Encode(out))
	}
	must(scanner.Err())
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Journal browser fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
