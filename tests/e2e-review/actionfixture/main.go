// Disposable loopback-only acceptance fixture for the real service-action APIs.
// It uses invented enrollment and a test-only protocol-driving agent. Helper
// framing/state are real; root identity, peer and executor are injected fakes.
// This does not run the production actionSender or any real host/systemctl action.
// Only bounded stdin controls the fake backend; no HTTP control/bypass exists.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionmanager"
	"localrmm/internal/actionstate"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

const fixturePassword = "TRACEBOLT_ACTION_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"
const fixtureUnit = "fixture.service"
const fixtureName = "QA synthetic action alpha"

var phase = "setup"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func id(prefix string) string {
	var b [16]byte
	_, e := rand.Read(b[:])
	must(e)
	return prefix + hex.EncodeToString(b[:])
}
func jsonBytes(v any) []byte { b, e := json.Marshal(v); must(e); return b }

type fixture struct {
	service            *enrollmentservice.Service
	store              *enrollmentstore.Store
	issuer             *enrollmentissuer.Issuer
	identity           enrollmentstate.Snapshot
	certificate        tls.Certificate
	manager            *actionmanager.Manager
	helper             *actionhelper.Server
	helperState        *actionstate.State
	backend            *fakeBackend
	client             *http.Client
	agentOrigin        string
	claims             atomic.Int32
	dispatchStarted    bool
	recoveryPeekStatus string
	resultDone         chan error
	cancel             context.CancelFunc
	context            context.Context
}

func (f *fixture) now() time.Time { return time.Now().UTC() }
func (f *fixture) close() {
	f.backend.release.Do(func() { close(f.backend.allowCompletion) })
	f.cancel()
	if f.resultDone != nil {
		select {
		case <-f.resultDone:
		case <-time.After(6 * time.Second):
		}
	}
	f.client.CloseIdleConnections()
	if f.helperState != nil {
		f.helperState.Close()
	}
	if f.manager != nil {
		f.manager.Close()
	}
	if key, ok := f.certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(key)
	}
}

type fakeBackend struct {
	calls           atomic.Int32
	entered         chan struct{}
	allowCompletion chan struct{}
	release         sync.Once
}

func (*fakeBackend) Check(context.Context, actionhelper.Target) (actionhelper.Observation, error) {
	return actionhelper.Active, nil
}
func (b *fakeBackend) TryRestart(ctx context.Context, unit string) error {
	if unit != fixtureUnit {
		return errors.New("fixture_unit_mismatch")
	}
	if b.calls.Add(1) != 1 {
		return errors.New("fixture_duplicate_execution")
	}
	close(b.entered)
	select {
	case <-b.allowCompletion:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*fakeBackend) Observe(context.Context, string) (actionhelper.Observation, error) {
	return actionhelper.Active, nil
}
func (f *fixture) status() (map[string]any, error) {
	r, at, e := f.manager.ViewAt(f.context, f.identity.Approval.DeviceID)
	if e != nil {
		return nil, e
	}
	state := "none"
	if len(r.Jobs) > 0 {
		state = r.Jobs[len(r.Jobs)-1].State(at)
	}
	return map[string]any{"ok": true, "deviceId": f.identity.Approval.DeviceID, "deviceName": fixtureName, "actorId": "operator_00000000000000000000000000000001", "recoveryPeekStatus": f.recoveryPeekStatus, "unit": fixtureUnit, "calls": f.backend.calls.Load(), "claims": f.claims.Load(), "jobs": len(r.Jobs), "jobState": state, "pending": f.dispatchStarted && state == "claimed"}, nil
}
func server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, ErrorLog: log.New(io.Discard, "", 0)}
}
func run() {
	listen := flag.String("listen", "127.0.0.1:19899", "loopback-only synthetic fixture")
	dir := flag.String("state", "", "empty private disposable directory")
	web := flag.String("web", "", "built UI directory")
	flag.Parse()
	host, portText, e := net.SplitHostPort(*listen)
	must(e)
	port, e := strconv.Atoi(portText)
	must(e)
	if flag.NArg() != 0 || host != "127.0.0.1" || port < 1 || port > 65535 || !filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir || !filepath.IsAbs(*web) {
		panic("invalid_fixture_flags")
	}
	info, e := os.Lstat(*dir)
	must(e)
	entries, e := os.ReadDir(*dir)
	must(e)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || len(entries) != 0 {
		panic("state_must_be_empty_private_fixture_directory")
	}
	phase = "issuer"
	issuer, e := makeIssuer(time.Now().UTC())
	must(e)
	origin := "http://" + *listen
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit = 25
	cfg.InvitationLimit = 25
	cfg.PendingLimit = 25
	phase = "store"
	state, e := enrollmentstore.Open(filepath.Join(*dir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
	must(e)
	defer state.Close()
	ctx, cancel := context.WithCancel(context.Background())
	f := &fixture{store: state, issuer: issuer, backend: &fakeBackend{entered: make(chan struct{}), allowCompletion: make(chan struct{})}, context: ctx, cancel: cancel, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	defer f.close()
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "invented_identity_and_observation"
	f.identity = f.seed()
	f.seedSystem()
	phase = "fixture_action_authority"
	f.prepareActions(*dir)
	phase = "agent_ingress"
	agentListener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	f.agentOrigin = "http://" + agentListener.Addr().String()
	ingress, e := enrollmenttransport.New(state, issuer.IssuerDER(), f.agentOrigin)
	must(e)
	must(ingress.ConfigureServiceActions(f.manager))
	agentServer := server(ingress)
	defer agentServer.Close()
	go func() { _ = agentServer.Serve(agentListener) }()
	must(f.refresh())
	phase = "operator"
	appStore, e := store.Open(filepath.Join(*dir, "app.db"))
	must(e)
	defer appStore.Close()
	app, e := api.New(appStore, port, *web, model.Device{})
	must(e)
	salt := []byte("action-browser-fixture-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	passwordHash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: "operator_00000000000000000000000000000001", Username: "maintainer", PasswordHash: passwordHash, Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}}, TTL: time.Hour})
	must(e)
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IssuerDER()}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}))
	registry, e := lantrust.NewRegistry(ctx, []byte(issuerPEM), lantrust.NewMemoryStore())
	must(e)
	handler, e := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: f.service, ServiceActions: f.manager, EnrollmentBootstrap: api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: cfg.Binding.InstanceID, Profile: "http-test", EnrollmentOrigin: origin, AgentOrigin: f.agentOrigin, CollectionProfile: cfg.Binding.CollectionProfile, IssuerRootPEM: rootPEM, IssuerPEM: issuerPEM}, Devices: func() ([]model.Device, error) {
		devices, e := f.service.Devices(context.Background(), f.now())
		for i := range devices {
			if devices[i].ID == f.identity.Approval.DeviceID {
				devices[i].Name = fixtureName
			}
		}
		return devices, e
	}})
	must(e)
	phase = "listen"
	listener, e := net.Listen("tcp", *listen)
	must(e)
	operatorServer := server(handler)
	defer operatorServer.Close()
	go func() { _ = operatorServer.Serve(listener) }()
	phase = "control"
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var c struct {
			Action string `json:"action"`
		}
		d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		d.DisallowUnknownFields()
		err := d.Decode(&c)
		if err == nil {
			if _, e := d.Token(); e != io.EOF {
				err = errors.New("invalid_control")
			}
		}
		if err == nil {
			switch c.Action {
			case "info", "status":
			case "refresh":
				err = f.refresh()
			case "dispatch":
				err = f.dispatch()
			case "complete":
				err = f.complete()
			case "recover":
				err = f.recoverStatus()
			default:
				err = errors.New("invalid_control")
			}
		}
		out, statusErr := f.status()
		if err != nil || statusErr != nil {
			out = map[string]any{"ok": false, "error": "fixture_control_failed"}
		}
		must(encoder.Encode(out))
	}
	must(scanner.Err())
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Synthetic service-action fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
