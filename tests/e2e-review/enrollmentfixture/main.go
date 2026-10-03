// enrollmentfixture is a disposable, loopback-only real-handler browser fixture.
// Stdin is a private control pipe, never an HTTP test backdoor. Generated keys
// stay in its temporary state; stdout returns only bounded public client status.
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
	"localrmm/internal/api"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const password = "TRACEBOLT_ENROLLMENT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

type clientState struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	phase       string
	fingerprint string
	comparison  string
	bootstrap   enrollmentclient.Bootstrap
	dir         string
}
type command struct {
	Action    string                     `json:"action"`
	Secret    string                     `json:"secret"`
	Bootstrap enrollmentclient.Bootstrap `json:"bootstrap"`
}

func (s *clientState) start(c command, parent string) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return errors.New("client already running")
	}
	if c.Action == "start" {
		dir, err := os.MkdirTemp(parent, "native-")
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.dir, s.bootstrap = dir, c.Bootstrap
	}
	if s.dir == "" {
		s.mu.Unlock()
		return errors.New("client missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done, s.phase = cancel, make(chan struct{}), "starting"
	b, dir, done := s.bootstrap, s.dir, s.done
	s.mu.Unlock()
	secret := []byte(c.Secret)
	go func() {
		defer clear(secret)
		_, err := enrollmentclient.Run(ctx, b, enrollmentclient.Options{StateDirectory: dir, InsecureHTTPAcknowledged: true, Timeout: time.Minute, PollInterval: 2 * time.Second,
			Display: func(d enrollmentclient.TrustDisplay) error {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.fingerprint, s.comparison = d.KeyFingerprint, d.ComparisonCode
				return nil
			},
			Secret: func(context.Context) ([]byte, error) {
				if len(secret) == 0 {
					return nil, errors.New("no fresh secret")
				}
				return append([]byte(nil), secret...), nil
			},
			Notify: func(p enrollmentclient.Progress) error {
				s.mu.Lock()
				defer s.mu.Unlock()
				s.phase = p.Phase
				return nil
			},
		})
		s.mu.Lock()
		switch {
		case err == nil:
			s.phase = "activated"
		case errors.Is(err, enrollmentclient.ErrTerminal):
			s.phase = "terminal"
		case errors.Is(err, context.Canceled):
			s.phase = "stopped"
		default:
			s.phase = "failed"
		}
		s.cancel = nil
		close(done)
		s.mu.Unlock()
	}()
	return nil
}
func (s *clientState) stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
func makeIssuer(now time.Time) (*enrollmentissuer.Issuer, error) {
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	defer clear(rk)
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable browser fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		return nil, e
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		return nil, e
	}
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable browser fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	der, e := x509.CreateCertificate(rand.Reader, intermediate, root, ip, rk)
	if e != nil {
		return nil, e
	}
	fp := sha256.Sum256(der)
	return enrollmentissuer.New(der, rd, ik, hex.EncodeToString(fp[:]), now)
}
func run() error {
	listen := flag.String("listen", "127.0.0.1:19889", "loopback-only fixture")
	stateDir := flag.String("state", "", "disposable state")
	web := flag.String("web", "", "built UI")
	invitationTTL := flag.Int64("invitation-ttl", 120, "test invitation lifetime in seconds")
	pendingTTL := flag.Int64("pending-ttl", 120, "test pending lifetime in seconds")
	enabled := flag.Bool("enabled", true, "configure enrollment in test fixture")
	flag.Parse()
	host, portString, e := net.SplitHostPort(*listen)
	if e != nil || host != "127.0.0.1" || *stateDir == "" || *web == "" {
		return errors.New("invalid fixture")
	}
	port, e := strconv.Atoi(portString)
	if e != nil {
		return e
	}
	issuer, e := makeIssuer(time.Now())
	if e != nil {
		return e
	}
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://" + *listen, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = enrollmentservice.MaxRecords, enrollmentservice.MaxRecords, enrollmentservice.MaxRecords
	cfg.InvitationTTL, cfg.PendingTTL = *invitationTTL, *pendingTTL
	enrolled, e := enrollmentstore.Open(filepath.Join(*stateDir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
	if e != nil {
		return e
	}
	defer enrolled.Close()
	service, e := enrollmentservice.New(enrolled, issuer, nil)
	if e != nil {
		return e
	}
	appStore, e := store.Open(filepath.Join(*stateDir, "app.db"))
	if e != nil {
		return e
	}
	defer appStore.Close()
	app, e := api.New(appStore, port, *web, model.Device{})
	if e != nil {
		return e
	}
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(password), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: 5 * time.Minute})
	if e != nil {
		return e
	}
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IssuerDER()}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}))
	registry, e := lantrust.NewRegistry(context.Background(), []byte(issuerPEM), lantrust.NewMemoryStore())
	if e != nil {
		return e
	}
	operator := api.LANOperatorConfig{Origin: cfg.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Devices: func() ([]model.Device, error) { return service.Devices(context.Background(), time.Now()) }}
	if *enabled {
		operator.Enrollment = service
		operator.EnrollmentBootstrap = api.EnrollmentBootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: cfg.Binding.InstanceID, Profile: "http-test", EnrollmentOrigin: cfg.Binding.Origin, AgentOrigin: "http://127.0.0.1:19890", CollectionProfile: cfg.Binding.CollectionProfile, ServerCAPEM: "", IssuerRootPEM: rootPEM, IssuerPEM: issuerPEM}
	}
	handler, e := api.NewLANOperatorHandler(app, operator)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return e
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	native := &clientState{}
	defer native.stop()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var c command
		if json.Unmarshal(scanner.Bytes(), &c) != nil {
			return errors.New("invalid control")
		}
		ok := true
		switch c.Action {
		case "start", "resume":
			ok = native.start(c, *stateDir) == nil
		case "stop":
			native.stop()
		case "status":
		default:
			ok = false
		}
		native.mu.Lock()
		response := map[string]any{"ok": ok, "phase": native.phase, "keyFingerprint": native.fingerprint, "comparisonCode": native.comparison}
		native.mu.Unlock()
		if encoder.Encode(response) != nil {
			return errors.New("control closed")
		}
	}
	return scanner.Err()
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Disposable enrollment fixture failed.")
		os.Exit(1)
	}
}
