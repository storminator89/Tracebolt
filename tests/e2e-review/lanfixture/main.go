// lanfixture runs the real operator HTTP-test handler on loopback for browser QA.
// Its password, CA and awaiting-device row are disposable test material. It is
// not a LAN deployment, enrollment test, production CLI or trusted TLS fixture.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"localrmm/internal/api"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
)

const fixturePassword = "TRACEBOLT_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

func run() error {
	listen := flag.String("listen", "127.0.0.1:19886", "loopback-only test listener")
	db := flag.String("db", "", "disposable test database")
	web := flag.String("web", "", "built UI directory")
	fixture := flag.String("fixture", "", "synthetic awaiting-agent contract JSON")
	ttl := flag.Duration("ttl", time.Minute, "real session expiry for this test")
	flag.Parse()
	host, portText, err := net.SplitHostPort(*listen)
	if err != nil || host != "127.0.0.1" || *db == "" || *web == "" || *fixture == "" {
		return fmt.Errorf("invalid loopback fixture configuration")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*fixture)
	if err != nil {
		return err
	}
	var contract struct {
		Device model.Device `json:"approvedAwaitingObservation"`
	}
	if err = json.Unmarshal(raw, &contract); err != nil {
		return err
	}
	if contract.Device.Source != "lan" || contract.Device.Platform != "unknown" || contract.Device.Name != "Fixture workstation" {
		return fmt.Errorf("unexpected contract fixture")
	}
	state, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer state.Close()
	app, err := api.New(state, port, *web, model.Device{})
	if err != nil {
		return err
	}
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: *ttl})
	if err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral browser-test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return err
	}
	registry, err := lantrust.NewRegistry(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), lantrust.NewMemoryStore())
	if err != nil {
		return err
	}
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: "http://" + *listen, Auth: auth, Registry: registry, InsecureHTTPTest: true, Devices: func() ([]model.Device, error) { return []model.Device{contract.Device}, nil }})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	return server.ListenAndServe()
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Loopback browser fixture failed.")
		os.Exit(1)
	}
}
