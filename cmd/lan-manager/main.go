// lan-manager is a separate, explicitly configured single-environment pilot.
// The localhost development manager is never promoted to a LAN listener.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"localrmm/internal/analysis"
	"localrmm/internal/api"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type prepared struct {
	operator, agent       http.Handler
	operatorTLS, agentTLS *tls.Config
	close                 func()
}

func prepare(m lanconfig.Material) (*prepared, error) {
	c := m.Config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: m.PasswordHash})
	if err != nil {
		return nil, err
	}
	if err = lanstore.PrepareProfileDirectory(c.StateDirectory, c.Profile); err != nil {
		return nil, err
	}
	trustStore, err := lanstore.Open(filepath.Join(c.StateDirectory, "agents.db"))
	if err != nil {
		return nil, err
	}
	registry, err := lantrust.NewRegistry(context.Background(), m.ClientCA, trustStore)
	if err != nil {
		trustStore.Close()
		return nil, err
	}
	var operatorTLS, agentTLS *tls.Config
	if c.Profile == lanconfig.TLS {
		agentTLS, err = registry.TLSConfig(m.Server)
		if err != nil {
			trustStore.Close()
			return nil, err
		}
		operatorTLS = &tls.Config{Certificates: []tls.Certificate{m.Server}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	}
	appPath := filepath.Join(c.StateDirectory, "operator.db")
	if err = lanstore.ValidateStateFile(appPath); err != nil {
		trustStore.Close()
		return nil, err
	}
	appStore, err := store.Open(appPath)
	if err != nil {
		trustStore.Close()
		return nil, err
	}
	var once sync.Once
	closeAll := func() { once.Do(func() { appStore.Close(); trustStore.Close() }) }
	app, err := api.New(appStore, 8787, c.WebDirectory, model.Device{})
	if err != nil {
		closeAll()
		return nil, err
	}
	operator, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: c.OperatorOrigin, Auth: auth, Registry: registry, InsecureHTTPTest: c.Profile == lanconfig.HTTPTest, Devices: func() ([]model.Device, error) {
		return trustStore.Devices(context.Background(), registry.List(), time.Now().UTC())
	}})
	if err != nil {
		closeAll()
		return nil, err
	}
	var agent http.Handler
	if c.Profile == lanconfig.TLS {
		agent, err = api.NewLANIngressHandler(registry, trustStore, c.AgentOrigin)
	} else {
		agent, err = api.NewHTTPTestIngressHandler(registry, trustStore, c.AgentOrigin)
	}
	if err != nil {
		closeAll()
		return nil, err
	}
	return &prepared{operator: operator, agent: agent, operatorTLS: operatorTLS, agentTLS: agentTLS, close: closeAll}, nil
}
func server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: analysis.MaxTimeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
}
func run(ctx context.Context, m lanconfig.Material) error {
	p, err := prepare(m)
	if err != nil {
		return err
	}
	defer p.close()
	operator, err := net.Listen("tcp", m.Config.OperatorListen)
	if err != nil {
		return errors.New("operator listener could not start")
	}
	defer operator.Close()
	agent, err := net.Listen("tcp", m.Config.AgentListen)
	if err != nil {
		return errors.New("agent listener could not start")
	}
	defer agent.Close()
	if p.operatorTLS != nil {
		operator = tls.NewListener(operator, p.operatorTLS)
		agent = tls.NewListener(agent, p.agentTLS)
	}
	operators, agents := server(p.operator), server(p.agent)
	results := make(chan error, 2)
	go func() { results <- operators.Serve(operator) }()
	go func() { results <- agents.Serve(agent) }()
	if m.Config.Profile == lanconfig.HTTPTest {
		log.Print("WARNING: UNENCRYPTED LAN TEST. Passwords, sessions and telemetry are exposed. Signed telemetry does not authenticate the server or UI. Use disposable test material.")
	}
	log.Print("Tracebolt single-environment LAN pilot started with separate operator and agent listeners; no automatic enrollment, discovery or commands.")
	select {
	case <-ctx.Done():
	case err = <-results:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = operators.Shutdown(shutdown)
	_ = agents.Shutdown(shutdown)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
func main() {
	path := flag.String("lan-config", "", "Explicit protected LAN profile JSON (required); HTTPS is the default")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		log.Fatal("Tracebolt LAN manager requires --lan-config PATH")
	}
	material, err := lanconfig.Load(*path)
	if err != nil {
		log.Fatal("Tracebolt LAN configuration rejected; verify profile, file ownership, TLS identity and protected material")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if run(ctx, material) != nil {
		log.Fatal("Tracebolt LAN manager failed closed")
	}
}
