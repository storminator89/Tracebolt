// lan-manager is a separate, explicitly configured single-environment pilot.
// The localhost development manager is never promoted to a LAN listener.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"localrmm/internal/actionmanager"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/analysis"
	"localrmm/internal/api"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxcvefeed"
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
	maintenance           *enrollmentservice.Service
	health                *api.Server
	alarms                *alarmdelivery.Worker
	applicationChecks     *applicationcheck.Monitor
}

func prepare(m lanconfig.Material) (*prepared, error) { return prepareWithEnrollment(m, nil) }
func prepareWithEnrollment(m lanconfig.Material, enrollment *enrollmentconfig.Material) (*prepared, error) {
	return prepareWithAlarms(m, enrollment, alarmdelivery.Config{})
}
func prepareWithAlarms(m lanconfig.Material, enrollment *enrollmentconfig.Material, alarms alarmdelivery.Config) (*prepared, error) {
	return prepareWithApplicationChecks(m, enrollment, alarms, applicationcheck.Config{})
}
func prepareWithApplicationChecks(m lanconfig.Material, enrollment *enrollmentconfig.Material, alarms alarmdelivery.Config, checks applicationcheck.Config) (*prepared, error) {
	managerID := ""
	if enrollment != nil {
		managerID = enrollment.StoreConfig().Binding.InstanceID
	}
	if checks.Enabled() && !checks.Matches(managerID, m.Config.OperatorOrigin, m.Config.Profile) {
		return nil, applicationcheck.ErrConfiguration
	}
	if alarms.Enabled() && (enrollment == nil || enrollment.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || alarms.Binding().ManagerInstanceID != enrollment.StoreConfig().Binding.InstanceID || alarms.Binding().Profile != m.Config.Profile) {
		return nil, alarmdelivery.ErrInvalid
	}
	c := m.Config
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if enrollment != nil && !enrollment.ValidFor(c) {
		return nil, enrollmentconfig.ErrConfiguration
	}
	if enrollment == nil && enrollmentconfig.RejectEnrollmentMode(c.StateDirectory) != nil {
		return nil, enrollmentconfig.ErrConfiguration
	}
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: m.PasswordHash, Operators: m.Operators})
	if e != nil {
		return nil, e
	}
	if e = lanstore.PrepareProfileDirectory(c.StateDirectory, c.Profile); e != nil {
		return nil, e
	}
	trustStore, e := lanstore.Open(filepath.Join(c.StateDirectory, "agents.db"))
	if e != nil {
		return nil, e
	}
	registry, e := lantrust.NewRegistry(context.Background(), m.ClientCA, trustStore)
	if e != nil {
		trustStore.Close()
		return nil, e
	}
	var actions *actionmanager.Manager
	var enrolledStore *enrollmentstore.Store
	var enrolledService *enrollmentservice.Service
	var enrolledIngress *enrollmenttransport.Ingress
	fail := func(err error) (*prepared, error) {
		if actions != nil {
			actions.Close()
		}
		if enrolledStore != nil {
			enrolledStore.Close()
		}
		trustStore.Close()
		return nil, err
	}
	if enrollment != nil {
		if len(registry.List()) != 0 {
			return fail(enrollmentconfig.ErrConfiguration)
		}
		if e = enrollment.PrepareMode(c.StateDirectory, len(registry.List())); e != nil {
			return fail(e)
		}
		enrolledStore, e = enrollmentstore.Open(filepath.Join(c.StateDirectory, enrollmentconfig.DatabaseFile), enrollment.StoreConfig(), enrollment.Issuer().IssuerDER())
		if e != nil {
			return fail(e)
		}
		if enrolledStore.Config().Binding.CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
			if e = enrolledStore.InitializeOverview(context.Background()); e != nil {
				return fail(e)
			}
			if e = enrolledStore.InitializeCompleteUpdates(context.Background()); e != nil {
				return fail(e)
			}
		}
		enrolledService, e = enrollmentservice.New(enrolledStore, enrollment.Issuer(), nil)
		if e != nil {
			return fail(e)
		}
		enrolledIngress, e = enrollmenttransport.New(enrolledStore, enrollment.Issuer().IssuerDER(), c.AgentOrigin, enrolledService.JournalCache())
		if e != nil {
			return fail(e)
		}
	}
	if c.ServiceActionsConfigFile != "" {
		if enrolledStore == nil || !auth.Named() {
			return fail(actionmanager.ErrConfiguration)
		}
		forbidden := []ed25519.PublicKey{}
		for _, der := range append([][]byte{enrollment.Issuer().IssuerDER(), enrollment.Issuer().RootDER()}, m.Server.Certificate...) {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return fail(actionmanager.ErrConfiguration)
			}
			if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok {
				forbidden = append(forbidden, pub)
			}
		}
		actions, e = actionmanager.Load(context.Background(), enrolledStore, c.ServiceActionsConfigFile, forbidden...)
		if e != nil {
			return fail(e)
		}
		if e = enrolledIngress.ConfigureServiceActions(actions); e != nil {
			return fail(e)
		}
	}
	var operatorTLS, agentTLS *tls.Config
	if c.Profile == lanconfig.TLS {
		if enrolledIngress != nil {
			agentTLS, e = enrolledIngress.TLSConfig(m.Server)
		} else {
			agentTLS, e = registry.TLSConfig(m.Server)
		}
		if e != nil {
			return fail(e)
		}
		operatorTLS = &tls.Config{Certificates: []tls.Certificate{m.Server}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	}
	appPath := filepath.Join(c.StateDirectory, "operator.db")
	if e = lanstore.ValidateStateFile(appPath); e != nil {
		return fail(e)
	}
	appStore, e := store.Open(appPath)
	if e != nil {
		return fail(e)
	}
	var alarmWorker *alarmdelivery.Worker
	var alarmBinding *alarmdelivery.Binding
	if alarms.Enabled() {
		b := alarms.Binding()
		alarmBinding = &b
		transport, err := alarmdelivery.NewWebhook(alarms)
		if err != nil {
			appStore.Close()
			return fail(err)
		}
		alarmWorker, err = alarmdelivery.NewWorker(appStore, b, transport, nil)
		if err != nil {
			appStore.Close()
			return fail(err)
		}
	}
	if e = appStore.ConfigureAlarms(context.Background(), alarmBinding, time.Now().UTC()); e != nil {
		appStore.Close()
		return fail(e)
	}
	var once sync.Once
	var cveCache *linuxcvefeed.Cache
	closeAll := func() {
		once.Do(func() {
			if actions != nil {
				actions.Close()
			}
			if cveCache != nil {
				_ = cveCache.Close()
			}
			appStore.Close()
			trustStore.Close()
			if enrolledStore != nil {
				enrolledStore.Close()
			}
		})
	}
	app, e := api.New(appStore, 8787, c.WebDirectory, model.Device{})
	if e != nil {
		closeAll()
		return nil, e
	}
	var applicationChecks *applicationcheck.Monitor
	if checks.Enabled() {
		applicationChecks = applicationcheck.New(checks)
	}
	operatorConfig := api.LANOperatorConfig{ApplicationChecks: applicationChecks, ServiceActions: actions, Origin: c.OperatorOrigin, Auth: auth, Registry: registry, InsecureHTTPTest: c.Profile == lanconfig.HTTPTest, Devices: func() ([]model.Device, error) {
		return trustStore.Devices(context.Background(), registry.List(), time.Now().UTC())
	}}
	if enrolledService != nil {
		binding := enrolledService.Binding()
		if binding.CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
			cveCache, e = linuxcvefeed.New(filepath.Join(c.StateDirectory, "security-data"))
			if e != nil {
				closeAll()
				return nil, e
			}
			operatorConfig.CVECache = cveCache
		}
		operatorConfig.Enrollment = enrolledService
		operatorConfig.EnrollmentBootstrap = api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: c.OperatorOrigin, AgentOrigin: c.AgentOrigin, CollectionProfile: binding.CollectionProfile, ServerCAPEM: enrollment.ServerCAPEM(), IssuerRootPEM: enrollment.RootPEM(), IssuerPEM: enrollment.IssuerPEM()}
		operatorConfig.Devices = func() ([]model.Device, error) { return enrolledService.Devices(context.Background(), time.Now().UTC()) }
	}
	operator, e := api.NewLANOperatorHandler(app, operatorConfig)
	if e != nil {
		closeAll()
		return nil, e
	}
	var agent http.Handler
	if enrolledIngress != nil {
		agent = enrolledIngress
	} else if c.Profile == lanconfig.TLS {
		agent, e = api.NewLANIngressHandler(registry, trustStore, c.AgentOrigin)
	} else {
		agent, e = api.NewHTTPTestIngressHandler(registry, trustStore, c.AgentOrigin)
	}
	if e != nil {
		closeAll()
		return nil, e
	}
	return &prepared{operator: operator, agent: agent, operatorTLS: operatorTLS, agentTLS: agentTLS, close: closeAll, maintenance: enrolledService, health: app, alarms: alarmWorker, applicationChecks: applicationChecks}, nil
}

func server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: analysis.MaxTimeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
}
func run(ctx context.Context, m lanconfig.Material) error { return runWithEnrollment(ctx, m, nil) }
func runWithEnrollment(ctx context.Context, m lanconfig.Material, enrollment *enrollmentconfig.Material) error {
	return runWithAlarms(ctx, m, enrollment, alarmdelivery.Config{})
}
func runWithAlarms(ctx context.Context, m lanconfig.Material, enrollment *enrollmentconfig.Material, alarms alarmdelivery.Config) error {
	return runWithApplicationChecks(ctx, m, enrollment, alarms, applicationcheck.Config{})
}
func runWithApplicationChecks(ctx context.Context, m lanconfig.Material, enrollment *enrollmentconfig.Material, alarms alarmdelivery.Config, checks applicationcheck.Config) error {
	p, err := prepareWithApplicationChecks(m, enrollment, alarms, checks)
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
	if p.applicationChecks != nil {
		checksCtx, stopChecks := context.WithCancel(ctx)
		checksDone := make(chan struct{})
		go func() {
			defer close(checksDone)
			if p.applicationChecks.Run(checksCtx) != nil && checksCtx.Err() == nil {
				log.Print("Application checks are unavailable; inspect authenticated application check status.")
			}
		}()
		// Join the in-memory worker before the prepared manager closes its stores.
		defer func() { stopChecks(); <-checksDone }()
	}
	if p.health != nil {
		healthCtx, stopHealth := context.WithCancel(ctx)
		healthDone := make(chan struct{})
		go func() {
			defer close(healthDone)
			_ = p.health.RunHealthMonitor(healthCtx, func() {
				log.Print("Health evaluation is unavailable; existing incident history is preserved.")
			})
		}()
		defer func() { stopHealth(); <-healthDone }()
	}
	if p.alarms != nil {
		alarmCtx, stopAlarms := context.WithCancel(ctx)
		alarmDone := make(chan struct{})
		go func() {
			defer close(alarmDone)
			_ = p.alarms.Run(alarmCtx, func() { log.Print("External alarm delivery is unavailable; inspect authenticated alarm status.") })
		}()
		defer func() { stopAlarms(); <-alarmDone }()
	}
	// Maintenance stops before store closure, including listener/server failures.
	if p.maintenance != nil && p.maintenance.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
		maintenanceCtx, stopMaintenance := context.WithCancel(ctx)
		maintenanceDone := make(chan struct{})
		go func() {
			defer close(maintenanceDone)
			_ = p.maintenance.RunInventoryMaintenance(maintenanceCtx, func() {
				log.Print("Complete inventory maintenance is unavailable; retained observations are preserved.")
			})
		}()
		defer func() { stopMaintenance(); <-maintenanceDone }()
	}
	operators, agents := server(p.operator), server(p.agent)
	results := make(chan error, 2)
	go func() { results <- operators.Serve(operator) }()
	go func() { results <- agents.Serve(agent) }()
	if m.Config.Profile == lanconfig.HTTPTest {
		log.Print("WARNING: UNENCRYPTED LAN TEST. Passwords, sessions and telemetry are exposed. Signed telemetry does not authenticate the server or UI. Use disposable test material.")
	}
	if enrollment != nil {
		log.Print("Tracebolt guided-enrollment LAN pilot started; manual approval is required and no service installation or discovery is performed.")
	} else {
		log.Print("Tracebolt single-environment LAN pilot started with separate operator and agent listeners; manual certificate mode, no discovery or commands.")
	}
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
	enrollmentPath := flag.String("enrollment-config", "", "Optional protected guided-enrollment v2 profile; requires a dedicated preprovided issuer and empty legacy registry")
	alarmPath := flag.String("alarm-config", "", "Optional protected opt-in HTTPS alarm delivery configuration; disabled when omitted")
	applicationChecksPath := flag.String("application-checks-config", "", "Optional protected opt-in manager-origin application check configuration; disabled when omitted")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		log.Fatal("Tracebolt LAN manager requires --lan-config PATH")
	}
	material, err := lanconfig.Load(*path)
	if err != nil {
		log.Fatal("Tracebolt LAN configuration rejected; verify profile, file ownership, TLS identity and protected material")
	}
	var enrollment *enrollmentconfig.Material
	if *enrollmentPath != "" {
		loaded, e := enrollmentconfig.Load(*enrollmentPath, material, time.Now().UTC())
		if e != nil {
			log.Fatal("Tracebolt enrollment configuration rejected; verify dedicated issuer custody, profile and bootstrap server trust")
		}
		enrollment = &loaded
	}
	managerID := ""
	if enrollment != nil {
		managerID = enrollment.StoreConfig().Binding.InstanceID
	}
	alarms, e := alarmdelivery.Load(*alarmPath, managerID, material.Config.Profile)
	if e != nil {
		log.Fatal("Tracebolt alarm configuration rejected; verify explicit destination, sharing acknowledgement, identity and protected material")
	}
	checks, e := applicationcheck.Load(*applicationChecksPath, managerID, material.Config.OperatorOrigin, material.Config.Profile)
	if e != nil {
		log.Fatal("Tracebolt application check configuration rejected; verify explicit targets, manager-origin acknowledgement, identity and protected material")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if runWithApplicationChecks(ctx, material, enrollment, alarms, checks) != nil {
		log.Fatal("Tracebolt LAN manager failed closed")
	}
}
