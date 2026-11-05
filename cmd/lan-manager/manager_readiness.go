package main

import (
	"context"
	"crypto/x509"
	"errors"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/managerreadiness"
	"localrmm/internal/store"
	"os"
	"path/filepath"
	"time"
)

const managerReadinessBudget = 500 * time.Millisecond

type managerReadinessCheck struct {
	name string
	read func(context.Context) error
}
type managerReadiness struct {
	admission                                        chan struct{}
	checks                                           []managerReadinessCheck
	certificate                                      [][]byte
	issuerDER, rootDER                               []byte
	fingerprint                                      string
	tls                                              bool
	issuerConfigured                                 bool
	now                                              func() time.Time
	linuxInventory, windowsInventory, macosInventory *managerreadiness.Worker
	linuxHealth, windowsHealth                       *managerreadiness.Worker
}

func newManagerReadiness(m lanconfig.Material, enrollment *enrollmentconfig.Material, app *store.Store, trust *lanstore.Store, linux, windows, macos, macosInventory *enrollmentstore.Store) *managerReadiness {
	r := &managerReadiness{admission: make(chan struct{}, 1), tls: m.Config.Profile == lanconfig.TLS, now: time.Now}
	stateDirectory := m.Config.StateDirectory
	r.checks = []managerReadinessCheck{
		{"state_boundary", func(context.Context) error { return lanstore.CheckRestoreQuarantine(stateDirectory) }},
		{"operator_store", protectedReadability(filepath.Join(m.Config.StateDirectory, "operator.db"), app.CheckReadable)},
		{"trust_store", protectedReadability(filepath.Join(m.Config.StateDirectory, "agents.db"), trust.CheckReadable)},
	}
	for _, source := range []struct {
		name  string
		store *enrollmentstore.Store
	}{
		{"linux_enrollment_store", linux}, {"windows_enrollment_store", windows}, {"macos_basic_store", macos}, {"macos_inventory_store", macosInventory},
	} {
		var read func(context.Context) error
		if source.store != nil {
			read = source.store.CheckReadable
		}
		r.checks = append(r.checks, managerReadinessCheck{source.name, read})
	}
	for _, der := range m.Server.Certificate {
		r.certificate = append(r.certificate, append([]byte(nil), der...))
	}
	if enrollment != nil {
		r.issuerConfigured = true
		issuer := enrollment.Issuer()
		r.issuerDER, r.rootDER, r.fingerprint = issuer.IssuerDER(), issuer.RootDER(), issuer.Fingerprint()
		if enrollment.StoreConfig().Binding.CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
			r.linuxInventory = managerreadiness.NewWorker(5 * time.Second)
			r.linuxHealth = managerreadiness.NewWorker(90 * time.Second)
		}
	}
	if windows != nil {
		r.windowsInventory = managerreadiness.NewWorker(5 * time.Second)
		r.windowsHealth = managerreadiness.NewWorker(90 * time.Second)
	}
	if macosInventory != nil {
		r.macosInventory = managerreadiness.NewWorker(2 * time.Minute)
	}
	return r
}

// Capture the already-open file identity without opening, creating or repairing
// any state. Replacing a path cannot make an old live handle appear current.
func protectedReadability(path string, read func(context.Context) error) func(context.Context) error {
	original, initialErr := os.Lstat(path)
	return func(ctx context.Context) error {
		unavailable := errors.New("protected storage read unavailable")
		if initialErr != nil || read == nil || ctx == nil || ctx.Err() != nil {
			return unavailable
		}
		check := func() bool {
			if lanstore.ValidateStateFile(path) != nil {
				return false
			}
			current, err := os.Lstat(path)
			return err == nil && os.SameFile(original, current)
		}
		if !check() || read(ctx) != nil || !check() || ctx.Err() != nil {
			return unavailable
		}
		return nil
	}
}

// Snapshot stays in the admitted HTTP handler. There is no detached probe to
// join on shutdown; request drain keeps the stores/writer lease until it exits.
// Only one probe may occupy real pools, even if a driver overruns cancellation.
func (r *managerReadiness) Snapshot(ctx context.Context) managerreadiness.View {
	if r == nil || ctx == nil {
		return managerreadiness.NewView(time.Now(), nil)
	}
	select {
	case r.admission <- struct{}{}:
		defer func() { <-r.admission }()
	default:
		return managerreadiness.NewView(r.now(), []managerreadiness.Component{{Component: "probe", State: "busy"}})
	}
	step, cancel := context.WithTimeout(ctx, managerReadinessBudget)
	defer cancel()
	components := make([]managerreadiness.Component, 0, len(r.checks)+7)
	for _, check := range r.checks {
		c := managerreadiness.Component{Component: check.name, State: "not_configured"}
		if check.read != nil {
			c.State = "unknown"
			if step.Err() == nil {
				err := check.read(step)
				at := r.now().UTC()
				c.CheckedAt = &at
				c.State = "ready"
				if err != nil {
					c.State = "failed"
				}
				if step.Err() != nil {
					c.State = "timeout"
				}
			}
		}
		components = append(components, c)
	}
	now := r.now().UTC()
	certificate := managerreadiness.Component{Component: "server_certificate", State: "not_configured"}
	if r.tls {
		certificate.State = "failed"
		if len(r.certificate) > 0 {
			certificate.State = "ready"
			for _, der := range r.certificate {
				cert, err := x509.ParseCertificate(der)
				if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
					certificate.State = "failed"
					break
				}
			}
		}
		certificate.CheckedAt = &now
	}
	issuer := managerreadiness.Component{Component: "enrollment_issuer", State: "not_configured"}
	if r.issuerConfigured {
		issuer.State = "failed"
		if enrollmentissuer.ValidatePublicAuthority(r.issuerDER, r.rootDER, r.fingerprint, now) == nil {
			issuer.State = "ready"
		}
		issuer.CheckedAt = &now
	}
	components = append(components, certificate, issuer,
		maintenanceStep(r.linuxInventory, "linux_inventory_step", now), maintenanceStep(r.windowsInventory, "windows_inventory_step", now), maintenanceStep(r.macosInventory, "macos_inventory_step", now),
		r.linuxHealth.Snapshot("linux_health_worker", now), r.windowsHealth.Snapshot("windows_health_worker", now))
	if step.Err() != nil {
		components = append(components, managerreadiness.Component{Component: "probe", State: "timeout"})
	}
	view := managerreadiness.NewView(now, components)
	view.CertificateLifetimes = managerreadiness.CertificateLifetimes(now, r.tls, r.certificate, r.issuerConfigured, r.issuerDER, r.rootDER)
	return view
}

// One round-robin slot does not prove a clean sweep or recovery of another
// previously failing domain. Keep this distinct from a whole evaluation ready.
func maintenanceStep(worker *managerreadiness.Worker, name string, now time.Time) managerreadiness.Component {
	c := worker.Snapshot(name, now)
	if c.State == "ready" {
		c.State = "succeeded"
	}
	return c
}
