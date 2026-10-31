package main

import (
	"context"
	"crypto/x509"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/managerstatus"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"os"
	"path/filepath"
	"time"
)

type managerDiagnosticSources struct {
	Application                                                        *store.Store
	Trust                                                              *lanstore.Store
	Auth                                                               *operatorauth.Manager
	Linux, Windows, MacOSBasic, MacOSInventory, MacOSInventoryRetained *enrollmentservice.Service
}
type managerDiagnostics struct {
	monitor               *managerstatus.Monitor
	linux, windows, macos *managerstatus.Worker
}

func newManagerDiagnostics(m lanconfig.Material, sources managerDiagnosticSources, now func() time.Time) (*managerDiagnostics, error) {
	if sources.Application == nil || sources.Trust == nil || sources.Auth == nil {
		return nil, errors.New("manager diagnostic sources unavailable")
	}
	if now == nil {
		now = time.Now
	}
	filesystem, err := managerstatus.NewFilesystemProbe(m.Config.StateDirectory)
	if err != nil {
		return nil, err
	}
	applicationProbe, err := protectedManagerStoreProbe(filepath.Join(m.Config.StateDirectory, "operator.db"), sources.Application.ManagerStatus)
	if err != nil {
		return nil, err
	}
	trustProbe, err := protectedManagerStoreProbe(filepath.Join(m.Config.StateDirectory, "agents.db"), sources.Trust.ManagerStatus)
	if err != nil {
		return nil, err
	}
	checks := []managerstatus.Check{
		{Component: managerstatus.AppStorage, Probe: applicationProbe},
		{Component: managerstatus.TrustStorage, Probe: trustProbe},
		{Component: managerstatus.Filesystem, Probe: func(ctx context.Context) managerstatus.ProbeResult {
			if lanstore.CheckRestoreQuarantine(m.Config.StateDirectory) != nil {
				return managerstatus.ProbeResult{State: managerstatus.Invalid}
			}
			return filesystem.Check(ctx)
		}},
		{Component: managerstatus.Authentication, Probe: func(ctx context.Context) managerstatus.ProbeResult {
			if err := ctx.Err(); err != nil {
				return managerstatus.ProbeResult{State: managerstatus.Classify(err)}
			}
			s := sources.Auth.OperationalStats()
			return managerstatus.ProbeResult{State: managerstatus.OK, Capacity: &managerstatus.CapacityMetrics{Used: s.RetainedSessions, Limit: s.SessionLimit, Active: s.ActiveSessions, Terminal: s.RetainedSessions - s.ActiveSessions}, Work: &managerstatus.WorkMetrics{Used: s.HashingUsed, Limit: s.HashingLimit}}
		}},
	}
	if m.Config.Profile == lanconfig.TLS {
		if len(m.Server.Certificate) == 0 {
			return nil, errors.New("manager server certificate unavailable")
		}
		leaf, err := x509.ParseCertificate(m.Server.Certificate[0])
		if err != nil {
			return nil, errors.New("manager server certificate unavailable")
		}
		checks = append(checks, managerstatus.Check{Component: managerstatus.ServerTLS, Probe: func(ctx context.Context) managerstatus.ProbeResult {
			if err := ctx.Err(); err != nil {
				return managerstatus.ProbeResult{State: managerstatus.Classify(err)}
			}
			at := now()
			if at.Before(leaf.NotBefore) {
				return managerstatus.ProbeResult{State: managerstatus.Invalid}
			}
			if !at.Before(leaf.NotAfter) {
				return managerstatus.ProbeResult{State: managerstatus.Expired}
			}
			return managerstatus.ProbeResult{State: managerstatus.OK}
		}})
	}
	d := &managerDiagnostics{}
	for _, source := range []struct {
		component managerstatus.Component
		service   *enrollmentservice.Service
	}{
		{managerstatus.LinuxEnrollment, sources.Linux}, {managerstatus.WindowsEnrollment, sources.Windows}, {managerstatus.MacOSBasicEnrollment, sources.MacOSBasic}, {managerstatus.MacOSInventoryEnrollment, sources.MacOSInventory},
	} {
		if source.service != nil {
			checks = append(checks, managerstatus.Check{Component: source.component, Probe: source.service.ManagerStatus})
		}
	}
	if sources.MacOSInventory == nil && sources.MacOSInventoryRetained != nil {
		checks = append(checks, managerstatus.Check{Component: managerstatus.MacOSInventoryEnrollment, Probe: sources.MacOSInventoryRetained.ManagerStatus})
	}
	if sources.Linux != nil {
		checks = append(checks, managerstatus.Check{Component: managerstatus.Issuer, Probe: sources.Linux.IssuerStatus})
	}
	if sources.Linux != nil && sources.Linux.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileComplete {
		d.linux, err = managerstatus.NewWorker(enrollmentservice.InventoryMaintenanceInterval, now)
		if err != nil {
			return nil, err
		}
		checks = append(checks, managerstatus.Check{Component: managerstatus.InventoryMaintenance, Probe: d.linux.Check})
	}
	if sources.Windows != nil {
		d.windows, err = managerstatus.NewWorker(time.Second, now)
		if err != nil {
			return nil, err
		}
		checks = append(checks, managerstatus.Check{Component: managerstatus.WindowsMaintenance, Probe: d.windows.Check})
	}
	if sources.MacOSInventoryRetained != nil {
		d.macos, err = managerstatus.NewWorker(time.Minute, now)
		if err != nil {
			return nil, err
		}
		checks = append(checks, managerstatus.Check{Component: managerstatus.MacOSInventoryMaintenance, Probe: d.macos.Check})
	}
	d.monitor, err = managerstatus.New(checks, now)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func maintenanceObserver(worker *managerstatus.Worker) enrollmentservice.MaintenanceObserver {
	if worker == nil {
		return enrollmentservice.MaintenanceObserver{}
	}
	return enrollmentservice.MaintenanceObserver{Started: worker.Begin, Completed: func(err error) {
		state := managerstatus.Classify(err)
		if errors.Is(err, enrollmentstore.ErrBusy) || errors.Is(err, enrollmentstore.ErrInventoryBusy) {
			state = managerstatus.Busy
		}
		worker.Complete(state)
	}}
}

// Generic application/trust stores do not retain a path anchor themselves.
// Bind their actual fixed protected runtime files here, before and after each
// cached background read; never repair, chmod or adopt replacement state.
func protectedManagerStoreProbe(path string, probe func(context.Context) managerstatus.ProbeResult) (func(context.Context) managerstatus.ProbeResult, error) {
	if probe == nil || lanstore.ValidateStateFile(path) != nil {
		return nil, errors.New("manager storage path unavailable")
	}
	original, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("manager storage path unavailable")
	}
	current := func() bool {
		if lanstore.ValidateStateFile(path) != nil {
			return false
		}
		info, err := os.Lstat(path)
		return err == nil && os.SameFile(original, info)
	}
	return func(ctx context.Context) managerstatus.ProbeResult {
		if !current() {
			return managerstatus.ProbeResult{State: managerstatus.Invalid}
		}
		result := probe(ctx)
		if !current() {
			return managerstatus.ProbeResult{State: managerstatus.Invalid}
		}
		return result
	}, nil
}
