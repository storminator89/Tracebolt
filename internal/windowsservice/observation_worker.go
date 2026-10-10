package windowsservice

import "context"

// ObservationWorkerIdentity is a read-only binding for a child of the running
// restricted service. ParentProcessID is obtained from SCM, never from IPC. It
// is deliberately not the child PID. Callers compare the entire binding before
// and after a bounded isolated observation, so a replaced service is rejected.
type ObservationWorkerIdentity struct {
	Layout              Layout
	ParentProcessID     uint32
	ParentCreated       uint64
	ServiceSID          string
	ConfigurationSHA256 string
	ExecutableSHA256    string
}

type observationWorkerProcess struct {
	workerPID, parentPID         uint32
	workerCreated, parentCreated uint64
	parentRunning                bool
}

func validateObservationWorker(ctx context.Context, identity func() error, b backend, executable string, process observationWorkerProcess) (ObservationWorkerIdentity, error) {
	zero := ObservationWorkerIdentity{}
	if ctx == nil || identity == nil || b == nil || process.workerPID == 0 {
		return zero, ErrMismatch
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// A generic LocalService token is insufficient. The native function checks
	// the exact enabled owning service SID and the complete privilege set.
	if err := identity(); err != nil {
		return zero, err
	}
	layout, err := b.Layout()
	if err != nil {
		return zero, err
	}
	service, err := b.Open(readAccess)
	if err != nil {
		return zero, err
	}
	defer service.Close()
	snapshot, err := service.Inspect()
	if err != nil {
		return zero, err
	}
	if snapshot.State != Running || snapshot.ProcessID == 0 || snapshot.ProcessID == process.workerPID || snapshot.ProcessID != process.parentPID || !process.parentRunning || process.parentCreated == 0 || process.workerCreated <= process.parentCreated {
		return zero, ErrMismatch
	}
	digest, err := b.VerifyExecutable(layout)
	if err != nil {
		return zero, err
	}
	// The service's PID came directly from SCM. The reusable validator checks
	// the protected current executable, exact fixed service configuration and
	// ownership marker/hash; it does not claim the child is the SCM process.
	if err = validateRuntimeInstallation(layout, snapshot, executable, digest, snapshot.ProcessID); err != nil {
		return zero, err
	}
	expected, err := b.LookupSID()
	if err != nil || snapshot.ServiceSID != expected {
		return zero, ErrMismatch
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return ObservationWorkerIdentity{layout, snapshot.ProcessID, process.parentCreated, snapshot.ServiceSID, digestConfig(snapshot.Configuration), digest}, nil
}
