package enrollmentservice

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"testing"
	"time"
)

// Invented values exercise the manager's actual validated store and dashboard
// projection. No native collector, host identity, service or credential is used.
// The wire's synthetic flag must be false because its schema accepts real-style
// local observations only; that does not turn this fixture into native evidence.
func windowsDashboardFrame(platform string, sequence uint64, at time.Time) lanstore.Frame {
	memory, disk := 41.5, 24.25
	unknown := model.Metric{Unit: "%", Quality: "unknown", Source: "Invented unavailable CPU fixture", CollectedAt: at}
	d := model.Device{
		ID: "local-windows", Name: "Local Windows", Platform: platform, OS: "Invented Windows fixture",
		Site: "Local machine", Group: "Local observations", Status: "unknown", Source: "local",
		LastSeen: at, AgentVersion: "test", CPU: unknown,
		Memory: model.Metric{Value: &memory, Unit: "%", Quality: "healthy", Source: "Invented RAM utilization fixture", CollectedAt: at},
		Disk:   model.Metric{Value: &disk, Unit: "%", Quality: "healthy", Source: "Invented disk utilization fixture", CollectedAt: at},
		Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{},
	}
	if platform == "linux" {
		d.ID, d.Name, d.Source, d.Site, d.OS = "sandbox-local", "Local sandbox", "sandbox", "Cloud sandbox", "Invented Linux fixture"
	}
	b := bundle.Bundle{
		SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at,
		Platform: platform, Architecture: "amd64", Scope: "single-read-only-local-observation",
		Validation: bundle.Validation{PlatformExecution: "Invented test data; no collector invoked", Acceptance: "No native platform acceptance"},
		Privacy:    []string{}, Observation: d,
	}
	return lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: sequence, Observation: b}
}

func marshalWindowsDashboardFrame(t *testing.T, frame lanstore.Frame, at time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal("fixture encoding failed", err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal("fixture must be schema-valid before identity admission", err)
	}
	return raw
}

func assertWindowsBasicTelemetry(t *testing.T, f *fixture, active enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	ctx := context.Background()
	at := f.now
	views, err := f.store.DeviceViews(ctx)
	if err != nil || len(views) != 1 || views[0].Snapshot != active || views[0].Snapshot.Platform != "windows" || views[0].Observation != nil {
		t.Fatal("activated Windows identity must remain unobserved before telemetry", err)
	}
	// This local certificate lookup is not a simulated TLS handshake. It uses
	// the synthetic issued certificate, then the real atomic telemetry ingress.
	authorized, err := f.store.AuthorizeCertificate(ctx, cert.DER(), at)
	if err != nil || authorized != active {
		t.Fatal("fixture certificate is not bound to the activated Windows identity", err)
	}
	first := marshalWindowsDashboardFrame(t, windowsDashboardFrame("windows", 1, at), at)
	receipt, err := f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), first, at)
	if err != nil || receipt.AgentID != active.Approval.DeviceID || receipt.Sequence != 1 || receipt.Duplicate || !receipt.ReceivedAt.Equal(at) || !receipt.CollectedAt.Equal(at) {
		t.Fatal("Windows basic observation was not committed", err)
	}
	assertWindowsBasicDeviceView(t, f, active, receipt)

	later := at.Add(time.Second)
	for _, kind := range []string{"wrong-platform-basic", "managed-linux"} {
		frame := windowsDashboardFrame("linux", 2, later)
		if kind == "managed-linux" {
			op := operational.Empty(later, operational.ReasonNotImplemented)
			frame.SchemaVersion, frame.Operational = lanstore.FrameOperationalVersion, &op
		}
		raw := marshalWindowsDashboardFrame(t, frame, later)
		if _, err = f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), raw, later); !errors.Is(err, enrollmentstate.ErrProof) {
			t.Fatalf("%s frame crossed the Windows basic identity boundary: %v", kind, err)
		}
		assertWindowsBasicDeviceView(t, f, active, receipt)
	}
	// Reopen proves that the dashboard result and original receipt came from
	// durable accepted telemetry, not a transient view or a rejected frame.
	f.restart(t)
	assertWindowsBasicDeviceView(t, f, active, receipt)
	retry, err := f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), first, later)
	if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(at) || retry.Sequence != 1 {
		t.Fatal("exact Windows retry changed its original receipt", err)
	}
	f.now = later
	next := marshalWindowsDashboardFrame(t, windowsDashboardFrame("windows", 2, later), later)
	receipt, err = f.store.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), next, later)
	if err != nil || receipt.Sequence != 2 || receipt.Duplicate {
		t.Fatal("rejected cross-platform/profile frames consumed the next sequence", err)
	}
	assertWindowsBasicDeviceView(t, f, active, receipt)
	devices, err := f.service.Devices(ctx, later.Add(3*time.Minute))
	if err != nil || len(devices) != 1 || devices[0].Memory.Quality != "stale" || devices[0].Disk.Quality != "stale" || devices[0].CPU.Quality != "unknown" || devices[0].Status != "unknown" {
		t.Fatal("Windows dashboard lost stale/unknown distinctions", err)
	}
}

func assertWindowsBasicDeviceView(t *testing.T, f *fixture, active enrollmentstate.Snapshot, receipt lanstore.Receipt) {
	t.Helper()
	ctx := context.Background()
	views, err := f.store.DeviceViews(ctx)
	if err != nil || len(views) != 1 || views[0].Snapshot != active || views[0].Observation == nil {
		t.Fatal("accepted Windows observation missing from approved device view", err)
	}
	observation := views[0].Observation
	if observation.Receipt != receipt || observation.State != enrollmentstate.Activated {
		t.Fatal("dashboard read changed accepted receipt or activation state")
	}
	check := func(d model.Device) {
		t.Helper()
		if d.ID != active.Approval.DeviceID || d.Name != d.ID || d.Platform != "windows" || d.OS != "Invented Windows fixture" || d.Source != "lan" || d.Status != "unknown" || d.IP != nil || !d.LastSeen.Equal(receipt.CollectedAt) {
			t.Fatal("Windows telemetry lost approved identity/platform/provenance binding")
		}
		if d.Memory.Value == nil || *d.Memory.Value != 41.5 || d.Memory.Quality != "healthy" || !d.Memory.CollectedAt.Equal(receipt.CollectedAt) || d.Disk.Value == nil || *d.Disk.Value != 24.25 || d.Disk.Quality != "healthy" || !d.Disk.CollectedAt.Equal(receipt.CollectedAt) || d.CPU.Value != nil || d.CPU.Quality != "unknown" {
			t.Fatal("Windows RAM/disk values or unknown CPU were changed")
		}
	}
	check(observation.Device)
	devices, err := f.service.Devices(ctx, receipt.ReceivedAt)
	if err != nil || len(devices) != 1 {
		t.Fatal("operator dashboard projection missing", err)
	}
	check(devices[0])
	if len(devices[0].Capabilities) != 1 || devices[0].Capabilities[0].ID != "agent_identity" || devices[0].Capabilities[0].Status != "supported" {
		t.Fatal("basic Windows observation gained managed Linux capabilities")
	}
}
