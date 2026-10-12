//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"localrmm/internal/windowsmanagedmsimanager"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type managedRefreshPeer struct {
	status    msi.Status
	manager   ed25519.PublicKey
	executor  ed25519.PrivateKey
	now       func() time.Time
	sequences []uint64
}

func (p *managedRefreshPeer) CheckPeer(context.Context, msi.Binding) error { return nil }
func (p *managedRefreshPeer) Status(context.Context) (msi.Status, error)   { return p.status, nil }
func (p *managedRefreshPeer) Chunk(context.Context, msi.Chunk) error       { return msi.ErrInvalid }
func (p *managedRefreshPeer) Accept(_ context.Context, raw []byte) error {
	permit, e := msi.VerifyPermit(raw, p.manager)
	if e != nil || permit.Kind != "readiness" {
		return msi.ErrInvalid
	}
	if len(p.sequences) > 0 && permit.Sequence <= p.sequences[len(p.sequences)-1] {
		return msi.ErrConsumed
	}
	p.sequences = append(p.sequences, permit.Sequence)
	at := p.now().Unix()
	ready := msi.Readiness{Selection: permit.Package, CapturedAt: at, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: permit.MaintenanceUntil}
	report := msi.Report{Version: msi.Version, Kind: "readiness", Binding: permit.Binding, TransferID: permit.TransferID, PermitDigest: msi.Digest(raw), Package: permit.Package, NativeAcceptanceDigest: permit.NativeAcceptanceDigest, CapturedAt: at, Offset: permit.Package.Size, State: "ready", Readiness: &ready}
	p.status.Report, e = msi.SignReport(report, p.executor)
	p.status.PermitDigest = report.PermitDigest
	p.status.State = "ready"
	return e
}

// Real relay and manager with the production enrollment-SQLite transaction
// implementation. Package/native peer bytes remain wholly inert fixtures.
func TestManagedMSIExpiredReadinessReportDoesNotStarveExplicitFreshSequence(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	ctx := enrollmentstore.WithOverviewClock(context.Background(), clock)
	managerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{201}, 32))
	executorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{202}, 32))
	b := msi.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.material.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(f.material), ExecutorID: "executor_" + strings.Repeat("7", 32), ExecutorKeyID: msi.Digest(executorKey.Public().(ed25519.PublicKey)), KeyID: msi.Digest(managerKey.Public().(ed25519.PublicKey)), DeliveryGrantID: "grant_" + strings.Repeat("5", 32), InstallGrantID: "grant_" + strings.Repeat("6", 32)}
	g := msi.Grant{Version: msi.GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: now.Unix() + 3600}
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, managerKey.Public().(ed25519.PublicKey), executorKey.Public().(ed25519.PublicKey), g, now); e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp(".", ".managed-relay-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = windowsmanagedmsimanager.CreateSpool(dir); e != nil {
		t.Fatal(e)
	}
	spool, e := windowsmanagedmsimanager.OpenSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	manager, e := windowsmanagedmsimanager.Open(ctx, f.store, b, managerKey, spool, clock, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(manager.Close)
	actor := "operator_" + strings.Repeat("9", 32)
	if e = manager.ConfigureOperatorPolicy(func(a string) bool { return a == actor }, func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 1024)
	copy(data, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	sel := msi.Selection{SHA256: msi.Digest(data), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Inert refresh fixture", TermsReviewDigest: msi.Digest([]byte("fixture terms")), ReviewReference: "source fixture"}
	if e = manager.ReserveUpload(ctx, actor, sel, msi.Digest([]byte("inert acceptance"))); e != nil {
		t.Fatal(e)
	}
	if e = manager.Upload(ctx, actor, windowsmanagedmsimanager.UploadChunk{PackageDigest: sel.SHA256, Digest: sel.SHA256, Data: data}); e != nil {
		t.Fatal(e)
	}
	if e = manager.CompleteUpload(ctx, actor); e != nil {
		t.Fatal(e)
	}
	transfer := "transfer_" + strings.Repeat("8", 32)
	if e = manager.Deliver(ctx, actor, transfer, true); e != nil {
		t.Fatal(e)
	}
	delivery, e := manager.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	permit, e := msi.VerifyPermit(delivery.Permit, managerKey.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	imported := msi.Report{Version: msi.Version, Kind: "delivery", Binding: b, TransferID: transfer, PermitDigest: msi.Digest(delivery.Permit), Package: sel, NativeAcceptanceDigest: permit.NativeAcceptanceDigest, CapturedAt: now.Unix(), Offset: sel.Size, State: "imported"}
	importedRaw, e := msi.SignReport(imported, executorKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.Report(ctx, importedRaw); e != nil {
		t.Fatal(e)
	}
	peer := &managedRefreshPeer{status: msi.Status{Version: msi.Version, State: "imported", TransferID: transfer, Report: importedRaw}, manager: managerKey.Public().(ed25519.PublicKey), executor: executorKey, now: clock}
	relay := WindowsManagedMSIRelayGrant{Version: WindowsManagedMSIRelayGrantVersion, Scope: WindowsManagedMSIRelayScope, Enabled: true, Acknowledged: true, SenderBinding: f.material.binding, ManagerOrigin: f.material.config.ManagerOrigin, Binding: b, ManagerPublicKey: managerKey.Public().(ed25519.PublicKey), ExecutorPublicKey: executorKey.Public().(ed25519.PublicKey), ExpiresAt: g.ExpiresAt, ExecutorPeer: windowsmanagedmsiipc.PeerConfig{Version: windowsmanagedmsiipc.PeerVersion, Binding: b, ExecutorPublicKey: executorKey.Public().(ed25519.PublicKey), Executable: `C:\Program Files\Tracebolt\deployment.exe`, ExecutableDigest: msi.Digest([]byte("image")), ConfigurationDigest: msi.Digest([]byte("config"))}}
	sender := openWindowsManagedMSISender(f.material)
	t.Cleanup(sender.Close)
	sender.now = clock
	sender.current = func(Material) bool { return true }
	sender.local = func(Material) (WindowsManagedMSIRelayGrant, error) { return relay, nil }
	sender.newPeer = func(windowsmanagedmsiipc.PeerConfig) (managedMSIPeer, error) { return peer, nil }
	rejected, polls := 0, 0
	sender.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		switch path {
		case managedMSIPrefix + "report":
			var q msi.ReportRequest
			if msi.Canonical(raw, &q, msi.MaxFrameBytes) != nil {
				return nil, msi.ErrInvalid
			}
			if e := manager.Report(ctx, q.Report); e != nil {
				rejected++
				return nil, errManagedMSIReportRejected
			}
			return []byte("{}"), nil
		case managedMSIPrefix + "poll":
			polls++
			p, e := manager.Poll(ctx)
			if e != nil {
				return nil, e
			}
			return json.Marshal(p)
		}
		return nil, msi.ErrInvalid
	}
	if e = manager.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal(e)
	}
	if got := sender.Run(ctx); got != "pending" || len(peer.sequences) != 1 {
		t.Fatal("first sequence", got, peer.sequences)
	}
	old := bytes.Clone(peer.status.Report)
	now = now.Add(61 * time.Second)
	prior := polls
	sender.Run(ctx) // First arrival is late: reject it but still perform one poll.
	if rejected != 1 || polls != prior+1 || !bytes.Equal(old, peer.status.Report) {
		t.Fatal("late report blocked normal poll", rejected, polls)
	}
	if e = manager.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal("explicit fresh review", e)
	}
	prior = polls
	if got := sender.Run(ctx); got != "pending" || rejected != 2 || polls != prior+1 || len(peer.sequences) != 2 || peer.sequences[1] != 2 {
		t.Fatal("saved report starved sequence 2", got, rejected, polls, peer.sequences)
	}
	if bytes.Equal(old, peer.status.Report) {
		t.Fatal("fresh challenge was not accepted")
	}
	sender.Run(ctx)
	record, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, b, managerKey.Public().(ed25519.PublicKey))
	if e != nil || !bytes.Equal(record.ReadinessReport, peer.status.Report) || len(record.InstallPermit) != 0 {
		t.Fatal("fresh evidence was not saved separately", e)
	}
	// Transport uncertainty does not use the exception, even for readiness.
	sender.exchange = func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("fixture disconnected") }
	if got := sender.Run(ctx); got != "pending" || len(peer.sequences) != 2 {
		t.Fatal("uncertainty advanced", got)
	}
}
