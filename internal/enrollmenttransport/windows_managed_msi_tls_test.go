package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real loopback mTLS production-ingress fixture, with inert compound-signature
// bytes and synthetic executor reports. It never opens a native installer,
// creates a host grant, starts an agent or selects a real software package.
func TestManagedMSIRealTLSIngressExactDeliveryReviewInstallReceipt(t *testing.T) {
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	managerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
	actor := id("operator", 81)
	transfer := id("transfer", 81)
	binding := msi.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + f.cert.CertificateHash(), ExecutorID: id("executor", 81), ExecutorKeyID: msi.Digest(executor.Public().(ed25519.PublicKey)), KeyID: msi.Digest(managerKey.Public().(ed25519.PublicKey)), DeliveryGrantID: id("grant", 81), InstallGrantID: id("grant", 82)}
	grant := msi.Grant{Version: msi.GrantVersion, Binding: binding, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: f.now.Add(time.Hour).Unix()}
	ctx := context.Background()
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, managerKey.Public().(ed25519.PublicKey), executor.Public().(ed25519.PublicKey), grant, f.now); e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp(".", ".managed-msi-tls-source-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = windowsmanagedmsimanager.CreateSpool(dir); e != nil {
		t.Fatal("protected source fixture spool", e)
	}
	spool, e := windowsmanagedmsimanager.OpenSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	manager, e := windowsmanagedmsimanager.Open(ctx, f.store, binding, managerKey, spool, func() time.Time { return f.now }, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer manager.Close()
	if e = manager.ConfigureOperatorPolicy(func(a string) bool { return a == actor }, func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, msi.MaxChunkBytes+512)
	copy(data, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	selection := preparedMSITestSelection()
	selection.Size = int64(len(data))
	selection.SHA256 = msi.Digest(data)
	native := msi.Digest([]byte("synthetic native acceptance fixture"))
	if e = manager.ReserveUpload(ctx, actor, selection, native); e != nil {
		t.Fatal(e)
	}
	for at := 0; at < len(data); at += msi.MaxChunkBytes {
		chunk := data[at:min(at+msi.MaxChunkBytes, len(data))]
		q := windowsmanagedmsimanager.UploadChunk{PackageDigest: selection.SHA256, Index: uint32(at / msi.MaxChunkBytes), Digest: msi.Digest(chunk), Data: chunk}
		if e = manager.Upload(ctx, actor, q); e != nil {
			t.Fatal(e)
		}
		if e = manager.Upload(ctx, actor, q); e != nil {
			t.Fatal("identical acknowledged chunk", e)
		}
	}
	if e = manager.CompleteUpload(ctx, actor); e != nil {
		t.Fatal(e)
	}
	h, server, client := f.listen(t, nil)
	h.now = func() time.Time { return f.now }
	client.Transport.(*http.Transport).DisableCompression = true
	if e = h.ConfigureWindowsManagedMSI(manager); e != nil {
		t.Fatal(e)
	}
	call := func(op string, value any, want int) []byte {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if len(raw) > msi.MaxFrameBytes {
			t.Fatal("oversized request")
		}
		req, e := http.NewRequest("POST", server.URL+windowsManagedMSIPrefix+op, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		out, e := io.ReadAll(io.LimitReader(res.Body, msi.MaxFrameBytes+1))
		if e != nil || len(out) > msi.MaxFrameBytes || res.StatusCode != want {
			t.Fatalf("%s: %d want %d %s %v", op, res.StatusCode, want, out, e)
		}
		if res.Header.Get("Content-Encoding") != "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("private canonical response changed")
		}
		return out
	}
	poll := func() []byte {
		raw := call("poll", struct{}{}, 200)
		var out msi.PollResponse
		if msi.Canonical(raw, &out, msi.MaxFrameBytes) != nil {
			t.Fatal("noncanonical poll")
		}
		return out.Permit
	}
	if len(poll()) != 0 {
		t.Fatal("upload granted delivery")
	}
	if e = manager.Deliver(ctx, actor, transfer, true); e != nil {
		t.Fatal(e)
	}
	delivery := poll()
	if len(delivery) == 0 || !bytes.Equal(delivery, poll()) {
		t.Fatal("delivery resume changed permit")
	}
	permit, e := msi.VerifyPermit(delivery, managerKey.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	var received []byte
	for index := uint32(0); int64(index)*msi.MaxChunkBytes < selection.Size; index++ {
		q := msi.ChunkRequest{TransferID: transfer, Index: index, PermitDigest: msi.Digest(delivery)}
		raw := call("chunk", q, 200)
		var out msi.Chunk
		if msi.Canonical(raw, &out, msi.MaxFrameBytes) != nil || out.Validate(permit) != nil {
			t.Fatal("invalid bounded chunk")
		}
		received = append(received, out.Data...)
	}
	if !bytes.Equal(received, data) {
		t.Fatal("changed exact artifact bytes")
	}
	report := msi.Report{Version: msi.Version, Kind: "delivery", Binding: binding, TransferID: transfer, PermitDigest: msi.Digest(delivery), Package: selection, NativeAcceptanceDigest: native, CapturedAt: f.now.Unix(), Offset: selection.Size, State: "imported"}
	send := func() {
		raw, e := msi.SignReport(report, executor)
		if e != nil {
			t.Fatal(e)
		}
		call("report", msi.ReportRequest{Report: raw}, 200)
	}
	send()
	if len(poll()) != 0 {
		t.Fatal("import granted installation")
	}
	if e = manager.Review(ctx, actor, true, true, true); e != nil {
		t.Fatal(e)
	}
	readinessPermit := poll()
	if len(readinessPermit) == 0 || len(poll()) != 0 {
		t.Fatal("readiness claim replay")
	}
	p, e := msi.VerifyPermit(readinessPermit, managerKey.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	ready := msi.Readiness{Selection: selection, CapturedAt: f.now.Unix(), PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: p.MaintenanceUntil}
	report.Kind = "readiness"
	report.PermitDigest = msi.Digest(readinessPermit)
	report.State = "ready"
	report.Readiness = &ready
	send()
	v, e := manager.View(ctx)
	if e != nil || v.State != "ready" {
		t.Fatal(e)
	}
	if e = manager.Approve(ctx, actor, v.ReadinessDigest, true); e != nil {
		t.Fatal(e)
	}
	install := poll()
	if len(install) == 0 || len(poll()) != 0 {
		t.Fatal("install claim replay")
	}
	result := msi.Result{ReturnCodeKnown: true, JobID: "software_" + strings.TrimPrefix(transfer, "transfer_"), EnvelopeDigest: msi.Digest(install), Attempted: true, Outcome: "restart_required", ReturnCode: 3010, RegistrationVerified: msi.Unknown, CompletedAt: f.now.Unix()}
	report.Kind = "result"
	report.PermitDigest = result.EnvelopeDigest
	report.Readiness = nil
	report.Result = &result
	report.State = result.Outcome
	send()
	send()
	v, e = manager.View(ctx)
	if e != nil || v.State != "complete" || v.Result.ReturnCode != 3010 || v.Result.RegistrationVerified != msi.Unknown {
		t.Fatal("durable result truth", e)
	}
	f.revoke(t)
	call("poll", struct{}{}, 403)
}
