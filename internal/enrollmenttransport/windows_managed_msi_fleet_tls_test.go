package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	manager "localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Source-only protected configs and real SQLite/mTLS. Fixtures do not execute
// the setup CLI, create a native grant/service or install any package.
func TestManagedFleetRegistryLoadAndTLSIdentityRouting(t *testing.T) {
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	second := enrollWindowsUpdateJobObserver(t, f, 2)
	ctx := context.Background()
	mk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	pub := mk.Public().(ed25519.PublicKey)
	dir, e := os.MkdirTemp(".", ".fleet-msi-tls-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	mkdir := func(p string) {
		t.Helper()
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	write := func(p string, v any) {
		t.Helper()
		raw, _ := json.Marshal(v)
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	keyPath := filepath.Join(dir, "windows-managed-msi-fleet", "manager.key")
	mkdir(filepath.Dir(keyPath))
	if e = os.WriteFile(keyPath, mk, 0600); e != nil {
		t.Fatal(e)
	}
	if e = manager.CreateSpool(dir); e != nil {
		t.Fatal(e)
	}
	configs := []string{}
	bindings := []msi.Binding{}
	for i, target := range []*fixture{f, second} {
		executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(92 + i)}, 32)).Public().(ed25519.PublicKey)
		b := msi.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: target.snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + target.cert.CertificateHash(), KeyID: msi.Digest(pub), ExecutorID: id("executor", 81+i), ExecutorKeyID: msi.Digest(executor), DeliveryGrantID: id("grant", 81+i*2), InstallGrantID: id("grant", 82+i*2)}
		g := msi.Grant{Version: msi.GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: f.now.Add(time.Hour).Unix()}
		if e = f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, executor, g, f.now, i > 0); e != nil {
			t.Fatal(e)
		}
		folder := filepath.Join(dir, "windows-managed-msi-fleet-"+b.DeviceID)
		mkdir(folder)
		c := manager.Config{Version: manager.FleetConfigVersion, Enabled: true, Binding: b, StateDirectory: dir, PrivateKeyFile: keyPath, SetupReceiptFile: filepath.Join(folder, "complete.json"), SetupPlanDigest: msi.Digest([]byte("source review")), SetupRegistrationDigest: msi.Digest([]byte("source registration"))}
		raw, _ := json.Marshal(c)
		write(c.SetupReceiptFile, struct {
			Version             string `json:"version"`
			PlanDigest          string `json:"planDigest"`
			RegistrationDigest  string `json:"registrationDigest"`
			ConfigurationDigest string `json:"configurationDigest"`
		}{manager.FleetSetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, msi.Digest(raw)})
		path := filepath.Join(folder, "manager.json")
		write(path, c)
		configs = append(configs, path)
		bindings = append(bindings, b)
	}
	registryPath := filepath.Join(dir, "registry.json")
	config := manager.RegistryConfig{Version: manager.RegistryVersion, Enabled: true, ManagerID: f.config.Binding.InstanceID, ConfigFiles: configs}
	write(registryPath, config)
	registry, e := manager.LoadRegistry(ctx, f.store, registryPath, dir)
	if e != nil {
		t.Fatal("load actual v2 registry:", e)
	}
	defer registry.Close()
	actor := id("operator", 81)
	allowed := func(a string) bool { return a == actor }
	if e = registry.ConfigureOperatorPolicy(allowed, allowed); e != nil {
		t.Fatal(e)
	}
	payload := make([]byte, 1024)
	copy(payload, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	selection := preparedMSITestSelection()
	selection.Size = int64(len(payload))
	selection.SHA256 = msi.Digest(payload)
	artifact := registry.Artifact()
	if e = artifact.ReserveUpload(ctx, actor, selection, msi.Digest([]byte("inert review"))); e != nil {
		t.Fatal(e)
	}
	if e = artifact.Upload(ctx, actor, manager.UploadChunk{PackageDigest: selection.SHA256, Index: 0, Digest: msi.Digest(payload), Data: payload}); e != nil {
		t.Fatal(e)
	}
	if e = artifact.CompleteUpload(ctx, actor); e != nil {
		t.Fatal(e)
	}
	view, e := registry.ArtifactView(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for i, b := range bindings {
		if e = registry.Manager(b.DeviceID).DeliverArtifact(ctx, actor, id("transfer", 81+i), true, view.ArtifactID, msi.BindingDigest(b)); e != nil {
			t.Fatal(e)
		}
	}
	h, server, clientA := f.listen(t, nil)
	if e = h.ConfigureWindowsManagedMSIRegistry(registry); e != nil {
		t.Fatal(e)
	}
	transportB := clientA.Transport.(*http.Transport).Clone()
	transportB.TLSClientConfig = transportB.TLSClientConfig.Clone()
	transportB.TLSClientConfig.Certificates = []tls.Certificate{second.pair}
	defer transportB.CloseIdleConnections()
	clientB := &http.Client{Transport: transportB, Timeout: 5 * time.Second}
	for _, client := range []*http.Client{clientA, clientB} {
		client.Transport.(*http.Transport).DisableCompression = true
	}
	call := func(client *http.Client, op string, in any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(in)
		r, e := http.NewRequest("POST", server.URL+windowsManagedMSIPrefix+op, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, msi.MaxFrameBytes+1))
		if e != nil || response.StatusCode != want {
			t.Fatalf("%s got %d want %d: %s (%v)", op, response.StatusCode, want, body, e)
		}
		return body
	}
	permits := [][]byte{}
	for i, client := range []*http.Client{clientA, clientB} {
		var p msi.PollResponse
		if msi.Canonical(call(client, "poll", struct{}{}, 200), &p, msi.MaxFrameBytes) != nil {
			t.Fatal("poll")
		}
		permit, e := msi.VerifyPermit(p.Permit, pub)
		if e != nil || permit.Binding != bindings[i] {
			t.Fatal("TLS identity routed wrong manager", e)
		}
		permits = append(permits, p.Permit)
	}
	qa := msi.ChunkRequest{TransferID: id("transfer", 81), PermitDigest: msi.Digest(permits[0]), Index: 0}
	qb := msi.ChunkRequest{TransferID: id("transfer", 82), PermitDigest: msi.Digest(permits[1]), Index: 0}
	call(clientA, "chunk", qb, 409)
	call(clientB, "chunk", qa, 409)
	call(clientB, "chunk", qb, 200)
	f.revoke(t)
	call(clientA, "poll", struct{}{}, 403)
	call(clientB, "chunk", qb, 200)
	registry.Close()
	reopened, e := manager.LoadRegistry(ctx, f.store, registryPath, dir)
	if e != nil {
		t.Fatal("revoked member prevented fleet startup", e)
	}
	defer reopened.Close()
	// Missing configured member never silently narrows a registered fleet.
	config.ConfigFiles = config.ConfigFiles[:1]
	write(registryPath, config)
	if _, e = manager.LoadRegistry(ctx, f.store, registryPath, dir); e == nil {
		t.Fatal("partial registry adopted")
	}
}
