package windowsmanagedmsimanager

import (
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentstore"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedFleetSetupUsesFreshPathsAndExactRegistry(t *testing.T) {
	state, _ := protectedSpoolFixture(t)
	m, _, _, _, _ := managerFixture(t)
	p := SetupPlan{Version: FleetSetupPlanVersion, StateDirectory: state, Request: SetupRequest{Fleet: true, DeviceID: m.binding.DeviceID}}
	if setupPlanKey(p) != fleetPath(state, "manager.key") || SetupPlanLANPath(p) != fleetDevicePath(state, m.binding.DeviceID, "lan.json") || setupPlanPath(p, "offer.json") == SetupOfferPath(state) {
		t.Fatal("fleet aliases legacy paths")
	}
	c := Config{Version: FleetConfigVersion, Enabled: true, Binding: m.binding, StateDirectory: state, PrivateKeyFile: setupPlanKey(p), SetupReceiptFile: setupPlanPath(p, "complete.json"), SetupPlanDigest: msi.Digest([]byte("review")), SetupRegistrationDigest: msi.Digest([]byte("registration"))}
	if !validFleetConfig(c) || validConfig(c) {
		t.Fatal("fleet promoted singleton configuration")
	}
	if e := createSetupDirectory(setupPlanPath(p, "")); e != nil {
		t.Fatal(e)
	}
	write := func(path string, v any) {
		t.Helper()
		raw, _ := json.Marshal(v)
		if e := createSetupFile(path, raw); e != nil {
			t.Fatal(e)
		}
	}
	raw, _ := json.Marshal(c)
	write(setupPlanPath(p, "manager.json"), c)
	write(c.SetupReceiptFile, setupComplete{FleetSetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, msi.Digest(raw)})
	registry := RegistryConfig{Version: RegistryVersion, Enabled: true, ManagerID: m.binding.ManagerID, ConfigFiles: []string{setupPlanPath(p, "manager.json")}}
	path := filepath.Join(state, "registry.json")
	write(path, registry)
	if _, configs, _, e := readFleetRegistry(path, state, 25); e != nil || len(configs) != 1 {
		t.Fatal("exact fleet registry", e)
	}
	for _, mutate := range []func(*RegistryConfig){func(r *RegistryConfig) { r.ConfigFiles = append(r.ConfigFiles, r.ConfigFiles[0]) }, func(r *RegistryConfig) { r.ConfigFiles = []string{path} }, func(r *RegistryConfig) { r.ManagerID = "manager_ffffffffffffffffffffffffffffffff" }} {
		changed := registry
		changed.ConfigFiles = append([]string(nil), registry.ConfigFiles...)
		mutate(&changed)
		b, _ := json.Marshal(changed)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		if _, _, _, e := readFleetRegistry(path, state, 25); e == nil {
			t.Fatal("aliased/nested/cross-manager registry admitted")
		}
	}
	p.Request.AdditionalDevice = true
	p.ManagerKeyID = m.binding.KeyID
	material := setupMaterial{plan: p, existing: []Config{c}}
	in := enrollmentstore.WindowsManagedMSISetupInspection{Fleet: true, Status: "fenced", PublicKey: m.key.Public().(ed25519.PublicKey), RegisteredBindings: []msi.Binding{m.binding}, RegisteredDevices: 1}
	if !setupInspectionMatches(material, in) {
		t.Fatal("exact registered roster rejected")
	}
	in.RegisteredBindings[0].InstallGrantID = "grant_ffffffffffffffffffffffffffffffff"
	if setupInspectionMatches(material, in) {
		t.Fatal("changed registered binding accepted")
	}
	in.RegisteredBindings[0] = m.binding
	in.Fleet = false
	if setupInspectionMatches(material, in) {
		t.Fatal("singleton adopted as fleet")
	}
}
