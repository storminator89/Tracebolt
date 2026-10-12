package windowsmanagedmsimanager

import (
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"testing"
)

func TestBackgroundPeerCompletionRequiresExactProtectedFiles(t *testing.T) {
	for _, kind := range []string{"missing-config", "missing-receipt", "wrong-receipt", "wrong-registration", "complete"} {
		t.Run(kind, func(t *testing.T) {
			state, _ := protectedSpoolFixture(t)
			m, s, _, _, _ := managerFixture(t)
			g := s.r.Grant
			g.Version, g.ReusableAcknowledged = msi.ReusableGrantVersion, true
			g.MutationPlanDigest, g.PeerBindingDigest = msi.Digest([]byte("paired plan")), msi.Digest([]byte("peer binding"))
			r := msi.SetupRegistration{Version: msi.ReusableRegistrationVersion, Offer: msi.SetupOffer{Version: msi.ReusableOfferVersion, ManagerID: g.Binding.ManagerID, DeviceID: g.Binding.DeviceID, IncarnationDigest: g.Binding.IncarnationDigest, ManagerOrigin: "https://manager.invalid", ManagerPublicKey: s.r.PublicKey, ExpiresAt: g.ExpiresAt}, Grant: g, ExecutorPublicKey: s.r.ExecutorPublicKey}
			if r.Validate() != nil {
				t.Fatal("invalid fixture")
			}
			dir := fleetDevicePath(state, m.binding.DeviceID, "")
			if e := createSetupDirectory(dir); e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(r)
			c := Config{Version: ReusableConfigVersion, Enabled: true, Binding: g.Binding, StateDirectory: state, PrivateKeyFile: fleetPath(state, "manager.key"), SetupReceiptFile: fleetDevicePath(state, m.binding.DeviceID, "complete.json"), SetupPlanDigest: msi.Digest([]byte("setup plan")), SetupRegistrationDigest: msi.Digest(raw)}
			configRaw, _ := json.Marshal(c)
			receipt := setupComplete{ReusableSetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, msi.Digest(configRaw)}
			if kind == "wrong-receipt" {
				receipt.ConfigurationDigest = msi.Digest([]byte("another config"))
			}
			if kind == "wrong-registration" {
				r.Grant.PeerBindingDigest = msi.Digest([]byte("another peer"))
			}
			write := func(name string, v any) {
				t.Helper()
				b, _ := json.Marshal(v)
				if e := createSetupFile(fleetDevicePath(state, m.binding.DeviceID, name), b); e != nil {
					t.Fatal(e)
				}
			}
			write("registration.json", r)
			if kind != "missing-config" {
				write("manager.json", c)
			}
			if kind != "missing-receipt" {
				write("complete.json", receipt)
			}
			got, e := ReadCompletedReusableRegistration(state, m.binding.DeviceID)
			if kind == "complete" {
				if e != nil || !sameJSON(got, r) {
					t.Fatal("completed peer rejected:", e)
				}
			} else if e == nil {
				t.Fatal("incomplete/mismatched finalization accepted")
			}
			if _, e := os.Stat(c.PrivateKeyFile); !os.IsNotExist(e) {
				t.Fatal("fixture unexpectedly has private key")
			}
		})
	}
}
