package windowsmanagedmsimanager

import (
	"bytes"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"testing"
)

func TestScheduledMSICompletedRegistrationPinsExactProfile(t *testing.T) {
	for _, kind := range []string{"complete", "old-registry", "old-config", "old-receipt", "old-offer", "changed-grant"} {
		t.Run(kind, func(t *testing.T) {
			state, _ := protectedSpoolFixture(t)
			m, s, _, _, _ := managerFixture(t)
			g := s.r.Grant
			g.Version = msi.ScheduledGrantVersion
			g.ReusableAcknowledged = true
			g.ScheduledEnabled = true
			g.ScheduledAcknowledged = true
			g.MutationPlanDigest = msi.Digest([]byte("paired plan"))
			g.PeerBindingDigest = msi.Digest([]byte("peer"))
			r := msi.SetupRegistration{Version: msi.ScheduledRegistrationVersion, Offer: msi.SetupOffer{Version: msi.ScheduledOfferVersion, ManagerID: g.Binding.ManagerID, DeviceID: g.Binding.DeviceID, IncarnationDigest: g.Binding.IncarnationDigest, ManagerOrigin: "https://manager.invalid", ManagerPublicKey: s.r.PublicKey, ExpiresAt: g.ExpiresAt}, Grant: g, ExecutorPublicKey: s.r.ExecutorPublicKey}
			if r.Validate() != nil {
				t.Fatal("invalid fixture")
			}
			if e := createSetupDirectory(fleetDevicePath(state, m.binding.DeviceID, "")); e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(r)
			c := Config{Version: ScheduledConfigVersion, Enabled: true, Binding: g.Binding, StateDirectory: state, PrivateKeyFile: fleetPath(state, "manager.key"), SetupReceiptFile: fleetDevicePath(state, m.binding.DeviceID, "complete.json"), SetupPlanDigest: msi.Digest([]byte("review")), SetupRegistrationDigest: msi.Digest(raw)}
			if kind == "old-config" {
				c.Version = ReusableConfigVersion
			}
			configRaw, _ := json.Marshal(c)
			receipt := setupComplete{ScheduledSetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, msi.Digest(configRaw)}
			if kind == "old-receipt" {
				receipt.Version = ReusableSetupPlanVersion
			}
			if kind == "changed-grant" {
				r.Grant.ExpiresAt--
				r.Offer.ExpiresAt--
			}
			if kind == "old-offer" {
				r.Offer.Version = msi.ReusableOfferVersion
			}
			write := func(path string, v any) {
				t.Helper()
				b, _ := json.Marshal(v)
				if e := createSetupFile(path, b); e != nil {
					t.Fatal(e)
				}
			}
			write(fleetDevicePath(state, m.binding.DeviceID, "registration.json"), r)
			write(fleetDevicePath(state, m.binding.DeviceID, "manager.json"), c)
			write(c.SetupReceiptFile, receipt)
			registry := RegistryConfig{Version: ScheduledRegistryVersion, Enabled: true, ManagerID: g.Binding.ManagerID, ConfigFiles: []string{fleetDevicePath(state, m.binding.DeviceID, "manager.json")}}
			if kind == "old-registry" {
				registry.Version = ReusableRegistryVersion
			}
			path := filepath.Join(state, "registry.json")
			write(path, registry)
			_, _, _, registryErr := readFleetRegistry(path, state, 25)
			got, e := ReadCompletedReusableRegistration(state, m.binding.DeviceID)
			if kind == "complete" {
				if e != nil || registryErr != nil || !sameJSON(got, r) {
					t.Fatal("fresh scheduled completion rejected", e, registryErr)
				}
			} else if kind == "old-registry" {
				if registryErr == nil {
					t.Fatal("old registry promoted scheduled config")
				}
			} else if e == nil {
				t.Fatal("changed completion accepted")
			}
			if _, e := os.Stat(c.PrivateKeyFile); !os.IsNotExist(e) {
				t.Fatal("fixture unexpectedly has private key")
			}
		})
	}
}

func TestScheduledManagerPlanKeepsOldRequestBytes(t *testing.T) {
	q := SetupRequest{Reusable: true, Fleet: true, Phase: "prepare", LANConfig: "/inert/lan", EnrollmentConfig: "/inert/enroll", DeviceID: "agent_11111111111111111111111111111111", ExpiresAt: 1800003600}
	raw, _ := json.Marshal(q)
	if bytes.Contains(raw, []byte("scheduled")) {
		t.Fatal("old request changed")
	}
	p := SetupPlan{Version: ReusableSetupPlanVersion, Request: q}
	before := p.digest()
	p.Request.Scheduled = true
	p.Version = ScheduledSetupPlanVersion
	if p.digest() == before || setupRegistryVersion(p.Request) != ScheduledRegistryVersion {
		t.Fatal("fresh schedule profile not bound in plan")
	}
	p.ScheduleOperators = []string{"operator_11111111111111111111111111111111"}
	d := p.digest()
	p.ScheduleOperators[0] = "operator_22222222222222222222222222222222"
	if p.digest() == d {
		t.Fatal("named scheduler not pinned")
	}
}
