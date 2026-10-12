//go:build linux

package lanclient

import (
	"crypto/ed25519"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

func TestWindowsUpdateFreshSetupIdentity(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	offer := job.SetupOffer{Version: job.SetupOfferVersion, ManagerID: f.peer.Binding.ManagerID, DeviceID: f.peer.Binding.DeviceID, IncarnationDigest: f.peer.Binding.IncarnationDigest, ManagerOrigin: f.current.config.ManagerOrigin, ManagerPublicKey: f.grant.ManagerPublicKey, ExpiresAt: f.now.Unix() + 300}
	check := func(o job.SetupOffer, now time.Time) error {
		_, e := windowsUpdateSetupIdentity(f.material.configPath, f.current, o, now)
		return e
	}
	if e := check(offer, f.now); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"manager", "device", "anchor", "origin", "key-reuse", "expiry", "leaf-expiry"} {
		t.Run(name, func(t *testing.T) {
			o := offer
			now := f.now
			switch name {
			case "manager":
				o.ManagerID = "manager_ffffffffffffffffffffffffffffffff"
			case "device":
				o.DeviceID = "agent_11111111111111111111111111111111"
			case "anchor":
				o.IncarnationDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			case "origin":
				o.ManagerOrigin = "https://other.invalid"
			case "key-reuse":
				o.ManagerPublicKey = f.material.key.Public().(ed25519.PublicKey)
			case "expiry":
				now = time.Unix(o.ExpiresAt, 0)
			case "leaf-expiry":
				now = time.Unix(f.current.renewal.Intent.NotAfter, 0)
			}
			if check(o, now) == nil {
				t.Fatal("mismatched authority admitted")
			}
		})
	}
}
