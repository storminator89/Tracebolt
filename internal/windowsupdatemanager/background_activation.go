package windowsupdatemanager

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/lanconfig"
	msimanager "localrmm/internal/windowsmanagedmsimanager"
	job "localrmm/internal/windowsupdatejob"
	"time"
)

// ExportBackgroundActivation exports only after both exact durable manager
// registrations and their protected setup completion/configuration proofs.
// It may be repeated after a lost public output; no setup mutation or rekey occurs.
func ExportBackgroundActivation(p SetupPlan) (job.BackgroundActivation, error) {
	var zero job.BackgroundActivation
	if p.Digest != p.digest() || p.Request.Phase != "finalize" || p.Registration == nil || p.Registration.Version != job.BackgroundRegistrationVersion {
		return zero, ErrSetup
	}
	var saved job.SetupRegistration
	raw, e := canonicalRead(setupPlanPath(p, "registration.json"), &saved)
	if e != nil || !sameJSON(saved, p.Registration) || actionpermit.Digest(raw) != p.RegistrationDigest {
		return zero, ErrSetup
	}
	var receipt setupComplete
	if _, e = canonicalRead(setupPlanPath(p, "complete.json"), &receipt); e != nil || receipt.PlanDigest != p.Digest || receipt.RegistrationDigest != p.RegistrationDigest {
		return zero, ErrSetup
	}
	var c Config
	configRaw, e := canonicalRead(setupPlanPath(p, "manager.json"), &c)
	if e != nil || !validConfig(c) || c.Binding != saved.Consent.Binding || actionpermit.Digest(configRaw) != receipt.ConfigurationDigest {
		return zero, ErrSetup
	}
	peer, e := msimanager.ReadCompletedReusableRegistration(p.StateDirectory, saved.Consent.Binding.DeviceID)
	if e != nil || peer.Grant.MutationPlanDigest != saved.Consent.MutationPlanDigest || peer.Grant.Binding.ManagerID != saved.Consent.Binding.ManagerID || peer.Grant.Binding.IncarnationDigest != saved.Consent.Binding.IncarnationDigest || peer.Offer.ManagerOrigin != saved.Offer.ManagerOrigin {
		return zero, ErrSetup
	}
	mb, _ := json.Marshal(peer.Grant.Binding)
	wb, _ := json.Marshal(saved.Consent.Binding)
	if saved.Consent.PeerBindingDigest != actionpermit.Digest(mb) || peer.Grant.PeerBindingDigest != actionpermit.Digest(wb) {
		return zero, ErrSetup
	}
	key, e := lanconfig.ReadProtected(setupPlanKey(p), true, 4096)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key[32:], saved.Offer.ManagerPublicKey) {
		return zero, ErrSetup
	}
	a, e := job.SignBackgroundActivation(saved, ed25519.PrivateKey(key))
	now := time.Now().UTC().Unix()
	if e != nil || now <= 0 || now >= saved.Consent.ExpiresAt || now >= p.CurrentLeafNotAfter {
		return zero, ErrSetup
	}
	return a, nil
}
