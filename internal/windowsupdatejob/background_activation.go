package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
)

const BackgroundActivationVersion = "tracebolt.windows-background-update-manager-activation.v1"
const backgroundActivationDomain = "Tracebolt background WUA manager registration v1\x00"

type BackgroundActivation struct {
	Version            string `json:"version"`
	RegistrationDigest string `json:"registrationDigest"`
	Signature          []byte `json:"signature"`
}

// This proves completed manager registration only. It grants no update selection,
// installation, scheduling, renewed expiry or permission to start the service.
func SignBackgroundActivation(r SetupRegistration, key ed25519.PrivateKey) (BackgroundActivation, error) {
	var a BackgroundActivation
	if r.Validate() != nil || r.Version != BackgroundRegistrationVersion || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) || !bytes.Equal(key.Public().(ed25519.PublicKey), r.Offer.ManagerPublicKey) {
		return a, ErrAuthority
	}
	raw, _ := json.Marshal(r)
	a.Version = BackgroundActivationVersion
	a.RegistrationDigest = actionpermit.Digest(raw)
	a.Signature = ed25519.Sign(key, []byte(backgroundActivationDomain+a.RegistrationDigest))
	return a, nil
}
func (a BackgroundActivation) Verify(r SetupRegistration) error {
	raw, _ := json.Marshal(r)
	if r.Validate() != nil || r.Version != BackgroundRegistrationVersion || a.Version != BackgroundActivationVersion || a.RegistrationDigest != actionpermit.Digest(raw) || !ed25519.Verify(r.Offer.ManagerPublicKey, []byte(backgroundActivationDomain+a.RegistrationDigest), a.Signature) {
		return ErrAuthority
	}
	return nil
}
