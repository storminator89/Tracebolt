package windowsmanagedmsi

import (
	"bytes"
	"encoding/json"
	"net/url"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const SetupOfferVersion = "tracebolt.windows-managed-msi-setup-offer.v1"
const SetupRegistrationVersion = "tracebolt.windows-managed-msi-setup-registration.v1"

// SetupOffer is public preparation material, not executor installation consent.
// Its original identity and absolute expiry must survive both create-only halves.
type SetupOffer struct {
	Version           string `json:"version"`
	ManagerID         string `json:"managerId"`
	DeviceID          string `json:"deviceId"`
	IncarnationDigest string `json:"incarnationDigest"`
	ManagerOrigin     string `json:"managerOrigin"`
	ManagerPublicKey  []byte `json:"managerPublicKey"`
	ExpiresAt         int64  `json:"expiresAt"`
}

func (o SetupOffer) Validate() error {
	u, e := url.Parse(o.ManagerOrigin)
	if o.Version != SetupOfferVersion || !enrollmentcrypto.ValidID(o.ManagerID, "manager_") || !enrollmentcrypto.ValidID(o.DeviceID, "agent_") || !actionpermit.ValidDigest(o.IncarnationDigest) || !keyvalidation.Ed25519(o.ManagerPublicKey) || !ValidTime(o.ExpiresAt) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != o.ManagerOrigin {
		return ErrInvalid
	}
	return nil
}

// SetupRegistration contains no private material. It is emitted only after local
// protected setup completes; manager activation still needs its own approval.
type SetupRegistration struct {
	Version           string     `json:"version"`
	Offer             SetupOffer `json:"offer"`
	Grant             Grant      `json:"grant"`
	ExecutorPublicKey []byte     `json:"executorPublicKey"`
}

func (r SetupRegistration) Validate() error {
	b := r.Grant.Binding
	if r.Version != SetupRegistrationVersion || r.Offer.Validate() != nil || r.Grant.Validate() != nil || !r.Grant.DeliveryEnabled || !r.Grant.DeliveryAcknowledged || !r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged || !r.Grant.ServiceRiskAcknowledged || r.Grant.ExpiresAt != r.Offer.ExpiresAt || b.ManagerID != r.Offer.ManagerID || b.DeviceID != r.Offer.DeviceID || b.IncarnationDigest != r.Offer.IncarnationDigest || b.KeyID != actionpermit.Digest(r.Offer.ManagerPublicKey) || !keyvalidation.Ed25519(r.ExecutorPublicKey) || b.ExecutorKeyID != actionpermit.Digest(r.ExecutorPublicKey) {
		return ErrInvalid
	}
	return nil
}
func DecodeSetupOffer(raw []byte) (SetupOffer, error) {
	var o SetupOffer
	if canonicalSetup(raw, &o) != nil || o.Validate() != nil {
		return SetupOffer{}, ErrInvalid
	}
	return o, nil
}
func DecodeSetupRegistration(raw []byte) (SetupRegistration, error) {
	var r SetupRegistration
	if canonicalSetup(raw, &r) != nil || r.Validate() != nil {
		return SetupRegistration{}, ErrInvalid
	}
	return r, nil
}
func canonicalSetup(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > 16384 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
