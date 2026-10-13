// Package macosinventorysender is an inactive, guarded sender integration seam.
// No command, service, enrollment initializer or renewal scheduler selects it.
package macosinventorysender

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"localrmm/internal/lantrust"
	inventory "localrmm/internal/macosinventory"
	wire "localrmm/internal/macosinventorywire"
)

const (
	ControlPath = "/v1/macos/inventory/control"
	ReportPath  = "/v1/macos/inventory/report"
)

var (
	ErrAuthority  = errors.New("macos_inventory_sender_authority_invalid")
	ErrTransport  = errors.New("macos_inventory_sender_delivery_unconfirmed")
	ErrCollection = errors.New("macos_inventory_sender_collection_failed")
	ErrBusy       = errors.New("macos_inventory_sender_busy")
	ErrClosed     = errors.New("macos_inventory_sender_closed")
)

// Authority is a TRUSTED platform integration boundary, not a wire validator.
// Before calling run it must authenticate the protected, activated FRESH macOS
// profile's original enrollment/issuer, explicit local scope approval, original
// enable and unpredictable grant, current credential manifest, and live grant /
// revocation state. It must hold the actual identity/credential admission lease
// until run returns, and invoke run exactly once, synchronously, without retaining
// it. Basic/Linux/Windows grants, unsigned caller data and wire receipts cannot
// implement this authority. No production Authority adapter is supplied yet.
//
// Check must reread current protected approval/credential/revocation authority;
// Exchange must use that SAME current leaf with verified TLS and original exact
// origin, fixed path, JSON content type and body length, bounded 2 KiB receipts,
// no redirect, downgrade, compression, logging or implicit retry. It must honor
// cancellation and join all owned workers before returning. Manager admission
// remains responsible for transaction-time revocation and durable receipts.
//
// These are obligations for the later reviewed enrollment/transport adapter.
// An arbitrary implementation is not made authentic by satisfying this interface.
type Authority interface {
	WithCurrent(context.Context, func(ActiveAuthority) error) error
}
type ActiveAuthority interface {
	Check(time.Time) (Evidence, error)
	Exchange(context.Context, string, []byte) ([]byte, error)
}

// Evidence is public certificate/approval metadata from the authenticated local
// adapter, never a substitute for it. Source bytes, credentials and keys are absent.
// OriginalEnable and Consent must come from protected local approval, not from
// a received control/report. AnchorDER is the immutable original enrollment leaf;
// CurrentDER is the activated transport leaf, never a candidate certificate.
type Evidence struct {
	ManagerOrigin        string
	OriginalEnable       []byte
	Consent              []byte
	AnchorDER            []byte
	CurrentDER           []byte
	IssuerDER            []byte
	CredentialGeneration uint64
}

func (Evidence) String() string               { return "macOS inventory authority (contents redacted)" }
func (e Evidence) Format(f fmt.State, _ rune) { fmt.Fprint(f, e.String()) }
func (Evidence) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// OriginalBinding is deterministic identity metadata, not authentication. The
// manager independently computes this same profile-specific domain from its
// authenticated ORIGINAL enrollment certificate and configured agent origin.
func OriginalBinding(origin, device string, anchor *x509.Certificate) (wire.Binding, error) {
	u, e := url.Parse(origin)
	if e != nil || len(origin) > 512 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || origin != "https://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(origin, "\\%\r\n\t ") || anchor == nil || len(anchor.Raw) == 0 || anchor.Subject.CommonName != device {
		return wire.Binding{}, ErrAuthority
	}
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.macos-inventory.v1\n" + wire.Profile + "\ntls\n" + origin + "\n" + lantrust.Fingerprint(anchor) + "\n" + device))
	b := wire.Binding{Platform: wire.Platform, Profile: wire.Profile, DeviceID: device, SenderBinding: hex.EncodeToString(sum[:])}
	if wire.ValidateBinding(b) != nil {
		return wire.Binding{}, ErrAuthority
	}
	return b, nil
}

func clientLeaf(c *x509.Certificate, device string) bool {
	return c != nil && !c.IsCA && c.BasicConstraintsValid && c.Subject.CommonName == device && len(c.Subject.Names) == 1 && c.KeyUsage == x509.KeyUsageDigitalSignature && len(c.ExtKeyUsage) == 1 && c.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth && len(c.UnknownExtKeyUsage) == 0 && len(c.UnhandledCriticalExtensions) == 0 && len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses)+len(c.URIs) == 0
}
func validateEvidence(v Evidence, enable wire.Control, original []byte, now time.Time) (inventory.Consent, string, error) {
	fail := func() (inventory.Consent, string, error) { return inventory.Consent{}, "", ErrAuthority }
	if !bytes.Equal(v.OriginalEnable, original) || v.CredentialGeneration == 0 || v.CredentialGeneration > wire.MaxSequence || now.IsZero() || now.Location() != time.UTC {
		return fail()
	}
	consent, e := inventory.DecodeConsent(v.Consent, enable.Binding.SenderBinding)
	if e != nil || !consent.Enabled || consent.GrantID != enable.GrantID {
		return fail()
	}
	if len(v.AnchorDER) == 0 || len(v.AnchorDER) > 8192 || len(v.CurrentDER) == 0 || len(v.CurrentDER) > 8192 || len(v.IssuerDER) == 0 || len(v.IssuerDER) > 8192 {
		return fail()
	}
	anchor, e := x509.ParseCertificate(v.AnchorDER)
	if e != nil {
		return fail()
	}
	current, e := x509.ParseCertificate(v.CurrentDER)
	if e != nil {
		return fail()
	}
	issuer, e := x509.ParseCertificate(v.IssuerDER)
	if e != nil {
		return fail()
	}
	binding, e := OriginalBinding(v.ManagerOrigin, enable.Binding.DeviceID, anchor)
	if e != nil || binding != enable.Binding || !clientLeaf(anchor, binding.DeviceID) || !clientLeaf(current, binding.DeviceID) || !bytes.Equal(anchor.RawSubjectPublicKeyInfo, current.RawSubjectPublicKeyInfo) || anchor.CheckSignatureFrom(issuer) != nil || current.CheckSignatureFrom(issuer) != nil {
		return fail()
	}
	if !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.MaxPathLen != 0 || !issuer.MaxPathLenZero || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(issuer.UnknownExtKeyUsage) != 0 || len(issuer.UnhandledCriticalExtensions) != 0 {
		return fail()
	}
	// Historical anchor may expire across renewal; its original signature/validity
	// bounds remain checked. Live authority always requires the CURRENT leaf.
	if now.Before(current.NotBefore) || !now.Before(current.NotAfter) || now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) || anchor.NotBefore.Before(issuer.NotBefore) || anchor.NotAfter.After(issuer.NotAfter) || current.NotBefore.Before(issuer.NotBefore) || current.NotAfter.After(issuer.NotAfter) || enable.ChangedAt.Before(anchor.NotBefore) || !enable.ChangedAt.Before(anchor.NotAfter) {
		return fail()
	}
	if v.CredentialGeneration == 1 && !bytes.Equal(anchor.Raw, current.Raw) || v.CredentialGeneration > 1 && (bytes.Equal(anchor.Raw, current.Raw) || !current.NotAfter.After(anchor.NotAfter)) {
		return fail()
	}
	return consent, lantrust.Fingerprint(current), nil
}
