//go:build darwin

package macosservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lantrust"
	"localrmm/internal/renewalidentity"
	"net/url"
	"time"
)

// InspectNativeSelection performs the existing native preflight as the service
// identity while allowing the root parent to inspect an already-owned plist.
// It is intentionally read-only, bounded and repeated between every effect.
func InspectNativeSelection(ctx context.Context, r Request, registeredHandoff bool) (SelectionEvidence, error) {
	if _, err := Plan(r); err != nil || r.RenderOnly || ctx == nil || ctx.Err() != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	checks, err := inspectSelection(ctx, r, false, registeredHandoff)
	if err != nil || len(checks) != len(checkOrder) {
		return SelectionEvidence{}, ErrPreflight
	}
	for i, check := range checks {
		if check.Code != checkOrder[i] || !check.Passed {
			return SelectionEvidence{}, ErrPreflight
		}
	}
	config, err := lanconfig.ReadProtected(ConfigPath, true, 16384)
	if err != nil || validateSelectedConfig(config, selectedProfile(r)) != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	// Only immutable original handoff bytes enter the ownership anchor. Before
	// bootstrap the mutable sender state is revalidated under its lock. Once the
	// owned job is registered, only current TLS material and immutable originals
	// can be rechecked without contending with the running foreground sender.
	names := []string{"ready.json"}
	if selectedProfile(r) == InventoryProfile {
		names = append(names, "macos-inventory-consent.json", "macos-inventory-enable.json")
	}
	h := sha256.New()
	parts := map[string]string{}
	anchorPart := func(name string, raw []byte) {
		parts[name] = digest(raw)
		part, _ := json.Marshal(struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		}{name, digest(raw)})
		h.Write(part)
	}
	anchorPart("agent.json", config)
	for _, name := range names {
		raw, e := lanconfig.ReadProtected(EnrollmentDirectory+"/"+name, true, 16384)
		if e != nil {
			return SelectionEvidence{}, ErrPreflight
		}
		anchorPart(name, raw)
	}
	if registeredHandoff {
		// The state owner may update its renewal manifest. Independently verify
		// current material a second time and reject a changed original anchor.
		if validateActiveCredential(ctx, selectedProfile(r)) != nil {
			return SelectionEvidence{}, ErrPreflight
		}
		again, e := lanconfig.ReadProtected(ConfigPath, true, 16384)
		if e != nil || !bytes.Equal(config, again) {
			return SelectionEvidence{}, ErrPreflight
		}
		for _, name := range names {
			raw, e := lanconfig.ReadProtected(EnrollmentDirectory+"/"+name, true, 16384)
			if e != nil || digest(raw) != parts[name] {
				return SelectionEvidence{}, ErrPreflight
			}
		}
	}
	if ctx.Err() != nil {
		return SelectionEvidence{}, ErrPreflight
	}
	return SelectionEvidence{Config: config, EnrollmentAnchorSHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// After exact owned registration a healthy foreground sender owns the mutable
// state lock. This checks only current protected TLS material and the immutable
// original anchor; it never treats lock contention as proof of its owner.
func validateActiveCredential(ctx context.Context, profile string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrPreflight
	}
	if profile == BasicProfile {
		material, e := lanclient.Load(ConfigPath)
		if e != nil || material.CertificateExpiry().IsZero() || !time.Now().UTC().Before(material.CertificateExpiry()) {
			return ErrPreflight
		}
		return ctx.Err()
	}
	if profile != InventoryProfile {
		return ErrPreflight
	}
	raw, e := lanconfig.ReadProtected(ConfigPath, true, 16384)
	if e != nil {
		return ErrPreflight
	}
	c, e := lanclient.ParseMacOSInventoryConfig(raw, ConfigPath)
	if e != nil {
		return ErrPreflight
	}
	cert, e := lanconfig.ReadProtected(c.CertificateFile, false, 65536)
	if e != nil {
		return ErrPreflight
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, 32768)
	if e != nil {
		return ErrPreflight
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return ErrPreflight
	}
	if c.RenewalManifestFile != "" {
		if len(pair.Certificate) != 2 {
			return ErrPreflight
		}
		anchor, e1 := x509.ParseCertificate(pair.Certificate[0])
		issuer, e2 := x509.ParseCertificate(pair.Certificate[1])
		if e1 != nil || e2 != nil {
			return ErrPreflight
		}
		manifestRaw, e := lanconfig.ReadProtected(c.RenewalManifestFile, true, renewalidentity.MaxBytes)
		if e != nil {
			return ErrPreflight
		}
		manifest, e := renewalidentity.Parse(manifestRaw)
		if e != nil {
			return ErrPreflight
		}
		current, e := manifest.Validate(anchor, issuer, c.ManagerOrigin, c.CollectionProfile, c.AgentID, time.Now().UTC())
		if e != nil || current == nil {
			return ErrPreflight
		}
		pair.Certificate[0] = current.Raw
		pair.Leaf = current
	}
	ca, e := lanconfig.ReadProtected(c.ServerCAFile, false, 65536)
	if e != nil {
		return ErrPreflight
	}
	u, e := url.Parse(c.ManagerOrigin)
	if e != nil {
		return ErrPreflight
	}
	if _, e = lantrust.ClientTLSConfig(pair, ca, u.Hostname()); e != nil {
		return ErrPreflight
	}
	return ctx.Err()
}
