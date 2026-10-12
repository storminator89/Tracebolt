package lanclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"time"

	"localrmm/internal/lanconfig"
	"localrmm/internal/renewalidentity"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"localrmm/internal/windowsservice"
)

// OpenWindowsManagedMSIPublicAuthority reads PUBLIC identity/relay records only.
// The deployment service never loads an enrollment private key, constructs an
// HTTP client, or impersonates the observer. A disconnected service cannot know
// a later manager revocation until an authenticated relay fails or time expires.
func OpenWindowsManagedMSIPublicAuthority(config windowsmanagedmsiipc.Config, check func(context.Context) error) (managed.CurrentCheck, error) {
	if config.Validate() != nil || check == nil {
		return nil, managed.ErrAuthority
	}
	peer, e := config.Peer()
	if e != nil {
		return nil, e
	}
	layout, e := windowsservice.ResolveLayout()
	if e != nil || layout != config.ObserverReceipt.Layout {
		return nil, managed.ErrAuthority
	}
	var generation uint64
	var digest string
	read := func(ctx context.Context, b managed.Binding) (managed.Current, error) {
		zero := managed.Current{}
		if ctx == nil || ctx.Err() != nil || b != config.Grant.Binding {
			return zero, managed.ErrAuthority
		}
		path := filepath.Join(layout.EnrollmentRoot, "agent.json")
		raw, e := lanconfig.ReadProtected(path, false, 16384)
		var c Config
		if e != nil || decodeConfig(raw, &c) != nil || c.Validate() != nil || !c.windowsInventory() || c.Profile != "tls" || c.ManagerOrigin != config.ManagerOrigin || c.AgentID != b.DeviceID || !(&windowsSoftwareExecutorAuthority{layout: layout}).fixedConfig(c) {
			return zero, managed.ErrAuthority
		}
		canonical, _ := json.Marshal(c)
		if managed.Digest(canonical) != config.ObserverConfigDigest {
			return zero, managed.ErrAuthority
		}
		certs, e := lanconfig.ReadProtected(c.CertificateFile, false, 65536)
		if e != nil {
			return zero, e
		}
		block, rest := pem.Decode(certs)
		if block == nil || block.Type != "CERTIFICATE" {
			return zero, managed.ErrIntegrity
		}
		anchor, e := x509.ParseCertificate(block.Bytes)
		if e != nil || managed.Digest(anchor.Raw) != b.IncarnationDigest {
			return zero, managed.ErrAuthority
		}
		leaf := anchor
		gen := uint64(1)
		if c.automaticRenewal() {
			issuerBlock, rest2 := pem.Decode(rest)
			if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest2)) != 0 {
				return zero, managed.ErrIntegrity
			}
			issuer, e := x509.ParseCertificate(issuerBlock.Bytes)
			if e != nil {
				return zero, e
			}
			raw, e := lanconfig.ReadProtected(c.RenewalManifestFile, true, renewalidentity.MaxBytes)
			if e != nil {
				return zero, e
			}
			manifest, e := renewalidentity.Parse(raw)
			if e != nil || manifest.ManagerInstanceID != b.ManagerID {
				return zero, managed.ErrAuthority
			}
			leaf, e = manifest.Validate(anchor, issuer, c.ManagerOrigin, c.CollectionProfile, c.AgentID, time.Now().UTC())
			if e != nil {
				return zero, e
			}
			gen = manifest.CredentialGeneration
		}
		// This material deliberately has no key/certificate pair/TLS client. The
		// grant reader uses only its fixed state-root, never material.valid or Load.
		g, e := readWindowsManagedMSIRelay(Material{config: c})
		if e != nil || !g.Enabled || !g.Acknowledged || g.Binding != b || g.SenderBinding != config.SenderBinding || g.ManagerOrigin != config.ManagerOrigin || g.ExpiresAt != config.Grant.ExpiresAt {
			return zero, managed.ErrAuthority
		}
		a, _ := json.Marshal(peer)
		z, _ := json.Marshal(g.ExecutorPeer)
		if !bytes.Equal(a, z) || !bytes.Equal(g.ManagerPublicKey, config.ManagerPublicKey) || !bytes.Equal(g.ExecutorPublicKey, config.ExecutorPublicKey) {
			return zero, managed.ErrAuthority
		}
		if e = check(ctx); e != nil {
			return zero, e
		}
		now := time.Now().UTC()
		d := managed.Digest(leaf.Raw)
		if now.Unix() >= g.ExpiresAt || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || gen < generation || gen == generation && digest != "" && digest != d {
			return zero, managed.ErrExpired
		}
		generation, digest = gen, d
		return managed.Current{Binding: b, LeafDigest: d, LeafGeneration: gen, LeafNotBefore: leaf.NotBefore.Unix(), LeafNotAfter: leaf.NotAfter.Unix(), Enabled: true}, ctx.Err()
	}
	return read, nil
}
