package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/actionpermit"
	"localrmm/internal/lanconfig"
	"localrmm/internal/renewalidentity"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"path/filepath"
	"time"
)

// OpenWindowsUpdatePublicAuthority never calls Load, reads an enrollment private
// key, builds a TLS client or impersonates the observer. Revocation is local relay
// disable/current authenticated leaf evidence, not a claim of online knowledge.
func OpenWindowsUpdatePublicAuthority(c windowsupdateipc.Config, check func(context.Context) error) (job.Authority, error) {
	layout, e := windowsservice.ResolveLayout()
	if e != nil {
		return nil, e
	}
	return openWindowsUpdatePublicAuthority(c, layout, check, lanconfig.ReadProtected, readWindowsUpdateRelay, time.Now)
}
func openWindowsUpdatePublicAuthority(config windowsupdateipc.Config, layout windowsservice.Layout, check func(context.Context) error, read func(string, bool, int64) ([]byte, error), grant func(Material) (WindowsUpdateRelayGrant, error), now func() time.Time) (job.Authority, error) {
	if config.Validate() != nil || config.Version != windowsupdateipc.ServiceConfigVersion || config.ObserverReceipt.Layout != layout || check == nil || read == nil || grant == nil || now == nil {
		return nil, job.ErrAuthority
	}
	peer, e := config.Peer()
	if e != nil {
		return nil, e
	}
	peerRaw, _ := json.Marshal(peer)
	a := &windowsUpdateExecutorAuthority{layout: layout, path: filepath.Join(layout.EnrollmentRoot, "agent.json"), peerDigest: actionpermit.Digest(peerRaw), binding: config.Consent.Binding, check: check, reads: windowsUpdateAuthorityReads{now: now}}
	a.publicRead = func(ctx context.Context) (windowsUpdateAuthoritySnapshot, error) {
		zero := windowsUpdateAuthoritySnapshot{}
		if ctx == nil || ctx.Err() != nil {
			return zero, job.ErrAuthority
		}
		raw, e := read(a.path, false, 16384)
		var c Config
		if e != nil || decodeConfig(raw, &c) != nil || c.Validate() != nil || !a.fixedConfig(c) || c.AgentID != a.binding.DeviceID || c.ManagerOrigin != config.ManagerOrigin {
			return zero, job.ErrAuthority
		}
		canonical, _ := json.Marshal(c)
		if actionpermit.Digest(canonical) != config.ObserverConfigDigest {
			return zero, job.ErrAuthority
		}
		certs, e := read(c.CertificateFile, false, 65536)
		if e != nil {
			return zero, e
		}
		block, rest := pem.Decode(certs)
		if block == nil || block.Type != "CERTIFICATE" {
			return zero, job.ErrIntegrity
		}
		anchor, e := x509.ParseCertificate(block.Bytes)
		if e != nil || actionpermit.Digest(anchor.Raw) != a.binding.IncarnationDigest {
			return zero, job.ErrAuthority
		}
		leaf := anchor
		generation := uint64(1)
		var renewal *renewalidentity.Manifest
		if c.automaticRenewal() {
			issuerBlock, remaining := pem.Decode(rest)
			if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(remaining)) != 0 {
				return zero, job.ErrIntegrity
			}
			issuer, e := x509.ParseCertificate(issuerBlock.Bytes)
			if e != nil {
				return zero, e
			}
			manifestRaw, e := read(c.RenewalManifestFile, true, renewalidentity.MaxBytes)
			if e != nil {
				return zero, e
			}
			manifest, e := renewalidentity.Parse(manifestRaw)
			if e != nil || manifest.ManagerInstanceID != a.binding.ManagerID {
				return zero, job.ErrAuthority
			}
			leaf, e = manifest.Validate(anchor, issuer, c.ManagerOrigin, c.CollectionProfile, c.AgentID, now().UTC())
			if e != nil {
				return zero, e
			}
			generation = manifest.CredentialGeneration
			renewal = &manifest
		}
		sum := senderBinding(c, anchor)
		sender := hex.EncodeToString(sum[:])
		if sender != config.SenderBinding {
			return zero, job.ErrAuthority
		}
		// Certificate metadata only: no PrivateKey, loaded bit or TLS configuration.
		public := Material{config: c, configPath: a.path, certificate: tls.Certificate{Certificate: [][]byte{leaf.Raw}}, authorityCertificate: anchor.Raw, binding: sender, renewal: renewal}
		ready, e := read(filepath.Join(layout.EnrollmentRoot, "ready.json"), true, 4096)
		if e != nil || validateUpdatesActivatedBytes(raw, ready, public) != nil {
			return zero, job.ErrAuthority
		}
		g, e := grant(public)
		if e != nil || !g.Enabled || g.Version != WindowsBackgroundUpdateRelayGrantVersion || g.Binding != a.binding || validateWindowsUpdateRelayGrant(public, g, now().UTC()) != nil || g.ExpiresAt != config.Consent.ExpiresAt || !bytes.Equal(g.ManagerPublicKey, config.ManagerPublicKey) || !bytes.Equal(g.ExecutorPublicKey, config.ExecutorPublicKey) {
			return zero, job.ErrAuthority
		}
		got, _ := json.Marshal(g.ExecutorPeer)
		if !bytes.Equal(got, peerRaw) {
			return zero, job.ErrAuthority
		}
		gr, _ := json.Marshal(g)
		// Final time follows every possibly blocking read; WithCurrent does a second
		// complete snapshot around the runtime check and samples again after its lock.
		n := now().UTC()
		if ctx.Err() != nil || n.Unix() <= 0 || n.Unix() >= g.ExpiresAt || n.Before(leaf.NotBefore) || !n.Before(leaf.NotAfter) {
			return zero, job.ErrExpired
		}
		return windowsUpdateAuthoritySnapshot{config: c, sender: sender, anchor: actionpermit.Digest(anchor.Raw), grant: actionpermit.Digest(gr), expiresAt: g.ExpiresAt, current: job.Current{Binding: g.Binding, LeafDigest: actionpermit.Digest(leaf.Raw), LeafGeneration: generation, LeafNotBefore: leaf.NotBefore.Unix(), LeafNotAfter: leaf.NotAfter.Unix(), Enabled: true}}, nil
	}
	first, e := a.read(context.Background())
	if e != nil {
		return nil, e
	}
	a.original = first
	if e = a.WithCurrent(context.Background(), a.binding, func(job.Current) error { return nil }); e != nil {
		return nil, e
	}
	return a, nil
}
