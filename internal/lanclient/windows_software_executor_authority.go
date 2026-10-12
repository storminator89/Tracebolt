package lanclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/renewalidentity"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssoftwareipc"
	job "localrmm/internal/windowssoftwarejob"
)

// OpenWindowsSoftwareExecutorAuthority opens only the installed Windows client's
// fixed activated TLS identity and its already-provisioned, exact relay grant.
// It creates no key, receipt, scope, storage or network connection. peer must
// come from the executor's protected immutable configuration, never a request.
// check must synchronously reread and reject disabled, replaced or missing
// executor install consent/configuration. Relay consent alone is insufficient.
// It must not call this authority or retain locks needed by an executor callback.
func OpenWindowsSoftwareExecutorAuthority(peer windowssoftwareipc.PeerConfig, check func(context.Context) error) (job.Authority, error) {
	if peer.Validate() != nil || check == nil {
		return nil, job.ErrAuthority
	}
	layout, err := windowsservice.ResolveLayout()
	if err != nil {
		return nil, job.ErrAuthority
	}
	return openWindowsSoftwareExecutorAuthority(layout, peer, check, windowsSoftwareAuthorityReads{Load, readWindowsSoftwareRelay, time.Now})
}

type windowsSoftwareAuthorityReads struct {
	load  func(string) (Material, error)
	grant func(Material) (WindowsSoftwareRelayGrant, error)
	now   func() time.Time
}

type windowsSoftwareAuthoritySnapshot struct {
	config                Config
	sender, anchor, grant string
	current               job.Current
	expiresAt             int64
}

type windowsSoftwareExecutorAuthority struct {
	layout           windowsservice.Layout
	path, peerDigest string
	binding          job.Binding
	check            func(context.Context) error
	reads            windowsSoftwareAuthorityReads
	original         windowsSoftwareAuthoritySnapshot
	mu               sync.Mutex // Observed generation floor only; never held across fn/native work.
	generation       uint64
	leaf             string
}

var _ job.Authority = (*windowsSoftwareExecutorAuthority)(nil)

func (*windowsSoftwareExecutorAuthority) String() string { return "<local Windows software authority>" }
func (*windowsSoftwareExecutorAuthority) GoString() string {
	return "<local Windows software authority>"
}
func (*windowsSoftwareExecutorAuthority) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

func openWindowsSoftwareExecutorAuthority(layout windowsservice.Layout, peer windowssoftwareipc.PeerConfig, check func(context.Context) error, reads windowsSoftwareAuthorityReads) (*windowsSoftwareExecutorAuthority, error) {
	if peer.Validate() != nil || check == nil || reads.load == nil || reads.grant == nil || reads.now == nil || layout.EnrollmentRoot == "" || layout.SenderRoot != filepath.Join(layout.EnrollmentRoot, "telemetry") {
		return nil, job.ErrAuthority
	}
	raw, err := json.Marshal(peer)
	if err != nil {
		return nil, job.ErrAuthority
	}
	a := &windowsSoftwareExecutorAuthority{layout: layout, path: filepath.Join(layout.EnrollmentRoot, "agent.json"), peerDigest: actionpermit.Digest(raw), binding: peer.Binding, check: check, reads: reads}
	first, err := a.read(context.Background())
	if err != nil {
		return nil, err
	}
	a.original = first
	// Opening pins the exact immutable grant/configuration. Recheck after the
	// protected executor callback too; slow local reads grant no expiry grace.
	if err = a.WithCurrent(context.Background(), peer.Binding, func(job.Current) error { return nil }); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *windowsSoftwareExecutorAuthority) fixedConfig(c Config) bool {
	root := a.layout.EnrollmentRoot
	return c.windowsInventory() && c.Profile == "tls" && !c.InsecureHTTPAcknowledged &&
		c.CertificateFile == filepath.Join(root, "agent-cert.pem") && c.PrivateKeyFile == filepath.Join(root, "agent-key.pem") &&
		c.ServerCAFile == filepath.Join(root, "server-ca.pem") && c.StateDirectory == a.layout.SenderRoot &&
		(!c.automaticRenewal() && c.RenewalManifestFile == "" || c.automaticRenewal() && c.RenewalManifestFile == filepath.Join(root, renewalidentity.ManifestName))
}

func (a *windowsSoftwareExecutorAuthority) read(ctx context.Context) (windowsSoftwareAuthoritySnapshot, error) {
	zero := windowsSoftwareAuthoritySnapshot{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	m, err := a.reads.load(a.path)
	if err != nil || m.configPath != a.path || !m.valid() || !a.fixedConfig(m.config) || validateUpdatesActivatedMaterial(a.path, m) != nil {
		return zero, job.ErrAuthority
	}
	// Renewable material carries the original manager identity as well as the
	// anchor. Ordinary activated Config/ready/leaf material has no manager-ID
	// field; that path remains bound by the separately acknowledged exact peer.
	if m.renewal != nil && m.renewal.ManagerInstanceID != a.binding.ManagerID {
		return zero, job.ErrAuthority
	}
	// The protected receipt store owns its short read lock; grant returns only
	// after closing it. Neither Material nor credential/key bytes are retained.
	g, err := a.reads.grant(m)
	if err != nil || !g.Enabled || g.Binding != a.binding || validateWindowsSoftwareRelayGrant(m, g, a.reads.now().UTC()) != nil {
		return zero, job.ErrAuthority
	}
	peer, err := json.Marshal(g.ExecutorPeer)
	if err != nil || actionpermit.Digest(peer) != a.peerDigest || g.ExecutorPeer.Validate() != nil || g.ExecutorPeer.Binding != g.Binding || !bytes.Equal(g.ExecutorPeer.ExecutorPublicKey, g.ExecutorPublicKey) {
		return zero, job.ErrAuthority
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return zero, job.ErrAuthority
	}
	leaf, err := x509.ParseCertificate(m.certificate.Certificate[0])
	if err != nil {
		return zero, job.ErrAuthority
	}
	generation := uint64(1)
	if m.renewal != nil {
		generation = m.renewal.CredentialGeneration
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	// Last time sample follows every potentially blocking read in this snapshot.
	now := a.reads.now().UTC()
	if now.Unix() <= 0 || now.Unix() >= g.ExpiresAt || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return zero, job.ErrExpired
	}
	return windowsSoftwareAuthoritySnapshot{config: m.config, sender: m.binding, anchor: actionpermit.Digest(m.authorityDER()), grant: actionpermit.Digest(raw), expiresAt: g.ExpiresAt, current: job.Current{Binding: g.Binding, LeafDigest: actionpermit.Digest(leaf.Raw), LeafGeneration: generation, LeafNotBefore: leaf.NotBefore.Unix(), LeafNotAfter: leaf.NotAfter.Unix(), Enabled: true}}, nil
}

// WithCurrent gives one synchronous, fresh local observation. All protected
// reads/checks finish before fn, and no receipt/credential lock spans fn. The
// kernel must call it again at its final native start fence, after blocking MSI
// preparation and durable writes, then resample original time bounds. It cannot
// make file replacement atomic with MSI dispatch or know disconnected manager
// revocation; neither a successful check nor Revoked=false asserts otherwise.
func (a *windowsSoftwareExecutorAuthority) WithCurrent(ctx context.Context, binding job.Binding, fn func(job.Current) error) error {
	if a == nil || ctx == nil || fn == nil || binding != a.binding {
		return job.ErrAuthority
	}
	first, err := a.read(ctx)
	if err != nil {
		return err
	}
	if !a.sameOriginal(first) {
		return job.ErrAuthority
	}
	if err = a.check(ctx); err != nil {
		return job.ErrAuthority
	}
	current, err := a.read(ctx)
	if err != nil {
		return err
	}
	if !a.sameOriginal(current) || current.current != first.current {
		return job.ErrAuthority
	}
	// Renewal between calls is allowed without changing original identity/grant
	// age. An admitted generation cannot roll back within this authority instance.
	// Complete private-state backup rollback is not supported recovery.
	a.mu.Lock()
	if current.current.LeafGeneration < a.generation || current.current.LeafGeneration == a.generation && a.leaf != current.current.LeafDigest {
		a.mu.Unlock()
		return job.ErrAuthority
	}
	a.generation, a.leaf = current.current.LeafGeneration, current.current.LeafDigest
	a.mu.Unlock()
	if err = ctx.Err(); err != nil {
		return err
	}
	now := a.reads.now().UTC().Unix()
	if now <= 0 || now >= current.expiresAt || now < current.current.LeafNotBefore || now >= current.current.LeafNotAfter {
		return job.ErrExpired
	}
	return fn(current.current)
}

func (a *windowsSoftwareExecutorAuthority) sameOriginal(s windowsSoftwareAuthoritySnapshot) bool {
	return s.config == a.original.config && s.sender == a.original.sender && s.anchor == a.original.anchor && s.grant == a.original.grant
}
