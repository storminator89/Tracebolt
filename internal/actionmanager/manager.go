// Package actionmanager binds the fixed service workflow to an existing manager
// ledger and separately provisioned command key. Construction provisions nothing.
package actionmanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"path/filepath"
	"sync"
	"time"
)

const ConfigVersion = "tracebolt.service-actions-config.v1"

var ErrConfiguration = errors.New("service_actions_configuration_invalid")

type Config struct {
	Version              string `json:"version"`
	Enabled              bool   `json:"enabled"`
	ManagerID            string `json:"managerId"`
	TransportProfile     string `json:"transportProfile"`
	HTTPTestAcknowledged bool   `json:"httpTestAcknowledged"`
	PrivateKeyFile       string `json:"privateKeyFile"`
}
type signingKey struct {
	mu     sync.RWMutex
	bytes  ed25519.PrivateKey
	closed bool
}
type Manager struct {
	store  *enrollmentstore.Store
	config Config
	path   string
	raw    []byte
	key    *signingKey
	now    func() time.Time
}

func (Manager) String() string               { return "actionmanager.Manager{secrets:redacted}" }
func (m Manager) Format(f fmt.State, _ rune) { io.WriteString(f, m.String()) }
func (Manager) MarshalJSON() ([]byte, error) { return []byte(`{"secretsRedacted":true}`), nil }
func Profile(profile string) string {
	if profile == lanconfig.TLS {
		return actionhelper.ProductionTLS
	}
	if profile == lanconfig.HTTPTest {
		return actionhelper.DisposableHTTPTest
	}
	return ""
}
func validConfig(c Config) bool {
	return c.Version == ConfigVersion && c.Enabled && enrollmentcrypto.ValidID(c.ManagerID, "manager_") && filepath.IsAbs(c.PrivateKeyFile) && filepath.Clean(c.PrivateKeyFile) == c.PrivateKeyFile && ((c.TransportProfile == actionhelper.ProductionTLS && !c.HTTPTestAcknowledged) || (c.TransportProfile == actionhelper.DisposableHTTPTest && c.HTTPTestAcknowledged))
}
func Load(ctx context.Context, store *enrollmentstore.Store, path string, forbidden ...ed25519.PublicKey) (*Manager, error) {
	if store == nil || path == "" || store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		return nil, ErrConfiguration
	}
	raw, e := lanconfig.ReadProtected(path, true, 4096)
	if e != nil {
		return nil, ErrConfiguration
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "transportProfile", "httpTestAcknowledged", "privateKeyFile") != nil || !validConfig(c) || c.ManagerID != store.Config().Binding.InstanceID || c.TransportProfile != Profile(store.Config().Binding.Profile) {
		return nil, ErrConfiguration
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrConfiguration
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, key) || !keyvalidation.Ed25519(derived.Public().(ed25519.PublicKey)) {
		return nil, ErrConfiguration
	}
	for _, other := range forbidden {
		if bytes.Equal(derived.Public().(ed25519.PublicKey), other) {
			return nil, ErrConfiguration
		}
	}
	if e = store.OpenServiceActions(ctx, derived.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	return &Manager{store: store, config: c, path: path, raw: bytes.Clone(raw), key: &signingKey{bytes: bytes.Clone(key)}, now: func() time.Time { return time.Now().UTC() }}, nil
}
func (m *Manager) Close() {
	if m == nil || m.key == nil {
		return
	}
	m.key.mu.Lock()
	defer m.key.mu.Unlock()
	m.key.closed = true
	clear(m.key.bytes)
}

func (m *Manager) Matches(s *enrollmentstore.Store) bool { return m != nil && m.store == s }
func (m *Manager) TransportProfile() string {
	if m == nil {
		return ""
	}
	return m.config.TransportProfile
}
func (m *Manager) Now() time.Time { return m.now().UTC() }
func (m *Manager) live() error {
	if m == nil || m.key == nil {
		return ErrConfiguration
	}
	m.key.mu.RLock()
	defer m.key.mu.RUnlock()
	return m.liveLocked()
}
func (m *Manager) liveLocked() error {
	if m.store == nil || m.key.closed || !validConfig(m.config) || len(m.key.bytes) != ed25519.PrivateKeySize {
		return ErrConfiguration
	}
	b, e := lanconfig.ReadProtected(m.path, true, 4096)
	if e != nil || !bytes.Equal(b, m.raw) {
		return ErrConfiguration
	}
	k, e := lanconfig.ReadProtected(m.config.PrivateKeyFile, true, ed25519.PrivateKeySize)
	defer clear(k)
	if e != nil || !bytes.Equal(k, m.key.bytes) {
		return ErrConfiguration
	}
	return nil
}

func (m *Manager) keyPublic() ed25519.PublicKey {
	if m == nil || m.key == nil {
		return nil
	}
	m.key.mu.RLock()
	defer m.key.mu.RUnlock()
	if m.key.closed || len(m.key.bytes) != ed25519.PrivateKeySize {
		return nil
	}
	return bytes.Clone(m.key.bytes.Public().(ed25519.PublicKey))
}
func (m *Manager) sign(p actionpermit.Permit) ([]byte, error) {
	if m == nil || m.key == nil {
		return nil, ErrConfiguration
	}
	m.key.mu.RLock()
	defer m.key.mu.RUnlock()
	if e := m.liveLocked(); e != nil {
		return nil, e
	}
	b, e := actionpermit.SigningMessage(p)
	if e != nil {
		return nil, e
	}
	return actionpermit.Encode(p, ed25519.Sign(m.key.bytes, b))
}

// ViewAt returns the exact trusted timestamp used by the durable observation.
// Callers must not resample it to expose an uncommitted expiry transition.
func (m *Manager) ViewAt(ctx context.Context, device string) (actionjob.Record, time.Time, error) {
	if m == nil {
		return actionjob.Record{}, time.Time{}, ErrConfiguration
	}
	now := m.Now()
	record, err := m.store.ServiceActionView(ctx, m.keyPublic(), device, now)
	return record, now, err
}
func (m *Manager) View(ctx context.Context, device string) (actionjob.Record, error) {
	record, _, err := m.ViewAt(ctx, device)
	return record, err
}

func (m *Manager) Preview(ctx context.Context, device, actor, unit string) (actionjob.Record, error) {
	if e := m.live(); e != nil {
		return actionjob.Record{}, e
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return actionjob.Record{}, actionjob.ErrUnavailable
	}
	return m.store.PreviewServiceAction(ctx, m.keyPublic(), device, "action_"+hex.EncodeToString(b[:]), actor, unit, m.config.TransportProfile, m.Now())
}
func (m *Manager) Approve(ctx context.Context, device, id, digest, actor string) (actionjob.Record, error) {
	if e := m.live(); e != nil {
		return actionjob.Record{}, e
	}
	return m.store.ApproveServiceAction(ctx, m.keyPublic(), device, id, digest, actor, m.config.TransportProfile, m.Now(), m.sign)
}
func (m *Manager) Report(ctx context.Context, id, hash string, c actionhelper.Capabilities) error {
	if e := m.live(); e != nil {
		return e
	}
	if c.TransportProfile != m.config.TransportProfile {
		return actionjob.ErrInvalid
	}
	return m.store.ReportServiceActions(ctx, m.keyPublic(), id, hash, c, m.Now())
}
func (m *Manager) Peek(ctx context.Context, id, hash string) (actionjob.Delivery, error) {
	if m == nil {
		return actionjob.Delivery{}, ErrConfiguration
	}
	return m.store.PeekServiceAction(ctx, m.keyPublic(), id, hash, m.Now())
}
func (m *Manager) Claim(ctx context.Context, id, hash string, i actionjob.Identity) (actionjob.Grant, error) {
	if e := m.live(); e != nil {
		return actionjob.Grant{}, e
	}
	return m.store.ClaimServiceAction(ctx, m.keyPublic(), id, hash, m.config.TransportProfile, i, m.Now())
}
func (m *Manager) Accept(ctx context.Context, id, hash string, result actionhelper.Result) error {
	if m == nil {
		return ErrConfiguration
	}
	return m.store.AcceptServiceAction(ctx, m.keyPublic(), id, hash, result, m.Now())
}
func (m *Manager) Available() bool { return m.live() == nil }

func (m *Manager) MatchesBinding(b enrollmentstate.Binding) bool {
	return m != nil && m.store != nil && m.store.Config().Binding == b
}
