package lanclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateipc"
	"localrmm/internal/windowsupdatejob"
)

const WindowsBackgroundUpdateRelayGrantVersion = "tracebolt.windows-selected-update-observer-relay.v3"

const WindowsUpdateRelayGrantVersion = "tracebolt.windows-selected-update-observer-relay.v2"
const WindowsUpdateRelayScope = "windows-selected-update-observer-relay-v1"
const WindowsUpdateRelayDisclosure = "Allow this observation client to relay exact signed selected cached Windows update requests and saved executor reports over TLS to the separately approved dedicated update executor. Verify the separately pinned executor executable and public configuration. This does not grant installation, service control, elevated observation access, downloads, license acceptance or reboot authority."

// WindowsUpdateRelayGrant is fresh local relay consent, separate from the
// executor's install consent, read receipts and service-action broker policy.
// Fresh v2 additionally pins the exact protected IPC executable/public config;
// earlier relay receipts are never adopted or silently extended.
// It contains public pins only; the observer never holds an executor key.
type WindowsUpdateRelayGrant struct {
	Version           string                      `json:"version"`
	Scope             string                      `json:"scope"`
	Enabled           bool                        `json:"enabled"`
	Acknowledged      bool                        `json:"acknowledged"`
	SenderBinding     string                      `json:"senderBinding"`
	ManagerOrigin     string                      `json:"managerOrigin"`
	Binding           windowsupdatejob.Binding    `json:"binding"`
	ManagerPublicKey  []byte                      `json:"managerPublicKey"`
	ExecutorPublicKey []byte                      `json:"executorPublicKey"`
	ExecutorPeer      windowsupdateipc.PeerConfig `json:"executorPeer"`
	ExpiresAt         int64                       `json:"expiresAt"`
}

func windowsUpdateRelayPath(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-update-job-relay"
}
func windowsUpdateRelayOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"grant.json"}, LockName: "relay.lock", TempName: "relay.tmp", MaxBytes: 4096, Create: create}
}
func validateWindowsUpdateRelayGrant(m Material, g WindowsUpdateRelayGrant, now time.Time) error {
	if !m.config.windowsInventory() || m.config.Profile != "tls" || !(g.Version == WindowsUpdateRelayGrantVersion && g.ExecutorPeer.Version == windowsupdateipc.PeerVersion || g.Version == WindowsBackgroundUpdateRelayGrantVersion && g.ExecutorPeer.Version == windowsupdateipc.ServicePeerVersion) || g.Scope != WindowsUpdateRelayScope || !g.Acknowledged || g.SenderBinding != m.binding || g.ManagerOrigin != m.config.ManagerOrigin || !windowsupdatejob.ValidBinding(g.Binding) || g.Binding.DeviceID != m.config.AgentID || g.Binding.IncarnationDigest != "sha256:"+journalLeaf(m) || !keyvalidation.Ed25519(g.ManagerPublicKey) || !keyvalidation.Ed25519(g.ExecutorPublicKey) || actionpermit.Digest(g.ManagerPublicKey) != g.Binding.KeyID || actionpermit.Digest(g.ExecutorPublicKey) != g.Binding.ExecutorKeyID || g.ExpiresAt <= 0 || g.ExpiresAt > 253402300799 || now.Unix() <= 0 || now.Unix() >= g.ExpiresAt {
		return ErrConfiguration
	}
	if g.ExecutorPeer.Validate() != nil || g.ExecutorPeer.Binding != g.Binding || !bytes.Equal(g.ExecutorPeer.ExecutorPublicKey, g.ExecutorPublicKey) {
		return ErrConfiguration
	}
	// Neither public pin may reuse the observation signing identity.
	if len(m.certificate.Certificate) == 0 {
		return ErrConfiguration
	}
	leaf, e := x509.ParseCertificate(m.certificate.Certificate[0])
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrConfiguration
	}
	if key, ok := leaf.PublicKey.(ed25519.PublicKey); ok && (bytes.Equal(key, g.ManagerPublicKey) || bytes.Equal(key, g.ExecutorPublicKey)) {
		return ErrConfiguration
	}
	return nil
}
func decodeWindowsUpdateRelayJSON(raw []byte, value any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrState
	}
	canonical, e := json.Marshal(value)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrState
	}
	return nil
}

// InitializeWindowsUpdateRelayCreateOnly is a source-only local provisioning
// seam. The caller must hold the stopped-owned-service installer lease and have
// obtained this distinct explicit approval. The fresh selected-update setup
// command invokes it; Read admin never does.
// Supplied original binding, pins and expiry are saved unchanged. Existing roots
// and partial/used manifests are never adopted, overwritten, repaired or reset.
// This relay receipt confers no executor or OS installation permission.
func InitializeWindowsUpdateRelayCreateOnly(path string, g WindowsUpdateRelayGrant) error {
	if !g.Enabled || !g.Acknowledged {
		return ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return ErrState
	}
	m, e := Load(path)
	if e != nil || validateUpdatesActivatedMaterial(path, m) != nil || validateWindowsUpdateRelayGrant(m, g, time.Now().UTC()) != nil {
		return ErrConfiguration
	}
	state, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return ErrState
	}
	defer state.Close()
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	if !currentWindowsUpdateRelayMaterial(m, Load) {
		return ErrState
	}
	store, e := windowsstate.Open(windowsUpdateRelayPathFor(m, g.Version), windowsUpdateRelayOptions(sid, true))
	if e != nil {
		return ErrState
	}
	defer store.Close()
	if !currentWindowsUpdateRelayMaterial(m, Load) || validateWindowsUpdateRelayGrant(m, g, time.Now().UTC()) != nil {
		return ErrState
	}
	raw, e := json.Marshal(g)
	if e != nil || store.Write("grant.json", raw) != nil || store.Close() != nil {
		return ErrState
	}
	return nil
}
func readWindowsUpdateRelay(m Material) (WindowsUpdateRelayGrant, error) {
	var g WindowsUpdateRelayGrant
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return g, e
	}
	store, version, e := openWindowsUpdateRelayStore(m, sid)
	if e != nil {
		return g, e
	}
	defer store.Close()
	raw, e := store.Read("grant.json")
	if e != nil || decodeWindowsUpdateRelayJSON(raw, &g, 4096) != nil || g.Version != version || store.Close() != nil {
		return g, ErrState
	}
	return g, nil
}

// The grant stays on the original anchor across renewal. A running relay must
// nevertheless stop using a replaced transport leaf; reloading the foreground
// client supplies the new leaf without extending the original grant expiry.
func currentWindowsUpdateRelayMaterial(m Material, reload func(string) (Material, error)) bool {
	if !m.valid() || !m.config.windowsInventory() || m.config.Profile != "tls" || reload == nil {
		return false
	}
	current, e := reload(m.configPath)
	return e == nil && current.valid() && current.binding == m.binding && current.config == m.config && bytes.Equal(current.authorityDER(), m.authorityDER()) && len(current.certificate.Certificate) > 0 && bytes.Equal(current.certificate.Certificate[0], m.certificate.Certificate[0]) && validateUpdatesActivatedMaterial(m.configPath, current) == nil
}

func windowsUpdateRelayPathFor(m Material, v string) string {
	if v == WindowsBackgroundUpdateRelayGrantVersion {
		return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-background-update-job-relay"
	}
	return windowsUpdateRelayPath(m)
}
func openWindowsUpdateRelayStore(m Material, sid string) (*windowsstate.Store, string, error) {
	old, oe := windowsstate.Open(windowsUpdateRelayPath(m), windowsUpdateRelayOptions(sid, false))
	fresh, fe := windowsstate.Open(windowsUpdateRelayPathFor(m, WindowsBackgroundUpdateRelayGrantVersion), windowsUpdateRelayOptions(sid, false))
	if old != nil && errors.Is(fe, fs.ErrNotExist) {
		return old, WindowsUpdateRelayGrantVersion, nil
	}
	if fresh != nil && errors.Is(oe, fs.ErrNotExist) {
		return fresh, WindowsBackgroundUpdateRelayGrantVersion, nil
	}
	if old != nil {
		old.Close()
	}
	if fresh != nil {
		fresh.Close()
	}
	return nil, "", ErrState
}
