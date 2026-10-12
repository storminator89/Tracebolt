package lanclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

const WindowsManagedMSIRelayGrantVersion = "tracebolt.windows-managed-msi-observer-relay.v2"
const WindowsManagedMSIRelayScope = "windows-managed-msi-observer-relay-v1"
const WindowsManagedMSIRelayDisclosure = "Allow this LocalService observation client to download bounded 32 KiB chunks of one exact centrally selected x64 machine MSI from the fixed authenticated manager route and relay them in the background to the separately approved deployment service. Relay exact signed delivery/readiness/install permits and saved service reports through its independently verified pipe. This separately consents to package-byte download and transfer only; it does not approve package terms, installation, arbitrary URLs/paths, service control, elevated observation, shell commands or reboot."

// WindowsManagedMSIRelayGrant is fresh local relay consent, separate from the
// executor's install consent, read receipts and service-action broker policy.
// Fresh v2 additionally pins the exact protected IPC executable/public config;
// earlier relay receipts are never adopted or silently extended.
// It contains public pins only; the observer never holds an executor key.
type WindowsManagedMSIRelayGrant struct {
	Version           string                          `json:"version"`
	Scope             string                          `json:"scope"`
	Enabled           bool                            `json:"enabled"`
	Acknowledged      bool                            `json:"acknowledged"`
	SenderBinding     string                          `json:"senderBinding"`
	ManagerOrigin     string                          `json:"managerOrigin"`
	Binding           windowsmanagedmsi.Binding       `json:"binding"`
	ManagerPublicKey  []byte                          `json:"managerPublicKey"`
	ExecutorPublicKey []byte                          `json:"executorPublicKey"`
	ExecutorPeer      windowsmanagedmsiipc.PeerConfig `json:"executorPeer"`
	ExpiresAt         int64                           `json:"expiresAt"`
}

func windowsManagedMSIRelayPath(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-managed-msi-relay"
}
func windowsManagedMSIRelayOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"grant.json"}, LockName: "relay.lock", TempName: "relay.tmp", MaxBytes: 8192, Create: create}
}
func validateWindowsManagedMSIRelayGrant(m Material, g WindowsManagedMSIRelayGrant, now time.Time) error {
	if !m.config.windowsInventory() || m.config.Profile != "tls" || g.Version != WindowsManagedMSIRelayGrantVersion || g.Scope != WindowsManagedMSIRelayScope || !g.Acknowledged || g.SenderBinding != m.binding || g.ManagerOrigin != m.config.ManagerOrigin || !windowsmanagedmsi.ValidBinding(g.Binding) || g.Binding.DeviceID != m.config.AgentID || g.Binding.IncarnationDigest != "sha256:"+journalLeaf(m) || !keyvalidation.Ed25519(g.ManagerPublicKey) || !keyvalidation.Ed25519(g.ExecutorPublicKey) || actionpermit.Digest(g.ManagerPublicKey) != g.Binding.KeyID || actionpermit.Digest(g.ExecutorPublicKey) != g.Binding.ExecutorKeyID || g.ExpiresAt <= 0 || g.ExpiresAt > 253402300799 || now.Unix() <= 0 || now.Unix() >= g.ExpiresAt {
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
func decodeWindowsManagedMSIRelayJSON(raw []byte, value any, max int) error {
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

// InitializeWindowsManagedMSIRelayCreateOnly is a source-only local provisioning
// seam. The caller must hold the stopped-owned-service installer lease and have
// obtained this distinct explicit approval. The fresh managed-MSI setup
// command invokes it; Read admin never does.
// Supplied original binding, pins and expiry are saved unchanged. Existing roots
// and partial/used manifests are never adopted, overwritten, repaired or reset.
// This relay receipt confers no executor or OS installation permission.
func InitializeWindowsManagedMSIRelayCreateOnly(path string, g WindowsManagedMSIRelayGrant) error {
	if !g.Enabled || !g.Acknowledged {
		return ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return ErrState
	}
	m, e := Load(path)
	if e != nil || validateUpdatesActivatedMaterial(path, m) != nil || validateWindowsManagedMSIRelayGrant(m, g, time.Now().UTC()) != nil {
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
	if !currentWindowsManagedMSIRelayMaterial(m, Load) {
		return ErrState
	}
	store, e := windowsstate.Open(windowsManagedMSIRelayPath(m), windowsManagedMSIRelayOptions(sid, true))
	if e != nil {
		return ErrState
	}
	defer store.Close()
	if !currentWindowsManagedMSIRelayMaterial(m, Load) || validateWindowsManagedMSIRelayGrant(m, g, time.Now().UTC()) != nil {
		return ErrState
	}
	raw, e := json.Marshal(g)
	if e != nil || store.Write("grant.json", raw) != nil || store.Close() != nil {
		return ErrState
	}
	return nil
}
func readWindowsManagedMSIRelay(m Material) (WindowsManagedMSIRelayGrant, error) {
	var g WindowsManagedMSIRelayGrant
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return g, e
	}
	store, e := windowsstate.Open(windowsManagedMSIRelayPath(m), windowsManagedMSIRelayOptions(sid, false))
	if e != nil {
		return g, e
	}
	defer store.Close()
	raw, e := store.Read("grant.json")
	if e != nil || decodeWindowsManagedMSIRelayJSON(raw, &g, 8192) != nil || store.Close() != nil {
		return g, ErrState
	}
	return g, nil
}

// The grant stays on the original anchor across renewal. A running relay must
// nevertheless stop using a replaced transport leaf; reloading the foreground
// client supplies the new leaf without extending the original grant expiry.
func currentWindowsManagedMSIRelayMaterial(m Material, reload func(string) (Material, error)) bool {
	if !m.valid() || !m.config.windowsInventory() || m.config.Profile != "tls" || reload == nil {
		return false
	}
	current, e := reload(m.configPath)
	return e == nil && current.valid() && current.binding == m.binding && current.config == m.config && bytes.Equal(current.authorityDER(), m.authorityDER()) && len(current.certificate.Certificate) > 0 && bytes.Equal(current.certificate.Certificate[0], m.certificate.Certificate[0]) && validateUpdatesActivatedMaterial(m.configPath, current) == nil
}
