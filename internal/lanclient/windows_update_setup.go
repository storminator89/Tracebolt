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
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	job "localrmm/internal/windowsupdatejob"
)

// WindowsUpdateSetupIdentity contains only public immutable/current binding
// evidence. Ordinary TLS manager identity is independently taken from the fixed
// protected original bootstrap by the stopped-observer setup coordinator.
type WindowsUpdateSetupIdentity struct {
	ManagerID           string `json:"managerId"`
	DeviceID            string `json:"deviceId"`
	IncarnationDigest   string `json:"incarnationDigest"`
	ManagerOrigin       string `json:"managerOrigin"`
	SenderBinding       string `json:"senderBinding"`
	ConfigDigest        string `json:"configDigest"`
	LeafDigest          string `json:"leafDigest"`
	LeafPublicKeyDigest string `json:"leafPublicKeyDigest"`
	LeafNotBefore       int64  `json:"leafNotBefore"`
	LeafNotAfter        int64  `json:"leafNotAfter"`
}

func InspectWindowsUpdateSetupIdentity(path string, offer job.SetupOffer) (WindowsUpdateSetupIdentity, error) {
	m, e := Load(path)
	layout, le := windowsservice.ResolveLayout()
	fixed := windowsUpdateExecutorAuthority{layout: layout}
	if le != nil || path != filepath.Join(layout.EnrollmentRoot, "agent.json") || !fixed.fixedConfig(m.config) || e != nil || ValidateGuidedHandoff(path) != nil {
		return WindowsUpdateSetupIdentity{}, ErrState
	}
	return windowsUpdateSetupIdentity(path, m, offer, time.Now().UTC())
}
func windowsUpdateSetupIdentity(path string, m Material, o job.SetupOffer, now time.Time) (WindowsUpdateSetupIdentity, error) {
	var z WindowsUpdateSetupIdentity
	if o.Validate() != nil || now.Unix() <= 0 || now.Unix() >= o.ExpiresAt || m.configPath != path || !m.valid() || !m.config.windowsInventory() || m.config.Profile != "tls" || m.config.InsecureHTTPAcknowledged || validateUpdatesActivatedMaterial(path, m) != nil || m.config.AgentID != o.DeviceID || m.config.ManagerOrigin != o.ManagerOrigin || actionpermit.Digest(m.authorityDER()) != o.IncarnationDigest || m.renewal != nil && m.renewal.ManagerInstanceID != o.ManagerID {
		return z, ErrConfiguration
	}
	if len(m.certificate.Certificate) == 0 {
		return z, ErrConfiguration
	}
	leaf, e := x509.ParseCertificate(m.certificate.Certificate[0])
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return z, ErrConfiguration
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || bytes.Equal(key, o.ManagerPublicKey) {
		return z, ErrConfiguration
	}
	raw, e := json.Marshal(m.config)
	if e != nil {
		return z, ErrConfiguration
	}
	return WindowsUpdateSetupIdentity{o.ManagerID, o.DeviceID, o.IncarnationDigest, o.ManagerOrigin, m.binding, actionpermit.Digest(raw), actionpermit.Digest(leaf.Raw), actionpermit.Digest(key), leaf.NotBefore.Unix(), leaf.NotAfter.Unix()}, nil
}

// CheckWindowsUpdateRelayAbsent distinguishes an absent final root from a used,
// partial, corrupt or busy store. It never creates/adopts missing material.
func CheckWindowsUpdateRelayAbsent(path string, o job.SetupOffer) error {
	m, e := Load(path)
	if e != nil {
		return ErrState
	}
	if _, e = windowsUpdateSetupIdentity(path, m, o, time.Now().UTC()); e != nil {
		return e
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(windowsUpdateRelayPath(m), windowsUpdateRelayOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return job.ErrConflict
	}
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	return job.ErrConflict
}
func VerifyWindowsUpdateRelaySetup(path string, expected WindowsUpdateRelayGrant) error {
	m, e := Load(path)
	if e != nil || validateWindowsUpdateRelayGrant(m, expected, time.Now().UTC()) != nil {
		return ErrState
	}
	g, e := readWindowsUpdateRelay(m)
	a, _ := json.Marshal(g)
	b, _ := json.Marshal(expected)
	if e != nil || !bytes.Equal(a, b) || !currentWindowsUpdateRelayMaterial(m, Load) {
		return ErrState
	}
	return nil
}

// RetireWindowsUpdateRelay is only for the separately approved owned removal
// transaction. It requires the original exact grant bytes, not active expiry,
// and preserves all fields except Enabled=false. It never removes the store.
func RetireWindowsUpdateRelay(layout windowsservice.Layout, sid string, expected WindowsUpdateRelayGrant) error {
	if sid == "" || expected.ExecutorPeer.Validate() != nil || !expected.Enabled || !expected.Acknowledged {
		return ErrState
	}
	path := filepath.Dir(layout.EnrollmentRoot) + "-update-job-relay"
	s, e := windowsstate.Open(path, windowsUpdateRelayOptions(sid, false))
	if e != nil {
		return ErrState
	}
	defer s.Close()
	raw, e := s.Read("grant.json")
	want, _ := json.Marshal(expected)
	if e != nil || !bytes.Equal(raw, want) {
		return ErrState
	}
	expected.Enabled = false
	raw, e = json.Marshal(expected)
	if e != nil || s.Write("grant.json", raw) != nil || s.Verify() != nil || s.Close() != nil {
		return ErrState
	}
	return nil
}
