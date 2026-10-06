package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"localrmm/internal/actionclient"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionwire"
	"localrmm/internal/inventorystate"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/systemstate"
	"path/filepath"
	"time"
)

const ActionSetupIdentityVersion = "tracebolt.action-setup-identity.v1"
const ActionSetupReadinessVersion = "tracebolt.action-setup-readiness.v1"

// ActionSetupIdentity is the bounded public projection of an already activated
// complete sender. It contains no paths, private key, certificate or config body.
type ActionSetupIdentity struct {
	SchemaVersion     string `json:"schemaVersion"`
	SenderBinding     string `json:"senderBinding"`
	ManagerOrigin     string `json:"managerOrigin"`
	EndpointID        string `json:"endpointId"`
	IncarnationDigest string `json:"incarnationDigest"`
	TransportProfile  string `json:"transportProfile"`
	AgentUID          uint32 `json:"agentUid"`
	AgentGID          uint32 `json:"agentGid"`
}

type ActionSetupReadiness struct {
	SchemaVersion string                    `json:"schemaVersion"`
	Identity      ActionSetupIdentity       `json:"identity"`
	Capabilities  actionhelper.Capabilities `json:"capabilities"`
}

// ReadActionSetupIdentity performs local protected reads only. It requires the
// existing nonroot service identity and validates all three existing sender
// ledgers. It does not lock, create, repair, collect, connect or transmit.
func ReadActionSetupIdentity(path string) (ActionSetupIdentity, error) {
	m, uid, gid, err := readActionSetupMaterial(path)
	if err != nil {
		return ActionSetupIdentity{}, err
	}
	return projectActionSetupIdentity(m, uid, gid), nil
}

func projectActionSetupIdentity(m Material, uid, gid uint32) ActionSetupIdentity {
	return ActionSetupIdentity{SchemaVersion: ActionSetupIdentityVersion, SenderBinding: m.binding,
		ManagerOrigin: m.config.ManagerOrigin, EndpointID: m.config.AgentID,
		IncarnationDigest: "sha256:" + journalLeaf(m), TransportProfile: actionProfile(m), AgentUID: uid, AgentGID: gid}
}

func readActionSetupMaterial(path string) (Material, uint32, uint32, error) {
	uid, gid, ok := journalAgentIdentity()
	if !ok {
		return Material{}, 0, 0, errActionDenied
	}
	m, err := loadActionSetupMaterial(path)
	if err != nil {
		return Material{}, 0, 0, err
	}
	return m, uid, gid, nil
}

func loadActionSetupMaterial(path string) (Material, error) {
	raw, err := lanconfig.ReadProtected(path, true, 16384)
	if err != nil {
		return Material{}, ErrConfiguration
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile") != nil || !c.complete() {
		return Material{}, ErrConfiguration
	}
	m, err := loadConfig(c)
	if err != nil || !m.valid() {
		return Material{}, ErrConfiguration
	}
	readyPath := filepath.Join(filepath.Dir(path), "ready.json")
	readyRaw, err := lanconfig.ReadProtected(readyPath, true, 4096)
	if err != nil {
		return Material{}, ErrState
	}
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated *bool  `json:"serverAuthenticated"`
	}
	hash := sha256.Sum256(raw)
	if lanconfig.StrictObject(readyRaw, &ready, "version", "configHash", "certificateHash", "serverAuthenticated") != nil ||
		ready.Version != "tracebolt.enrollment-ready.v2" || ready.ConfigHash != hex.EncodeToString(hash[:]) ||
		ready.CertificateHash != journalLeaf(m) || ready.ServerAuthenticated == nil || *ready.ServerAuthenticated != (c.Profile == "tls") {
		return Material{}, ErrState
	}
	if lanclientstate.InspectExisting(c.StateDirectory, m.binding) != nil ||
		inventorystate.InspectExisting(inventoryStateDirectory(c), m.binding, c.AgentID) != nil ||
		systemstate.InspectExisting(systemStateDirectory(c), systemStateBinding(m)) != nil {
		return Material{}, ErrState
	}
	// Recheck the activated handoff and credentials after the ledger reads. A
	// changed enrollment/configuration cannot be projected as the old identity.
	currentRaw, err := lanconfig.ReadProtected(path, true, 16384)
	if err != nil || !bytes.Equal(raw, currentRaw) {
		return Material{}, ErrConfiguration
	}
	currentReady, err := lanconfig.ReadProtected(readyPath, true, 4096)
	if err != nil || !bytes.Equal(readyRaw, currentReady) {
		return Material{}, ErrState
	}
	current, err := loadConfig(c)
	if err != nil || !current.valid() || current.binding != m.binding || journalLeaf(current) != journalLeaf(m) {
		return Material{}, ErrConfiguration
	}
	return current, nil
}

// CheckActionSetupReadiness only connects to the fixed authenticated action
// helper socket for Capabilities, after validating the actual enabled grant.
// There is no manager transport, collection, claim, submit or status path here.
func CheckActionSetupReadiness(ctx context.Context, path string) (ActionSetupReadiness, error) {
	return checkActionSetupReadiness(ctx, path, readActionSetupMaterial, loadActionLocal, actionclient.Client{}.Capabilities, func() time.Time { return time.Now().UTC() })
}

func checkActionSetupReadiness(ctx context.Context, path string,
	material func(string) (Material, uint32, uint32, error), local func(Material) (actionLocal, error),
	capabilities func(context.Context) (actionhelper.Capabilities, error), now func() time.Time) (ActionSetupReadiness, error) {
	if ctx == nil || ctx.Err() != nil {
		return ActionSetupReadiness{}, errActionDenied
	}
	m, uid, gid, err := material(path)
	if err != nil {
		return ActionSetupReadiness{}, err
	}
	l, err := local(m)
	if err != nil || validateActionLocal(l.policy, m, uid, gid) != nil {
		return ActionSetupReadiness{}, errActionDenied
	}
	c, err := capabilities(ctx)
	if err != nil || !c.Enabled || matchActionCapabilities(c, l, m) != nil || actionwire.CheckCapabilityTime(c, now()) != nil {
		return ActionSetupReadiness{}, errActionDenied
	}
	fresh, freshUID, freshGID, err := material(path)
	if err != nil || freshUID != uid || freshGID != gid || fresh.config != m.config || fresh.binding != m.binding || journalLeaf(fresh) != journalLeaf(m) {
		return ActionSetupReadiness{}, errActionDenied
	}
	current, err := local(fresh)
	if err != nil || current.revision != l.revision || current.policy != l.policy || ctx.Err() != nil || actionwire.CheckCapabilityTime(c, now()) != nil {
		return ActionSetupReadiness{}, errActionDenied
	}
	return ActionSetupReadiness{SchemaVersion: ActionSetupReadinessVersion, Identity: projectActionSetupIdentity(m, uid, gid), Capabilities: c}, nil
}
