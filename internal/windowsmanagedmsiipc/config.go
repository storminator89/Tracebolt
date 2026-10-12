package windowsmanagedmsiipc

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/keyvalidation"
	job "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"strings"
)

const ConfigVersion = "tracebolt.windows-managed-msi-service-config.v1"

const CoordinatedConfigVersion = "tracebolt.windows-managed-msi-service-config.v2"

// Config is entirely public. The private signing key and used executor ledger
// have separate protected files and are NEVER included in this digest.
type Config struct {
	Mutation                         *fence.Roster          `json:"mutation,omitempty"`
	ObserverConfigDigest             string                 `json:"observerConfigDigest"`
	SenderBinding                    string                 `json:"senderBinding"`
	ManagerOrigin                    string                 `json:"managerOrigin"`
	Version                          string                 `json:"version"`
	Grant                            job.Grant              `json:"grant"`
	ManagerPublicKey                 []byte                 `json:"managerPublicKey"`
	ExecutorPublicKey                []byte                 `json:"executorPublicKey"`
	Executable                       string                 `json:"executable"`
	ExecutableDigest                 string                 `json:"executableDigest"`
	ObserverReceipt                  windowsservice.Receipt `json:"observerReceipt"`
	ObserverProcessQueryAcknowledged bool                   `json:"observerProcessQueryAcknowledged"`
}

func (c Config) Validate() error {
	if !job.ValidDigest(c.ObserverConfigDigest) || c.SenderBinding == "" || c.ManagerOrigin == "" || !(c.Version == ConfigVersion && c.Mutation == nil && c.Grant.MutationPlanDigest == "" || c.Version == CoordinatedConfigVersion && job.ValidMutationRoster(c.Mutation, c.Grant)) || c.Grant.Validate() != nil || !c.Grant.DeliveryEnabled || !c.Grant.DeliveryAcknowledged || !c.Grant.ServiceRiskAcknowledged || !keyvalidation.Ed25519(c.ManagerPublicKey) || !keyvalidation.Ed25519(c.ExecutorPublicKey) || actionpermit.Digest(c.ManagerPublicKey) != c.Grant.Binding.KeyID || actionpermit.Digest(c.ExecutorPublicKey) != c.Grant.Binding.ExecutorKeyID || !c.ObserverReceipt.Complete || c.ObserverReceipt.Version != 1 || c.ObserverReceipt.InstallationID == "" || c.ObserverReceipt.ServiceSID == "" {
		return job.ErrInvalid
	}
	return c.peerUnchecked().Validate()
}
func (c Config) peerUnchecked() PeerConfig {
	raw, _ := json.Marshal(c)
	return PeerConfig{PeerVersion, c.Grant.Binding, bytes.Clone(c.ExecutorPublicKey), c.Executable, c.ExecutableDigest, actionpermit.Digest(raw)}
}
func (c Config) Peer() (PeerConfig, error) {
	if c.Validate() != nil {
		return PeerConfig{}, job.ErrInvalid
	}
	return c.peerUnchecked(), nil
}
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	if decode(raw, &c) != nil || c.Validate() != nil {
		return Config{}, job.ErrInvalid
	}
	return c, nil
}

// RootPath is fixed beside the existing observation state, never from IPC,
// environment variables, or an administrator-selected alternate directory.
func RootPath() (string, error) {
	l, e := windowsservice.ResolveLayout()
	if e != nil {
		return "", e
	}
	return strings.TrimSuffix(l.StateRoot, `\windows-agent`) + `\windows-managed-msi-service`, nil
}
func StoreOptions() windowsstate.Options {
	return windowsstate.Options{InstallerOnly: true, Names: []string{"config.json", "activation.json", "executor-key.json", "endpoint.json", "setup-intent.json", "setup-receipt.json", "image.json"}, LockName: "executor.lock", TempName: "executor.tmp", MaxBytes: job.MaxRecordBytes}
}

const ServiceName = "TraceboltWindowsDeployment"
