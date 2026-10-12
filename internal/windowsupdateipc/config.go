package windowsupdateipc

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/keyvalidation"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	job "localrmm/internal/windowsupdatejob"
	"strings"
)

const ServiceConfigVersion = "tracebolt.windows-update-service-config.v1"
const ServiceName = "TraceboltWindowsCachedUpdate"

const ConfigVersion = "tracebolt.windows-update-foreground.v1"

const CoordinatedConfigVersion = "tracebolt.windows-update-foreground.v2"

// Config is entirely public. The private signing key and used executor ledger
// have separate protected files and are NEVER included in this digest.
type Config struct {
	ObserverConfigDigest             string                 `json:"observerConfigDigest,omitempty"`
	SenderBinding                    string                 `json:"senderBinding,omitempty"`
	ManagerOrigin                    string                 `json:"managerOrigin,omitempty"`
	Mutation                         *fence.Roster          `json:"mutation,omitempty"`
	Version                          string                 `json:"version"`
	Consent                          job.Consent            `json:"consent"`
	ManagerPublicKey                 []byte                 `json:"managerPublicKey"`
	ExecutorPublicKey                []byte                 `json:"executorPublicKey"`
	Executable                       string                 `json:"executable"`
	ExecutableDigest                 string                 `json:"executableDigest"`
	ObserverReceipt                  windowsservice.Receipt `json:"observerReceipt"`
	ObserverProcessQueryAcknowledged bool                   `json:"observerProcessQueryAcknowledged"`
}

func (c Config) Validate() error {
	if c.Version != ServiceConfigVersion && (c.ObserverConfigDigest != "" || c.SenderBinding != "" || c.ManagerOrigin != "") || c.Version == ServiceConfigVersion && (!actionpermit.ValidDigest(c.ObserverConfigDigest) || c.SenderBinding == "" || c.ManagerOrigin == "" || !c.ObserverProcessQueryAcknowledged || c.Consent.Version != job.BackgroundConsentVersion) || !(c.Version == ConfigVersion && c.Mutation == nil && c.Consent.MutationPlanDigest == "" || c.Version == CoordinatedConfigVersion && c.Consent.Version == job.CoordinatedConsentVersion && job.ValidMutationRoster(c.Mutation, c.Consent) || c.Version == ServiceConfigVersion && job.ValidMutationRoster(c.Mutation, c.Consent)) || c.Consent.Validate() != nil || !c.Consent.Enabled || !c.Consent.Acknowledged || !keyvalidation.Ed25519(c.ManagerPublicKey) || !keyvalidation.Ed25519(c.ExecutorPublicKey) || actionpermit.Digest(c.ManagerPublicKey) != c.Consent.Binding.KeyID || actionpermit.Digest(c.ExecutorPublicKey) != c.Consent.Binding.ExecutorKeyID || !c.ObserverReceipt.Complete || c.ObserverReceipt.Version != 1 || c.ObserverReceipt.InstallationID == "" || c.ObserverReceipt.ServiceSID == "" {
		return job.ErrInvalid
	}
	return c.peerUnchecked().Validate()
}
func (c Config) peerUnchecked() PeerConfig {
	raw, _ := json.Marshal(c)
	v := PeerVersion
	if c.Version == ServiceConfigVersion {
		v = ServicePeerVersion
	}
	return PeerConfig{v, c.Consent.Binding, bytes.Clone(c.ExecutorPublicKey), c.Executable, c.ExecutableDigest, actionpermit.Digest(raw)}
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
	return strings.TrimSuffix(l.StateRoot, `\windows-agent`) + `\windows-update-executor`, nil
}
func StoreOptions() windowsstate.Options {
	return windowsstate.Options{InstallerOnly: true, Names: []string{"config.json", "executor-key.json", "started.json", "receipt.json", "executor.json", "provision.json", "progress.json", "removed.json"}, LockName: "executor.lock", TempName: "executor.tmp", MaxBytes: job.MaxBytes}
}

func ServiceRootPath() (string, error) {
	l, e := windowsservice.ResolveLayout()
	if e != nil {
		return "", e
	}
	return strings.TrimSuffix(l.StateRoot, `\windows-agent`) + `\windows-update-service`, nil
}
func ServiceStoreOptions() windowsstate.Options {
	o := StoreOptions()
	o.Names = append(o.Names, "service.json", "activation.json")
	return o
}
