package windowssoftwareipc

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowssoftwarejob"
	"localrmm/internal/windowsstate"
	"strings"
)

const ConfigVersion = "tracebolt.windows-software-foreground.v1"

// Config is entirely public. The private signing key and used executor ledger
// have separate protected files and are NEVER included in this digest.
type Config struct {
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
	if c.Version != ConfigVersion || c.Consent.Validate() != nil || !c.Consent.Enabled || !c.Consent.Acknowledged || !keyvalidation.Ed25519(c.ManagerPublicKey) || !keyvalidation.Ed25519(c.ExecutorPublicKey) || actionpermit.Digest(c.ManagerPublicKey) != c.Consent.Binding.KeyID || actionpermit.Digest(c.ExecutorPublicKey) != c.Consent.Binding.ExecutorKeyID || !c.ObserverReceipt.Complete || c.ObserverReceipt.Version != 1 || c.ObserverReceipt.InstallationID == "" || c.ObserverReceipt.ServiceSID == "" {
		return job.ErrInvalid
	}
	return c.peerUnchecked().Validate()
}
func (c Config) peerUnchecked() PeerConfig {
	raw, _ := json.Marshal(c)
	return PeerConfig{PeerVersion, c.Consent.Binding, bytes.Clone(c.ExecutorPublicKey), c.Executable, c.ExecutableDigest, actionpermit.Digest(raw)}
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
	return strings.TrimSuffix(l.StateRoot, `\windows-agent`) + `\windows-software-executor`, nil
}
func StoreOptions() windowsstate.Options {
	return windowsstate.Options{InstallerOnly: true, Names: []string{"config.json", "executor-key.json", "started.json", "receipt.json", "executor.json", "provision.json", "progress.json", "removed.json", "package.json"}, LockName: "executor.lock", TempName: "executor.tmp", MaxBytes: job.MaxBytes}
}
