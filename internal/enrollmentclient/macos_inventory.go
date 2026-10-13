package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	inventory "localrmm/internal/macosinventory"
	sender "localrmm/internal/macosinventorysender"
	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
	"localrmm/internal/renewalidentity"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const macOSInventoryEnrollmentVersion = "tracebolt.enrollment-macos-inventory.v1"

// This immutable approval is carried by the enrollment ledger, independently of
// the inventory store. SenderInitializationStarted is its permanent used fence.
type macOSInventoryEnrollment struct {
	Version        string `json:"version"`
	Acknowledged   bool   `json:"acknowledged"`
	GrantID        string `json:"grantId"`
	Consent        string `json:"consent"`
	OriginalEnable string `json:"originalEnable"`
}

const MacOSInventoryPrivacy = inventory.Privacy + " Capture runs at most once per minute. The latest generation expires 24 hours after its original capture, including pending retries. This creates a new protected identity and a one-time inventory grant; it does not adopt an existing basic identity. No service is installed."

// RunFreshMacOSInventory is the only enrollment entry point for this profile.
// Explicit complete local disclosure/approval precedes directories, keys, grants
// and network. The hidden invitation callback retains its existing contract.
func RunFreshMacOSInventory(ctx context.Context, b Bootstrap, o Options) (Result, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() <= 0 {
		return Result{}, ErrBootstrap
	}
	if e := approveMacOSInventory(ctx, b, o, runtime.GOOS); e != nil {
		return Result{}, e
	}
	o.inventoryEnrollment = true
	return runEnrollment(ctx, b, o)
}
func approveMacOSInventory(ctx context.Context, b Bootstrap, o Options, platform string) error {
	if ctx == nil || ctx.Err() != nil || platform != "darwin" || b.Profile != "tls" || b.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory || o.ClaimOnly || o.ResumeOnly || o.InsecureHTTPAcknowledged || o.WindowsInventoryAcknowledged || o.ApproveMacOSInventory == nil || (b.RenewalPolicy != "") != o.AutomaticRenewalAcknowledged {
		return ErrBootstrap
	}
	if _, e := validateBootstrap(b, time.Now()); e != nil {
		return e
	}
	ok, e := o.ApproveMacOSInventory(MacOSInventoryPrivacy)
	if e != nil || !ok {
		return ErrInput
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
func validateEnrollmentPlatform(b Bootstrap, platform string, explicit bool) error {
	if explicit {
		if platform == "darwin" && b.Profile == "tls" && b.CollectionProfile == enrollmentcrypto.CollectionProfileMacOSInventory {
			return nil
		}
		return ErrBootstrap
	}
	return validatePlatformBootstrap(b, platform)
}
func (s *session) validateEnrollmentSnapshot(v enrollmentstate.Snapshot, b Bootstrap, platform string) error {
	if v.Platform != platform || validateEnrollmentPlatform(b, platform, s.opts.inventoryEnrollment) != nil {
		return ErrResponse
	}
	return nil
}
func (s *session) validateMacOSInventoryLedger() error {
	g := s.l.MacOSInventory
	if s.l.Bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory {
		if g != nil {
			return ErrState
		}
		return nil
	}
	if !s.opts.inventoryEnrollment || s.l.Bootstrap.Profile != "tls" || g == nil || g.Version != macOSInventoryEnrollmentVersion || !g.Acknowledged || len(g.GrantID) != 32 || !enrollmentcrypto.ValidID("grant_"+g.GrantID, "grant_") {
		return ErrState
	}
	if (g.Consent == "") != (g.OriginalEnable == "") || g.OriginalEnable != "" && !s.l.Activated || s.l.SenderInitializationStarted && g.OriginalEnable == "" {
		return ErrState
	}
	return nil
}
func (s *session) macOSInventoryOriginal() (lanclient.MacOSInventoryConfig, []byte, []byte, error) {
	var zero lanclient.MacOSInventoryConfig
	if s.validateMacOSInventoryLedger() != nil || !s.l.Activated || s.l.MacOSInventory.OriginalEnable == "" {
		return zero, nil, nil, ErrState
	}
	g := s.l.MacOSInventory
	original, e := decode64(g.OriginalEnable, wire.MaxControlBytes)
	if e != nil {
		return zero, nil, nil, ErrState
	}
	enable, e := wire.DecodeControl(original)
	if e != nil || !enable.Enabled || enable.GrantID != g.GrantID {
		return zero, nil, nil, ErrState
	}
	consent, e := decode64(g.Consent, 1024)
	if e != nil {
		return zero, nil, nil, ErrState
	}
	cc, e := inventory.DecodeConsent(consent, enable.Binding.SenderBinding)
	if e != nil || !cc.Enabled || cc.GrantID != g.GrantID {
		return zero, nil, nil, ErrState
	}
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		return zero, nil, nil, ErrState
	}
	anchor, e := x509.ParseCertificate(der)
	if e != nil {
		return zero, nil, nil, ErrState
	}
	binding, e := sender.OriginalBinding(s.l.Bootstrap.AgentOrigin, s.l.Intent.DeviceID, anchor)
	if e != nil || binding != enable.Binding || enable.ChangedAt.Before(anchor.NotBefore) || !enable.ChangedAt.Before(anchor.NotAfter) {
		return zero, nil, nil, ErrState
	}
	dir := s.opts.StateDirectory
	c := lanclient.MacOSInventoryConfig{Config: lanclient.Config{SchemaVersion: lanclient.MacOSInventoryConfigVersion, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileMacOSInventory, ManagerOrigin: s.l.Bootstrap.AgentOrigin, AgentID: s.l.Intent.DeviceID, CertificateFile: filepath.Join(dir, "agent-cert.pem"), PrivateKeyFile: filepath.Join(dir, "agent-key.pem"), ServerCAFile: filepath.Join(dir, "server-ca.pem"), StateDirectory: filepath.Join(dir, "telemetry")}, ConsentFile: filepath.Join(dir, lanclient.MacOSInventoryConsentName), OriginalEnableFile: filepath.Join(dir, lanclient.MacOSInventoryEnableName)}
	if s.l.Bootstrap.RenewalPolicy != "" {
		c.RenewalManifestFile = filepath.Join(dir, renewalidentity.ManifestName)
	}
	if c.Validate(filepath.Join(dir, "agent.json")) != nil {
		return zero, nil, nil, ErrState
	}
	return c, consent, original, nil
}
func (s *session) prepareMacOSInventoryGrant() error {
	if s.validateMacOSInventoryLedger() != nil || !s.l.Activated {
		return ErrState
	}
	if s.l.MacOSInventory.OriginalEnable != "" {
		_, _, _, e := s.macOSInventoryOriginal()
		return e
	}
	if s.l.SenderInitializationStarted || s.l.HandoffPrepared {
		return ErrState
	}
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		return ErrState
	}
	anchor, e := x509.ParseCertificate(der)
	if e != nil {
		return ErrState
	}
	now := time.Now().UTC()
	if _, e = enrollmentcrypto.VerifyIssued(der, s.issuerDER, s.l.Intent, now); e != nil {
		return ErrState
	}
	binding, e := sender.OriginalBinding(s.l.Bootstrap.AgentOrigin, s.l.Intent.DeviceID, anchor)
	if e != nil {
		return ErrState
	}
	grant := s.l.MacOSInventory.GrantID
	control := wire.Control{SchemaVersion: wire.ControlVersion, Binding: binding, GrantID: grant, GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: now}
	original, e := wire.EncodeControl(control)
	if e != nil {
		return ErrState
	}
	consent, e := inventory.EncodeConsent(inventory.Consent{SchemaVersion: inventory.ConsentVersion, Scope: inventory.Scope, SenderBinding: binding.SenderBinding, GrantID: grant, Enabled: true}, binding.SenderBinding)
	if e != nil {
		return ErrState
	}
	s.l.MacOSInventory.Consent = base64.RawStdEncoding.EncodeToString(consent)
	s.l.MacOSInventory.OriginalEnable = base64.RawStdEncoding.EncodeToString(original)
	return s.save()
}
func (s *session) macOSInventoryHandoff() (lanclient.Config, []artifact, []byte, error) {
	c, consent, enable, e := s.macOSInventoryOriginal()
	if e != nil {
		return lanclient.Config{}, nil, nil, e
	}
	key, e := x509.MarshalPKCS8PrivateKey(s.key)
	if e != nil {
		return lanclient.Config{}, nil, nil, ErrState
	}
	defer clear(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		clear(keyPEM)
		return lanclient.Config{}, nil, nil, ErrState
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.issuerDER})...)
	raw, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		clear(keyPEM)
		return lanclient.Config{}, nil, nil, ErrState
	}
	files := []artifact{{"agent-key.pem", keyPEM}, {"agent-cert.pem", cert}, {"server-ca.pem", []byte(s.l.Bootstrap.ServerCAPEM)}, {lanclient.MacOSInventoryConsentName, consent}, {lanclient.MacOSInventoryEnableName, enable}, {"agent.json", raw}}
	ready, _ := json.Marshal(struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated bool   `json:"serverAuthenticated"`
	}{"tracebolt.enrollment-ready.macos-inventory.v1", fingerprint(raw), fingerprint(der), true})
	return c.Config, files, ready, nil
}
func (s *session) validateMacOSInventoryArtifacts() error {
	if s.validateMacOSInventoryLedger() != nil {
		return ErrState
	}
	expected := map[string][]byte{}
	if s.l.MacOSInventory.OriginalEnable != "" {
		_, files, ready, e := s.macOSInventoryHandoff()
		if e != nil {
			return e
		}
		defer clearArtifacts(files)
		for _, f := range files {
			expected[f.name] = f.raw
		}
		expected["ready.json"] = ready
	}
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "server-ca.pem", lanclient.MacOSInventoryConsentName, lanclient.MacOSInventoryEnableName, "agent.json", "ready.json"} {
		raw, e := s.store.Read(name)
		valid := validateMacOSInventoryArtifact(*s.l.ledgerData, name, raw, e, expected[name])
		clear(raw)
		if valid != nil {
			return valid
		}
	}
	if _, e := s.store.Read(serviceMarkerName); !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	exists, e := s.store.TelemetryExists()
	if e != nil || exists != s.l.SenderInitializationStarted {
		return ErrState
	}
	if s.l.Bootstrap.RenewalPolicy == "" {
		for _, n := range []string{renewalidentity.ManifestName, renewalidentity.LedgerName} {
			if _, e := s.store.Read(n); !errors.Is(e, os.ErrNotExist) {
				return ErrState
			}
		}
	}
	if s.l.SenderInitializationStarted && !s.opts.inventoryAuthorityReading && !s.opts.renewalReconcile {
		c, _, enable, e := s.macOSInventoryOriginal()
		if e != nil {
			return e
		}
		return validateMacOSInventoryStorage(c.StateDirectory, enable)
	}
	return nil
}
func validateMacOSInventoryStorage(path string, enable []byte) error {
	st, raw, e := sender.OpenExistingStorage(path, enable)
	if e != nil {
		return ErrState
	}
	valid := state.ValidateCheckpoint(raw, enable) == nil
	closeErr := st.Close()
	if !valid || closeErr != nil {
		return ErrState
	}
	return nil
}
func initializeMacOSInventoryStorage(path string, enable []byte) error {
	st, e := sender.OpenFreshStorage(path, enable)
	if e != nil {
		return ErrState
	}
	s, e := state.InitializeFresh(st, enable, time.Now().UTC())
	if s != nil {
		s.Close()
	}
	closeErr := st.Close()
	if e != nil || closeErr != nil {
		return ErrState
	}
	return nil
}
func (s *session) publishMacOSInventory() (Result, error) {
	if e := s.prepareMacOSInventoryGrant(); e != nil {
		return Result{}, e
	}
	if e := s.validateArtifacts(); e != nil {
		return Result{}, e
	}
	c, files, ready, e := s.macOSInventoryHandoff()
	if e != nil {
		return Result{}, e
	}
	defer clearArtifacts(files)
	for _, f := range files {
		if f.name != "agent.json" {
			if e = s.writeArtifactIfAbsent(f); e != nil {
				return Result{}, e
			}
		}
	}
	if s.l.Bootstrap.RenewalPolicy != "" {
		if e = s.prepareRenewal(); e != nil {
			return Result{}, e
		}
	}
	_, _, enable, e := s.macOSInventoryOriginal()
	if e != nil {
		return Result{}, e
	}
	if e = initializeMacOSInventoryOnce(s.l.SenderInitializationStarted,
		func() error { s.l.SenderInitializationStarted = true; return s.save() },
		s.store.EnsureTelemetry,
		func() error { return initializeMacOSInventoryStorage(c.StateDirectory, enable) },
		func() error { return validateMacOSInventoryStorage(c.StateDirectory, enable) }); e != nil {
		return Result{}, e
	}

	for _, f := range files {
		if f.name == "agent.json" {
			if e = s.writeArtifactIfAbsent(f); e != nil {
				return Result{}, e
			}
		}
	}
	if !s.l.HandoffPrepared {
		s.l.HandoffPrepared = true
		if e = s.save(); e != nil {
			return Result{}, e
		}
	}
	if e = s.writeArtifactIfAbsent(artifact{"ready.json", ready}); e != nil {
		return Result{}, e
	}
	if s.l.Bootstrap.RenewalPolicy != "" && !s.l.RenewalReadyPublished {
		s.l.RenewalReadyPublished = true
		if e = s.save(); e != nil {
			return Result{}, e
		}
	}
	if e = s.notify("ready"); e != nil {
		return Result{}, e
	}
	return Result{Config: c, ConfigPath: filepath.Join(s.opts.StateDirectory, "agent.json"), KeyFingerprint: s.trust.KeyFingerprint, ComparisonCode: s.trust.ComparisonCode, ServerAuthenticated: true}, nil
}

// The primary fence is committed first and is never cleared. Once started,
// recovery has exactly one route: validate the existing independent used state.
func initializeMacOSInventoryOnce(started bool, commitUsed, ensureDirectory, fresh, existing func() error) error {
	if commitUsed == nil || ensureDirectory == nil || fresh == nil || existing == nil {
		return ErrState
	}
	if started {
		return existing()
	}
	if e := commitUsed(); e != nil {
		return e
	}
	if e := ensureDirectory(); e != nil {
		return e
	}
	return fresh()
}

func validateMacOSInventoryArtifact(l ledgerData, name string, raw []byte, readErr error, want []byte) error {
	if errors.Is(readErr, os.ErrNotExist) {
		if l.HandoffPrepared || l.RenewalReadyPublished || l.SenderInitializationStarted && name != "agent.json" && name != "ready.json" {
			return ErrState
		}
		return nil
	}
	if readErr != nil || len(want) == 0 || !bytes.Equal(raw, want) || name == "agent.json" && !l.SenderInitializationStarted || name == "ready.json" && !l.HandoffPrepared {
		return ErrState
	}
	return nil
}
