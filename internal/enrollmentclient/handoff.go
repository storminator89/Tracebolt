package enrollmentclient

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"os"
	"path/filepath"
)

type artifact struct {
	name string
	raw  []byte
}

func (s *session) handoff() (lanclient.Config, []artifact, []byte, error) {
	fail := func() (lanclient.Config, []artifact, []byte, error) { return lanclient.Config{}, nil, nil, ErrState }
	if !s.l.Activated {
		return fail()
	}
	c := lanclient.Config{SchemaVersion: lanclient.GuidedConfigVersion, Profile: s.l.Bootstrap.Profile, ManagerOrigin: s.l.Bootstrap.AgentOrigin, AgentID: s.l.Intent.DeviceID, CertificateFile: filepath.Join(s.opts.StateDirectory, "agent-cert.pem"), PrivateKeyFile: filepath.Join(s.opts.StateDirectory, "agent-key.pem"), StateDirectory: filepath.Join(s.opts.StateDirectory, "telemetry"), InsecureHTTPAcknowledged: s.opts.InsecureHTTPAcknowledged}
	if s.l.Bootstrap.CollectionProfile == enrollmentcrypto.CollectionProfileOperational {
		c.SchemaVersion = lanclient.OperationalConfigVersion
		c.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
	}
	if s.l.Bootstrap.CollectionProfile == enrollmentcrypto.CollectionProfilePackages {
		c.SchemaVersion = lanclient.PackageConfigVersion
		c.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	}
	if c.Profile == "tls" {
		c.ServerCAFile = filepath.Join(s.opts.StateDirectory, "server-ca.pem")
	}
	if c.Validate() != nil {
		return fail()
	}
	key, e := x509.MarshalPKCS8PrivateKey(s.key)
	if e != nil {
		return fail()
	}
	defer clear(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		clear(keyPEM)
		return fail()
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if c.Profile == "tls" {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.issuerDER})...)
	}
	config, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		clear(keyPEM)
		return fail()
	}
	files := []artifact{{"agent-key.pem", keyPEM}, {"agent-cert.pem", cert}, {"agent.json", config}}
	if c.Profile == "tls" {
		files = append(files, artifact{"server-ca.pem", []byte(s.l.Bootstrap.ServerCAPEM)})
	}
	ready, _ := json.Marshal(struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated bool   `json:"serverAuthenticated"`
	}{"tracebolt.enrollment-ready.v2", fingerprint(config), fingerprint(der), c.Profile == "tls"})
	return c, files, ready, nil
}
func clearArtifacts(files []artifact) {
	for _, f := range files {
		clear(f.raw)
	}
}

// Validate every preexisting output against local durable identity before any
// request. HandoffPrepared protects telemetry continuity independently of the
// final ready marker, including interrupted marker publication and deletion.
func (s *session) validateArtifacts() error {
	expected := map[string][]byte{}
	var files []artifact
	var config lanclient.Config
	if s.l.Activated {
		c, f, ready, e := s.handoff()
		config = c
		if e != nil {
			return e
		}
		files = f
		defer clearArtifacts(files)
		for _, a := range files {
			expected[a.name] = a.raw
		}
		expected["ready.json"] = ready
	}
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "agent.json", "server-ca.pem", "ready.json"} {
		raw, e := s.store.Read(name)
		if errors.Is(e, os.ErrNotExist) {
			if (s.l.HandoffPrepared || s.l.SenderInitializationStarted && name != "agent.json") && name != "ready.json" && (name != "server-ca.pem" || s.l.Bootstrap.Profile == "tls") {
				return ErrState
			}
			continue
		}
		if e != nil {
			return ErrState
		}
		want, ok := expected[name]
		same := ok && bytes.Equal(raw, want)
		clear(raw)
		if !same || name == "ready.json" && !s.l.HandoffPrepared || name == "agent.json" && !s.l.SenderInitializationStarted {
			return ErrState
		}
	}
	exists, e := s.store.TelemetryExists()
	if e != nil || exists && !s.l.SenderInitializationStarted || !exists && s.l.SenderInitializationStarted {
		return ErrState
	}
	if s.l.SenderInitializationStarted && lanclient.ValidateGuidedState(config) != nil {
		return ErrState
	}
	return nil
}
func (s *session) publish() (Result, error) {
	if e := s.validateArtifacts(); e != nil {
		return Result{}, e
	}
	c, files, ready, e := s.handoff()
	if e != nil {
		return Result{}, e
	}
	defer clearArtifacts(files)
	// Material comes first. No runnable configuration is published until the
	// sender's exact bound sequence ledger has been durably initialized.
	for _, f := range files {
		if f.name == "agent.json" {
			continue
		}
		if e = s.writeArtifactIfAbsent(f); e != nil {
			return Result{}, e
		}
	}
	if !s.l.SenderInitializationStarted {
		// Persist before initialization. A restart may validate a completed
		// initialization, but must never invoke the initializer a second time.
		s.l.SenderInitializationStarted = true
		if e = s.save(); e != nil {
			return Result{}, e
		}
		if e = s.store.EnsureTelemetry(); e != nil {
			return Result{}, e
		}
		if e = lanclient.InitializeGuidedState(c); e != nil {
			return Result{}, ErrState
		}
	} else if lanclient.ValidateGuidedState(c) != nil {
		return Result{}, ErrState
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
	if _, e = s.store.Read("ready.json"); errors.Is(e, os.ErrNotExist) {
		if e = s.store.Write("ready.json", ready); e != nil {
			return Result{}, e
		}
	} else if e != nil {
		return Result{}, e
	}
	if e = s.notify("ready"); e != nil {
		return Result{}, e
	}
	return Result{Config: c, ConfigPath: filepath.Join(s.opts.StateDirectory, "agent.json"), KeyFingerprint: s.trust.KeyFingerprint, ComparisonCode: s.trust.ComparisonCode, ServerAuthenticated: c.Profile == "tls"}, nil
}

func (s *session) writeArtifactIfAbsent(f artifact) error {
	raw, err := s.store.Read(f.name)
	if err == nil {
		equal := bytes.Equal(raw, f.raw)
		clear(raw)
		if !equal {
			return ErrState
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ErrState
	}
	return s.store.Write(f.name, f.raw)
}
