package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"

	"localrmm/internal/lanclient"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lantrust"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
)

// Acceptance-only proof, not a production alternate identity loader. The
// completed protected receipt records the coordinator's pre-Start identity and
// grant validation. Capture immutable bytes while that owned service exists;
// never acquire sender/grant locks while the reporting service is running.
// Its foreground sender retains its exclusive lock even during sleep.
// Once the held SCM handle proves stopped/deletion-pending, read grants and the
// sender with the ORIGINAL receipt SID, then require identical stopped bytes
// after SCM absence. No LookupServiceSID, repair, creation, or mutation belongs
// in either stopped verification. All store handles close within each read.
type setupRetentionStore interface {
	Read(string) ([]byte, error)
	Entries() ([]string, error)
	Verify() error
	Close() error
}
type setupRetentionOpen func(string, windowsstate.Options) (setupRetentionStore, error)
type setupRetainedState struct {
	receipt   installReceipt
	immutable map[string][32]byte
	stopped   map[string][32]byte
}

type setupRetentionSpec struct {
	label, path     string
	options         windowsstate.Options
	files, children []string
}

func setupRetentionCore(r installReceipt) []setupRetentionSpec {
	l, sid := r.Service.Layout, r.Service.ServiceSID
	enrollment := []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "agent.json", "ready.json", "service-enrollment.json"}
	if !r.ReadSetup.Consent.InsecureHTTPAcknowledged {
		enrollment = append(enrollment, "server-ca.pem")
	}
	return []setupRetentionSpec{
		{"receipt", l.StateRoot + "-installer", windowsagentconfig.Installer(false), []string{"intent.json", "receipt.json"}, nil},
		{"runtime", l.StateRoot, windowsagentconfig.RuntimeRoot(sid, false), []string{"bootstrap.json"}, []string{"enrollment"}},
		{"enrollment", l.EnrollmentRoot, windowsagentconfig.Enrollment(sid, false), enrollment, []string{"telemetry"}},
	}
}

func setupRetentionRead(ctx context.Context, spec setupRetentionSpec, open setupRetentionOpen) (result map[string][]byte, err error) {
	if ctx == nil || ctx.Err() != nil || open == nil || spec.options.Create {
		return nil, setupgate.ErrGuard
	}
	s, err := open(spec.path, spec.options)
	if err != nil || s == nil {
		if s != nil {
			_ = s.Close()
		}
		return nil, setupgate.ErrGuard
	}
	result = map[string][]byte{}
	defer func() {
		// Close exactly once on every path. Even otherwise valid bytes cannot
		// escape if releasing protected-store ownership fails.
		if s.Close() != nil || ctx.Err() != nil {
			err = setupgate.ErrGuard
		}
		if err != nil {
			setupRetentionClear(result)
			result = nil
		}
	}()
	entries, e := s.Entries()
	want := append(slices.Clone(spec.files), spec.children...)
	slices.Sort(want)
	if e != nil || !slices.Equal(entries, want) {
		return result, setupgate.ErrGuard
	}
	for _, name := range spec.files {
		if ctx.Err() != nil {
			return result, setupgate.ErrGuard
		}
		raw, e := s.Read(name)
		if e != nil || len(raw) == 0 || int64(len(raw)) > spec.options.MaxBytes {
			clear(raw)
			return result, setupgate.ErrGuard
		}
		result[name] = raw
	}
	if s.Verify() != nil || ctx.Err() != nil {
		return result, setupgate.ErrGuard
	}
	return result, nil
}
func setupRetentionClear(raw map[string][]byte) {
	for _, b := range raw {
		clear(b)
	}
}
func setupRetentionHashes(label string, raw map[string][]byte, out map[string][32]byte) {
	for name, b := range raw {
		out[label+"/"+name] = sha256.Sum256(b)
	}
}
func setupRetentionDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// This validates the immutable ready/config/certificate linkage against the
// ORIGINAL coordinator binding. Material's full live-SID certificate/trust
// validation is additionally required at capture via lanclient.Load, which
// does not acquire the sender or grant locks. The private key never persists
// in this observation; every byte buffer is cleared before returning.
func setupRetentionIdentity(r installReceipt, raw map[string][]byte) error {
	// Match the active loader/handoff's narrower per-artifact limits even
	// though the fixed enrollment store permits larger ledger records.
	for _, bound := range []struct {
		name string
		max  int
	}{
		{"agent.json", 16384}, {"agent-cert.pem", 65536}, {"agent-key.pem", 32768}, {"ready.json", 4096},
	} {
		if len(raw[bound.name]) == 0 || len(raw[bound.name]) > bound.max {
			return setupgate.ErrGuard
		}
	}
	if ca := raw["server-ca.pem"]; len(ca) > 65536 || (!r.ReadSetup.Consent.InsecureHTTPAcknowledged && len(ca) == 0) {
		return setupgate.ErrGuard
	}
	var c lanclient.Config
	if lanconfig.StrictObject(raw["agent.json"], &c, "schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile") != nil || c.Validate() != nil || c.SchemaVersion != lanclient.WindowsInventoryConfigVersion || c.CollectionProfile != r.ReadSetup.Consent.CollectionProfile || c.InsecureHTTPAcknowledged != r.ReadSetup.Consent.InsecureHTTPAcknowledged {
		return setupgate.ErrGuard
	}
	l := r.Service.Layout
	if c.CertificateFile != filepath.Join(l.EnrollmentRoot, "agent-cert.pem") || c.PrivateKeyFile != filepath.Join(l.EnrollmentRoot, "agent-key.pem") || c.StateDirectory != l.SenderRoot || (c.Profile == "tls" && c.ServerCAFile != filepath.Join(l.EnrollmentRoot, "server-ca.pem")) {
		return setupgate.ErrGuard
	}
	pair, err := tls.X509KeyPair(raw["agent-cert.pem"], raw["agent-key.pem"])
	if err != nil || len(pair.Certificate) == 0 {
		return setupgate.ErrGuard
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return setupgate.ErrGuard
	}
	binding := setupRetentionDigest([]byte("tracebolt.sender-binding.windows.v1\n" + c.CollectionProfile + "\n" + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated *bool  `json:"serverAuthenticated"`
	}
	if lanconfig.StrictObject(raw["ready.json"], &ready, "version", "configHash", "certificateHash", "serverAuthenticated") != nil || ready.Version != "tracebolt.enrollment-ready.v2" || ready.ServerAuthenticated == nil || *ready.ServerAuthenticated != (c.Profile == "tls") || ready.ConfigHash != setupRetentionDigest(raw["agent.json"]) || ready.CertificateHash != setupRetentionDigest(pair.Certificate[0]) || binding != r.ReadSetup.SenderBinding {
		return setupgate.ErrGuard
	}
	return nil
}

func setupRetentionReadCore(ctx context.Context, r installReceipt, open setupRetentionOpen, stage func(string), prefix string) (map[string][32]byte, error) {
	out := map[string][32]byte{}
	for _, spec := range setupRetentionCore(r) {
		stage(prefix + spec.label)
		raw, err := setupRetentionRead(ctx, spec, open)
		if err != nil {
			return nil, setupgate.ErrGuard
		}
		valid := true
		switch spec.label {
		case "receipt":
			expected, e := json.Marshal(r)
			valid = e == nil && bytes.Equal(expected, raw["receipt.json"])
			clear(expected)
		case "enrollment":
			stage(prefix + "identity")
			valid = setupRetentionIdentity(r, raw) == nil
		}
		setupRetentionHashes(spec.label, raw, out)
		setupRetentionClear(raw)
		if !valid {
			return nil, setupgate.ErrGuard
		}
	}
	return out, nil
}

func captureSetupRetainedState(ctx context.Context, r installReceipt, layout windowsservice.Layout, open setupRetentionOpen, inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error), material func(string) error, stage func(string)) (setupRetainedState, error) {
	zero := setupRetainedState{}
	if ctx == nil || ctx.Err() != nil || open == nil || inspect == nil || material == nil || stage == nil || !completeReadSetup(r) || r.Service.Layout != layout || r.Service.ServiceSID == "" {
		return zero, setupgate.ErrGuard
	}
	// Deep copy slices and progress: caller mutation cannot rebind later checks.
	raw, err := json.Marshal(r)
	defer clear(raw)
	var original installReceipt
	if err != nil || json.Unmarshal(raw, &original) != nil {
		return zero, setupgate.ErrGuard
	}
	stage("retention-baseline-owned")
	s, err := inspect(ctx, original.Service)
	if err != nil || !s.Exists || s.ServiceSID != original.Service.ServiceSID || (s.State != windowsservice.Running && s.State != windowsservice.Stopped) || ctx.Err() != nil {
		return zero, setupgate.ErrGuard
	}
	immutable, err := setupRetentionReadCore(ctx, original, open, stage, "retention-baseline-")
	if err != nil {
		return zero, err
	}
	stage("retention-baseline-material")
	if material(filepath.Join(layout.EnrollmentRoot, "agent.json")) != nil || ctx.Err() != nil {
		return zero, setupgate.ErrGuard
	}
	// Bracket active material validation with identical protected immutable bytes.
	again, err := setupRetentionReadCore(ctx, original, open, stage, "retention-baseline-")
	if err != nil {
		return zero, setupgate.ErrGuard
	}
	stage("retention-baseline-immutable-unchanged")
	if !reflect.DeepEqual(immutable, again) {
		return zero, setupgate.ErrGuard
	}
	return setupRetainedState{receipt: original, immutable: immutable}, nil
}

func setupRetentionGrantSpecs(r installReceipt) []setupRetentionSpec {
	var out []setupRetentionSpec
	for _, kind := range []struct{ label, suffix string }{
		{"event-grant", "event-metadata"}, {"volume-grant", "visible-volumes"}, {"process-grant", "process-metrics"}, {"network-grant", "network"},
	} {
		out = append(out, setupRetentionSpec{label: kind.label, path: r.Service.Layout.StateRoot + "-" + kind.suffix,
			options: windowsstate.Options{RuntimeSID: r.Service.ServiceSID, Names: []string{"consent.json"}, LockName: kind.suffix + ".lock", TempName: kind.suffix + ".tmp", MaxBytes: 1024, Create: false}, files: []string{"consent.json"}})
	}
	return out
}
func setupRetentionGrant(raw []byte, scope, binding string) bool {
	switch scope {
	case windowseventhealth.Scope:
		c, e := windowseventhealth.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsvolumes.Scope:
		c, e := windowsvolumes.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsprocessmetrics.Scope:
		c, e := windowsprocessmetrics.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsnetwork.Scope:
		c, e := windowsnetwork.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	}
	return false
}

// Test-only canonical form of lanclientstate's private codec. This deliberately
// accepts only bytes its writer emits, then enforces the same version, binding,
// bounded sequence, exact pending sequence/body/digest and JSON-body invariants.
// Canonical re-encoding also rejects duplicate/unknown/missing/null scalar keys,
// aliases, trailing input and noncanonical base64. No content is formatted.
func setupRetentionSender(raw []byte, binding string, floor uint64) bool {
	var v struct {
		Version      int    `json:"version"`
		Binding      string `json:"binding"`
		LastSequence uint64 `json:"lastSequence"`
		Pending      *struct {
			Sequence uint64 `json:"sequence"`
			Digest   string `json:"digest"`
			Body     []byte `json:"body"`
		} `json:"pending"`
	}
	if len(raw) == 0 || len(raw) > lanclientstate.MaxStateBytes || !validReadSetupBinding(binding) || floor == 0 || floor > lanclientstate.MaxSequence || json.Unmarshal(raw, &v) != nil {
		return false
	}
	if v.Pending != nil {
		defer clear(v.Pending.Body)
	}
	canonical, err := json.Marshal(v)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) || v.Version != 1 || v.Binding != binding || v.LastSequence < floor || v.LastSequence > lanclientstate.MaxSequence {
		return false
	}
	if p := v.Pending; p != nil {
		if p.Sequence == 0 || p.Sequence != v.LastSequence || !validReadSetupBinding(p.Digest) || len(p.Body) == 0 || len(p.Body) > lanclientstate.MaxBodyBytes || !json.Valid(p.Body) || setupRetentionDigest(p.Body) != p.Digest {
			return false
		}
	}
	return true
}

// Call only after the controller has observed this exact held SCM handle
// stopped and deletion pending. The actual manager-accepted LastSequence is a
// floor, not the number of frames (discarded requests can consume sequences).
func (o *setupRetainedState) captureStopped(ctx context.Context, floor uint64, open setupRetentionOpen, stage func(string)) error {
	if o == nil || o.stopped != nil {
		return setupgate.ErrGuard
	}
	hashes, err := o.verify(ctx, floor, open, stage, "retention-stopped-")
	if err != nil {
		return err
	}
	o.stopped = hashes
	return nil
}
func (o setupRetainedState) verifyAbsent(ctx context.Context, floor uint64, open setupRetentionOpen, stage func(string)) error {
	if o.stopped == nil {
		return setupgate.ErrGuard
	}
	hashes, err := o.verify(ctx, floor, open, stage, "verify-retention-")
	if err != nil {
		return setupgate.ErrGuard
	}
	stage("verify-retention-stopped-unchanged")
	if !reflect.DeepEqual(o.stopped, hashes) {
		return setupgate.ErrGuard
	}
	return nil
}
func (o setupRetainedState) verify(ctx context.Context, floor uint64, open setupRetentionOpen, stage func(string), prefix string) (map[string][32]byte, error) {
	if ctx == nil || ctx.Err() != nil || stage == nil || open == nil || !completeReadSetup(o.receipt) || len(o.immutable) == 0 {
		return nil, setupgate.ErrGuard
	}
	core, err := setupRetentionReadCore(ctx, o.receipt, open, stage, prefix)
	if err != nil {
		return nil, setupgate.ErrGuard
	}
	stage(prefix + "immutable-unchanged")
	if !reflect.DeepEqual(core, o.immutable) {
		return nil, setupgate.ErrGuard
	}
	r := o.receipt
	for i, spec := range setupRetentionGrantSpecs(r) {
		stage(prefix + spec.label)
		raw, err := setupRetentionRead(ctx, spec, open)
		if err != nil {
			return nil, setupgate.ErrGuard
		}
		digest := r.ReadSetup.GrantDigests[i]
		valid := setupRetentionGrant(raw["consent.json"], digest.Scope, r.ReadSetup.SenderBinding) && setupRetentionDigest(raw["consent.json"]) == digest.SHA256
		setupRetentionHashes(spec.label, raw, core)
		setupRetentionClear(raw)
		if !valid {
			return nil, setupgate.ErrGuard
		}
	}
	stage(prefix + "sender")
	spec := setupRetentionSpec{label: "sender", path: r.Service.Layout.SenderRoot, options: windowsagentconfig.Sender(r.Service.ServiceSID, false), files: []string{"state.json"}}
	raw, err := setupRetentionRead(ctx, spec, open)
	if err != nil {
		return nil, setupgate.ErrGuard
	}
	valid := setupRetentionSender(raw["state.json"], r.ReadSetup.SenderBinding, floor)
	setupRetentionHashes("sender", raw, core)
	setupRetentionClear(raw)
	if !valid || ctx.Err() != nil {
		return nil, setupgate.ErrGuard
	}
	return core, nil
}
