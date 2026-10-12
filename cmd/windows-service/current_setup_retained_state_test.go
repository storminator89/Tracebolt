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
	"localrmm/internal/renewalidentity"
	"localrmm/internal/windowsacceptance/currentsetupgate"
	"localrmm/internal/windowsacceptance/setupgate"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsvolumes"
	"time"
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
type currentRetentionStore interface {
	Read(string) ([]byte, error)
	Entries() ([]string, error)
	Verify() error
	Close() error
}
type currentRetentionOpen func(string, windowsstate.Options) (currentRetentionStore, error)
type currentRetainedState struct {
	receipt   installReceipt
	immutable map[string][32]byte
	stopped   map[string][32]byte
	proof     currentsetupgate.ReceiptProof
}

type currentRetentionSpec struct {
	label, path     string
	options         windowsstate.Options
	files, children []string
}

func currentRetentionCore(r installReceipt) []currentRetentionSpec {
	l, sid := r.Service.Layout, r.Service.ServiceSID
	enrollment := []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "agent.json", "ready.json", "service-enrollment.json"}
	if !r.ReadSetup.Consent.InsecureHTTPAcknowledged {
		enrollment = append(enrollment, "server-ca.pem", "renewal-manifest.json", "renewal-transaction.json")
	}
	return []currentRetentionSpec{
		{"receipt", l.StateRoot + "-installer", windowsagentconfig.Installer(false), []string{"intent.json", "receipt.json"}, nil},
		{"runtime", l.StateRoot, windowsagentconfig.RuntimeRoot(sid, false), []string{"bootstrap.json"}, []string{"enrollment"}},
		{"enrollment", l.EnrollmentRoot, windowsagentconfig.EnrollmentRenewable(sid, false), enrollment, []string{"telemetry"}},
	}
}

func currentRetentionRead(ctx context.Context, spec currentRetentionSpec, open currentRetentionOpen) (result map[string][]byte, err error) {
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
			currentRetentionClear(result)
			result = nil
		}
	}()
	entries, e := s.Entries()
	want := append(slices.Clone(spec.files), spec.children...)
	if slices.Contains(spec.options.Names, "pack.json") && slices.Contains(entries, "pack.json") {
		want = append(want, "pack.json")
		spec.files = append(slices.Clone(spec.files), "pack.json")
	}
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
func currentRetentionClear(raw map[string][]byte) {
	for _, b := range raw {
		clear(b)
	}
}
func currentRetentionHashes(label string, raw map[string][]byte, out map[string][32]byte) {
	for name, b := range raw {
		out[label+"/"+name] = sha256.Sum256(b)
	}
}
func currentRetentionDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// This validates the immutable ready/config/certificate linkage against the
// ORIGINAL coordinator binding. Material's full live-SID certificate/trust
// validation is additionally required at capture via lanclient.Load, which
// does not acquire the sender or grant locks. The private key never persists
// in this observation; every byte buffer is cleared before returning.
func currentRetentionIdentity(r installReceipt, raw map[string][]byte) error {
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
	if lanconfig.StrictObject(raw["agent.json"], &c, "schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile", "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile", "renewalManifestFile") != nil || c.Validate() != nil || c.SchemaVersion != lanclient.WindowsRenewalConfigVersion || c.CollectionProfile != r.ReadSetup.Consent.CollectionProfile || c.InsecureHTTPAcknowledged != r.ReadSetup.Consent.InsecureHTTPAcknowledged {
		return setupgate.ErrGuard
	}
	l := r.Service.Layout
	if c.RenewalManifestFile != filepath.Join(l.EnrollmentRoot, renewalidentity.ManifestName) || c.CertificateFile != filepath.Join(l.EnrollmentRoot, "agent-cert.pem") || c.PrivateKeyFile != filepath.Join(l.EnrollmentRoot, "agent-key.pem") || c.StateDirectory != l.SenderRoot || (c.Profile == "tls" && c.ServerCAFile != filepath.Join(l.EnrollmentRoot, "server-ca.pem")) {
		return setupgate.ErrGuard
	}
	pair, err := tls.X509KeyPair(raw["agent-cert.pem"], raw["agent-key.pem"])
	if err != nil || len(pair.Certificate) != 2 {
		return setupgate.ErrGuard
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return setupgate.ErrGuard
	}
	issuer, err := x509.ParseCertificate(pair.Certificate[1])
	if err != nil {
		return setupgate.ErrGuard
	}
	manifest, err := renewalidentity.Parse(raw[renewalidentity.ManifestName])
	if err != nil || manifest.CredentialGeneration != 1 {
		return setupgate.ErrGuard
	}
	if _, err = manifest.Validate(leaf, issuer, c.ManagerOrigin, c.CollectionProfile, c.AgentID, time.Now().UTC()); err != nil {
		return setupgate.ErrGuard
	}
	binding := currentRetentionDigest([]byte("tracebolt.sender-binding.windows.v1\n" + c.CollectionProfile + "\n" + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated *bool  `json:"serverAuthenticated"`
	}
	if lanconfig.StrictObject(raw["ready.json"], &ready, "version", "configHash", "certificateHash", "serverAuthenticated") != nil || ready.Version != "tracebolt.enrollment-ready.v2" || ready.ServerAuthenticated == nil || *ready.ServerAuthenticated != (c.Profile == "tls") || ready.ConfigHash != currentRetentionDigest(raw["agent.json"]) || ready.CertificateHash != currentRetentionDigest(pair.Certificate[0]) || binding != r.ReadSetup.SenderBinding {
		return setupgate.ErrGuard
	}
	return nil
}

func currentRetentionReadCore(ctx context.Context, r installReceipt, open currentRetentionOpen, stage func(string), prefix string) (map[string][32]byte, error) {
	out := map[string][32]byte{}
	for _, spec := range currentRetentionCore(r) {
		stage("current-retention")
		raw, err := currentRetentionRead(ctx, spec, open)
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
			stage("current-identity")
			valid = currentRetentionIdentity(r, raw) == nil
		}
		currentRetentionHashes(spec.label, raw, out)
		currentRetentionClear(raw)
		if !valid {
			return nil, setupgate.ErrGuard
		}
	}
	return out, nil
}

func captureCurrentRetainedState(ctx context.Context, r installReceipt, layout windowsservice.Layout, open currentRetentionOpen, inspect func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error), material func(string) error, stage func(string)) (currentRetainedState, error) {
	zero := currentRetainedState{}
	if ctx == nil || ctx.Err() != nil || open == nil || inspect == nil || material == nil || stage == nil || !completeCurrentReadSetup(r) || r.Service.Layout != layout || r.Service.ServiceSID == "" {
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
	immutable, err := currentRetentionReadCore(ctx, original, open, stage, "retention-baseline-")
	if err != nil {
		return zero, err
	}
	stage("retention-baseline-material")
	if material(filepath.Join(layout.EnrollmentRoot, "agent.json")) != nil || ctx.Err() != nil {
		return zero, setupgate.ErrGuard
	}
	// Bracket active material validation with identical protected immutable bytes.
	again, err := currentRetentionReadCore(ctx, original, open, stage, "retention-baseline-")
	if err != nil {
		return zero, setupgate.ErrGuard
	}
	stage("retention-baseline-immutable-unchanged")
	if !reflect.DeepEqual(immutable, again) {
		return zero, setupgate.ErrGuard
	}
	return currentRetainedState{receipt: original, immutable: immutable}, nil
}

func currentRetentionGrantSpecs(r installReceipt) []currentRetentionSpec {
	sid := r.Service.ServiceSID
	create := false
	return []currentRetentionSpec{
		{"event-metadata", r.Service.Layout.StateRoot + "-event-metadata", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "event-metadata.lock", TempName: "event-metadata.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"visible-volumes", r.Service.Layout.StateRoot + "-visible-volumes", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "visible-volumes.lock", TempName: "visible-volumes.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"process-metrics", r.Service.Layout.StateRoot + "-process-metrics", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "process-metrics.lock", TempName: "process-metrics.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"network", r.Service.Layout.StateRoot + "-network", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "network.lock", TempName: "network.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"service-startup", r.Service.Layout.StateRoot + "-service-startup", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "service-startup.lock", TempName: "service-startup.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"full-services", r.Service.Layout.StateRoot + "-full-services", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "full-services.lock", TempName: "full-services.tmp", MaxBytes: windowsfullservices.MaxPackBytes, Create: create}, []string{"consent.json", "sender.json"}, []string{}},
		{"full-software", r.Service.Layout.StateRoot + "-full-software", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "full-software.lock", TempName: "full-software.tmp", MaxBytes: windowsfullsoftware.MaxPackBytes, Create: create}, []string{"consent.json", "sender.json"}, []string{}},
		{"adapter-context", r.Service.Layout.StateRoot + "-adapter-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "adapter-context.lock", TempName: "adapter-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"patch-context", r.Service.Layout.StateRoot + "-patch-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "patch-context.lock", TempName: "patch-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"security-posture", r.Service.Layout.StateRoot + "-security-posture", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "security-posture.lock", TempName: "security-posture.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"session-context", r.Service.Layout.StateRoot + "-session-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "session-context.lock", TempName: "session-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"hardware-context", r.Service.Layout.StateRoot + "-hardware-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "hardware-context.lock", TempName: "hardware-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"storage-context", r.Service.Layout.StateRoot + "-storage-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "storage-context.lock", TempName: "storage-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"security-coverage", r.Service.Layout.StateRoot + "-security-coverage", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "security-coverage.lock", TempName: "security-coverage.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"full-processes", r.Service.Layout.StateRoot + "-full-processes", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "full-processes.lock", TempName: "full-processes.tmp", MaxBytes: windowsfullprocesses.MaxPackBytes, Create: create}, []string{"consent.json", "sender.json"}, []string{}},
		{"network-context", r.Service.Layout.StateRoot + "-network-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "network-context.lock", TempName: "network-context.tmp", MaxBytes: windowsnetworkcontext.MaxPackBytes, Create: create}, []string{"consent.json", "sender.json"}, []string{}},
		{"resource-context", r.Service.Layout.StateRoot + "-resource-context", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "resource-context.lock", TempName: "resource-context.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"storage-io", r.Service.Layout.StateRoot + "-storage-io", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "storage-io.lock", TempName: "storage-io.tmp", MaxBytes: 1024, Create: create}, []string{"consent.json"}, []string{}},
		{"full-software", r.Service.Layout.StateRoot + "-full-software", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "full-software.lock", TempName: "full-software.tmp", MaxBytes: windowsfullsoftware.MaxPackBytes, Create: create}, []string{"consent.json", "sender.json"}, []string{}},
		{"event-history", r.Service.Layout.StateRoot + "-event-history", windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, Directories: []string{"reports", "consumption"}, LockName: "event-history.lock", TempName: "event-history.tmp", MaxBytes: 2048, Create: create}, []string{"consent.json"}, []string{"reports", "consumption"}},
	}
}
func currentRetentionGrant(raw []byte, scope, binding string) bool {
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
	case windowsmanaged.ServiceStartupScope:
		c, e := windowsmanaged.DecodeServiceStartupConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsfullservices.Scope:
		c, e := windowsfullservices.DecodeConsent(raw)
		return e == nil && c.Enabled && c.SenderBinding == binding
	case windowsfullsoftware.Scope:
		c, e := windowsfullsoftware.DecodeConsent(raw)
		return e == nil && c.Enabled && c.SenderBinding == binding
	case windowsadapters.Scope:
		c, e := windowsadapters.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowspatchcontext.Scope:
		c, e := windowspatchcontext.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowssecurity.Scope:
		c, e := windowssecurity.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowssessions.Scope:
		c, e := windowssessions.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowshardware.Scope:
		c, e := windowshardware.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsstorage.Scope:
		c, e := windowsstorage.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowssecuritycoverage.Scope:
		c, e := windowssecuritycoverage.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsfullprocesses.Scope:
		c, e := windowsfullprocesses.DecodeConsent(raw)
		return e == nil && c.Enabled && c.SenderBinding == binding
	case windowsnetworkcontext.Scope:
		c, e := windowsnetworkcontext.DecodeConsent(raw)
		return e == nil && c.Enabled && c.SenderBinding == binding
	case windowsresourcecontext.Scope:
		c, e := windowsresourcecontext.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsstorageio.Scope:
		c, e := windowsstorageio.DecodeConsent(raw, binding)
		return e == nil && c.Enabled
	case windowsfullsoftware.HistoryScope:
		c, e := windowsfullsoftware.DecodeConsent(raw)
		return e == nil && c.Enabled && c.SenderBinding == binding && c.HistoryScope == windowsfullsoftware.HistoryScope
	case windowshistoryrequest.Scope:
		c, e := windowshistoryrequest.DecodeConsent(raw, binding, "tls")
		return e == nil && c.Enabled
	}
	return false
}

// Test-only canonical form of lanclientstate's private codec. This deliberately
// accepts only bytes its writer emits, then enforces the same version, binding,
// bounded sequence, exact pending sequence/body/digest and JSON-body invariants.
// Canonical re-encoding also rejects duplicate/unknown/missing/null scalar keys,
// aliases, trailing input and noncanonical base64. No content is formatted.
func currentRetentionSender(raw []byte, binding string, floor uint64) bool {
	var v struct {
		WindowsNetworkContextUsed bool   `json:"windowsNetworkContextUsed,omitempty"`
		WindowsFullProcessesUsed  bool   `json:"windowsFullProcessesUsed,omitempty"`
		WindowsFullSoftwareUsed   bool   `json:"windowsFullSoftwareUsed,omitempty"`
		WindowsFullServicesUsed   bool   `json:"windowsFullServicesUsed,omitempty"`
		Version                   int    `json:"version"`
		Binding                   string `json:"binding"`
		LastSequence              uint64 `json:"lastSequence"`
		Pending                   *struct {
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
	if err != nil || !bytes.Equal(raw, canonical) || v.Version != 5 || !v.WindowsNetworkContextUsed || !v.WindowsFullProcessesUsed || !v.WindowsFullSoftwareUsed || !v.WindowsFullServicesUsed || v.Binding != binding || v.LastSequence < floor || v.LastSequence > lanclientstate.MaxSequence {
		return false
	}
	if p := v.Pending; p != nil {
		if p.Sequence == 0 || p.Sequence != v.LastSequence || !validReadSetupBinding(p.Digest) || len(p.Body) == 0 || len(p.Body) > lanclientstate.MaxBodyBytes || !json.Valid(p.Body) || currentRetentionDigest(p.Body) != p.Digest {
			return false
		}
	}
	return true
}

// Call only after the controller has observed this exact held SCM handle
// stopped and deletion pending. The actual manager-accepted LastSequence is a
// floor, not the number of frames (discarded requests can consume sequences).
func (o *currentRetainedState) captureStopped(ctx context.Context, floor uint64, open currentRetentionOpen, stage func(string)) error {
	if o == nil || o.stopped != nil {
		return setupgate.ErrGuard
	}
	hashes, err := o.verify(ctx, floor, open, stage, "retention-stopped-")
	if err != nil {
		return err
	}
	o.stopped = hashes
	raw, _ := json.Marshal(o.receipt)
	consent, _ := json.Marshal(o.receipt.ReadSetup.Consent)
	manifest := hashes["enrollment/renewal-manifest.json"]
	o.proof = currentsetupgate.ReceiptProof{Verified: true, ReceiptSHA256: currentRetentionDigest(raw), ConsentSHA256: currentRetentionDigest(consent), SenderBinding: o.receipt.ReadSetup.SenderBinding, ManifestSHA256: hex.EncodeToString(manifest[:]), CredentialGeneration: 1, GrantDigests: slices.Clone(o.receipt.ReadSetup.GrantDigests)}
	clear(raw)
	clear(consent)
	if o.proof.Validate() != nil {
		return setupgate.ErrGuard
	}
	return nil
}
func (o currentRetainedState) verifyAbsent(ctx context.Context, floor uint64, open currentRetentionOpen, stage func(string)) error {
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
func (o currentRetainedState) verify(ctx context.Context, floor uint64, open currentRetentionOpen, stage func(string), prefix string) (map[string][32]byte, error) {
	if ctx == nil || ctx.Err() != nil || stage == nil || open == nil || !completeCurrentReadSetup(o.receipt) || len(o.immutable) == 0 {
		return nil, setupgate.ErrGuard
	}
	core, err := currentRetentionReadCore(ctx, o.receipt, open, stage, prefix)
	if err != nil {
		return nil, setupgate.ErrGuard
	}
	stage(prefix + "immutable-unchanged")
	if !reflect.DeepEqual(core, o.immutable) {
		return nil, setupgate.ErrGuard
	}
	r := o.receipt
	for i, spec := range currentRetentionGrantSpecs(r) {
		stage("current-retention")
		raw, err := currentRetentionRead(ctx, spec, open)
		if err != nil {
			return nil, setupgate.ErrGuard
		}
		digest := r.ReadSetup.GrantDigests[i]
		valid := currentRetentionGrant(raw["consent.json"], digest.Scope, r.ReadSetup.SenderBinding) && currentRetentionDigest(raw["consent.json"]) == digest.SHA256
		currentRetentionHashes(spec.label, raw, core)
		currentRetentionClear(raw)
		if !valid {
			return nil, setupgate.ErrGuard
		}
	}
	// History's consume-once/report metadata has its own protected child stores.
	// It is retained byte-for-byte, never initialized or interpreted as query proof.
	for _, child := range []struct{ dir, file, lock, temp string }{{"reports", "reports.json", "reports.lock", "reports.tmp"}, {"consumption", "consumed.json", "consumed.lock", "consumed.tmp"}} {
		stage("current-retention")
		label := "event-history/" + child.dir
		spec := currentRetentionSpec{label: label, path: filepath.Join(r.Service.Layout.StateRoot+"-event-history", child.dir), options: windowsstate.Options{RuntimeSID: r.Service.ServiceSID, Names: []string{child.file}, LockName: child.lock, TempName: child.temp, MaxBytes: windowshistorystate.MaxBytes}, files: []string{child.file}}
		raw, err := currentRetentionRead(ctx, spec, open)
		if err != nil {
			return nil, setupgate.ErrGuard
		}
		currentRetentionHashes(label, raw, core)
		currentRetentionClear(raw)
	}

	stage(prefix + "sender")
	spec := currentRetentionSpec{label: "sender", path: r.Service.Layout.SenderRoot, options: windowsagentconfig.Sender(r.Service.ServiceSID, false), files: []string{"state.json"}}
	raw, err := currentRetentionRead(ctx, spec, open)
	if err != nil {
		return nil, setupgate.ErrGuard
	}
	valid := currentRetentionSender(raw["state.json"], r.ReadSetup.SenderBinding, floor)
	currentRetentionHashes("sender", raw, core)
	currentRetentionClear(raw)
	if !valid || ctx.Err() != nil {
		return nil, setupgate.ErrGuard
	}
	return core, nil
}
