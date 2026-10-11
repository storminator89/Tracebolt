package windowsaction

import (
	"bytes"
	"context"
	"crypto/sha1" // Windows service SID derivation, never an authority signature.
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf16"

	"localrmm/internal/windowspackage"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsstate"
)

const ProvisionVersion = "tracebolt.windows-action-provision.v1"
const ProvisionConsent = "Create separate selected-service control authority for the exact reviewed target. The broker virtual account can authenticate to network resources as the computer account; no network client is not an OS-enforced network sandbox. Apply the exact displayed file/service/query-only process ACL changes, preserve partial setup, and leave services stopped with the broker disabled. No target control, firewall rule, credential or automatic cleanup is authorized."
const MaxProvisionBytes = 64 << 10
const BrokerImageName = "tracebolt-windows-action-broker.exe"
const PeerProcessQueryRights uint32 = 0x101000

var (
	ErrProvisionTargetConfig     = errors.New("target configuration is unsupported or differs from its reviewed digest")
	ErrProvisionTargetImage      = errors.New("target executable is untrusted or differs from its reviewed digest")
	ErrProvisionTargetDependents = errors.New("target has active dependents or they cannot be inspected")
	ErrProvisionTargetState      = errors.New("target must be stably running or stopped")
	ErrProvisionExisting         = errors.New("broker object or setup authority already exists; it cannot be adopted")
	ErrProvisionReviewChanged    = errors.New("the current plan differs from the exact approved review")
)

// ProvisionDiagnostic returns finite public diagnostics, never raw native errors.
func ProvisionDiagnostic(err error) string {
	for _, known := range []error{ErrProvisionTargetConfig, ErrProvisionTargetImage, ErrProvisionTargetDependents, ErrProvisionTargetState, ErrProvisionExisting, ErrProvisionReviewChanged} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "Provisioning unavailable or incomplete; preserve every existing object and receipt."
}

// ACLDelta preserves every existing ACE, owner and protection flag. The only
// permitted delta adds the one fixed principal and the exact reviewed rights.
type ACLDelta struct {
	Before    string `json:"before"`
	After     string `json:"after"`
	Principal string `json:"principal"`
	Rights    uint32 `json:"rights"`
}

// ProvisionPlan is LOCAL review material; paths and descriptors never leave the
// installer. The digest approves these exact bytes, including artifact and
// observer identity, rather than a mutable filename or a manager-side grant.
type ProvisionPlan struct {
	Version                string                  `json:"version"`
	Consent                string                  `json:"consent"`
	Policy                 Policy                  `json:"policy"`
	Artifact               windowspackage.Manifest `json:"artifact"`
	ObserverReceiptDigest  string                  `json:"observerReceiptDigest"`
	Executable             string                  `json:"executable"`
	Account                string                  `json:"account"`
	Description            string                  `json:"description"`
	BrokerServiceSDDL      string                  `json:"brokerServiceSddl"`
	ImageDirectory         ACLDelta                `json:"imageDirectory"`
	TargetService          ACLDelta                `json:"targetService"`
	ObserverService        ACLDelta                `json:"observerService"`
	PeerProcessQueryRights uint32                  `json:"peerProcessQueryRights"`
	HTTPAcknowledged       bool                    `json:"httpAcknowledged"`
}

// FixedServiceSIDs is valid before SCM creation. Service SIDs derive from the
// uppercase UTF-16 service name. Native apply independently compares SCM's
// LookupAccountName result immediately after creating the disabled service.
func FixedServiceSIDs() (broker, observer string) {
	return derivedServiceSID(BrokerName), derivedServiceSID(AgentName)
}
func derivedServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	raw := make([]byte, len(u)*2)
	for i, n := range u {
		binary.LittleEndian.PutUint16(raw[i*2:], n)
	}
	sum := sha1.Sum(raw)
	return fmt.Sprintf("S-1-5-80-%d-%d-%d-%d-%d", binary.LittleEndian.Uint32(sum[0:4]), binary.LittleEndian.Uint32(sum[4:8]), binary.LittleEndian.Uint32(sum[8:12]), binary.LittleEndian.Uint32(sum[12:16]), binary.LittleEndian.Uint32(sum[16:20]))
}
func provisionDescription(p Policy, m windowspackage.Manifest) string {
	return "Tracebolt Windows action broker; installation=" + p.Binding.InstallationID + "; executable-sha256=" + m.SHA256
}
func brokerServiceSDDL(broker, agent string) string {
	return "O:BAG:BAD:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)(A;;0x20005;;;" + broker + ")(A;;0x20005;;;" + agent + ")"
}
func (p ProvisionPlan) Bytes() ([]byte, error) { return json.Marshal(p) }
func (p ProvisionPlan) Digest() string         { b, _ := p.Bytes(); return Digest(b) }
func validateProvisionPlan(p ProvisionPlan, payload []byte) error {
	if p.Artifact.Validate(payload) != nil {
		return ErrInvalid
	}
	return validateProvisionMetadata(p)
}
func validateProvisionMetadata(p ProvisionPlan) error {
	manifestRaw, _ := json.Marshal(p.Artifact)
	if _, e := windowspackage.ParseManifest(manifestRaw); e != nil {
		return ErrInvalid
	}
	b, a := FixedServiceSIDs()
	if p.Version != ProvisionVersion || p.Consent != ProvisionConsent || ValidatePolicy(p.Policy) != nil || !p.Policy.Enabled || p.Policy.ProvisioningVersion != ProvisionVersion || p.Policy.BrokerSID != b || p.Policy.AgentSID != a || !ValidDigest(p.ObserverReceiptDigest) || p.Artifact.Architecture != runtime.GOARCH || !windowspath.Canonical(p.Executable) || !strings.HasSuffix(p.Executable, `\Tracebolt\`+BrokerImageName) || p.Account != BrokerAccount || p.Description != provisionDescription(p.Policy, p.Artifact) || p.BrokerServiceSDDL != brokerServiceSDDL(b, a) || p.PeerProcessQueryRights != PeerProcessQueryRights {
		return ErrInvalid
	}
	for _, d := range []struct {
		delta ACLDelta
		sid   string
		mask  uint32
	}{{p.ImageDirectory, b, 0x1200a9}, {p.TargetService, b, 0x2003d}, {p.ObserverService, b, 0x20005}} {
		if d.delta.Principal != d.sid || d.delta.Rights != d.mask || d.delta.Before == "" || d.delta.After == "" || len(d.delta.Before) > 8192 || len(d.delta.After) > 8192 || d.delta.Before == d.delta.After {
			return ErrInvalid
		}
	}
	raw, _ := p.Bytes()
	if len(raw) > MaxProvisionBytes {
		return ErrInvalid
	}
	return nil
}

// ProvisionHooks hold the existing stopped-owned-observer receipt lease and
// activated enrollment binding throughout setup. Validate must remain read-only.
// Relay creation is separately create-only; it grants no target SCM rights.
type ProvisionHooks struct {
	Validate    func(context.Context) error
	CreateRelay func(context.Context) error
	VerifyRelay func(context.Context) error
}

type provisionJournal interface {
	Write(string, []byte) error
	Verify() error
	Close() error
}
type provisionSession interface {
	Plan(context.Context, Policy, windowspackage.Manifest, string, bool) (ProvisionPlan, error)
	CreateJournal(context.Context, ProvisionPlan) (provisionJournal, error)
	ApplyStage(context.Context, string, ProvisionPlan, []byte) error
	Verify(context.Context, ProvisionPlan) error
	Close() error
}
type provisionOpen func(context.Context) (provisionSession, error)

var provisionStages = []string{"image-directory-query", "broker-image", "disabled-broker-service", "broker-service-security", "target-service-rights", "observer-service-query", "broker-authority", "observer-relay"}

type provisionProgress struct {
	PlanDigest string   `json:"planDigest"`
	Completed  []string `json:"completed"`
	Attempted  string   `json:"attempted"`
}
type provisionReceipt struct {
	Version    string `json:"version"`
	PlanDigest string `json:"planDigest"`
	Complete   bool   `json:"complete"`
}

func ProvisionOptions(broker string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: broker, Names: []string{"started.json", "progress.json", "receipt.json"}, LockName: "provision.lock", TempName: "provision.tmp", MaxBytes: MaxProvisionBytes, Create: create}
}

// PlanProvision is read-only, including absence checks of every independently
// owned broker object. Existing shared Tracebolt directories are pinned/reviewed.
func PlanProvision(ctx context.Context, policy Policy, artifact windowspackage.Manifest, payload []byte, observerDigest string, http bool) (plan ProvisionPlan, err error) {
	if ctx == nil || ctx.Err() != nil || ValidatePolicy(policy) != nil || !policy.Enabled || policy.ProvisioningVersion != ProvisionVersion || artifact.Architecture != runtime.GOARCH || artifact.Validate(payload) != nil || !ValidDigest(observerDigest) {
		return plan, ErrInvalid
	}
	s, e := nativeProvisionSession(ctx)
	if e != nil {
		return plan, e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	plan, err = s.Plan(ctx, policy, artifact, observerDigest, http)
	if err == nil {
		err = validateProvisionPlan(plan, payload)
	}
	return
}

// ApplyProvision never starts/enables a service, invokes a target control,
// overwrites an existing object, resets used authority or retries an uncertain
// stage. Every failed/partial setup keeps its independent permanent fence.
func ApplyProvision(ctx context.Context, plan ProvisionPlan, payload []byte, approved string, hooks ProvisionHooks) error {
	return applyProvision(ctx, plan, payload, approved, hooks, nativeProvisionSession)
}
func applyProvision(ctx context.Context, plan ProvisionPlan, payload []byte, approved string, hooks ProvisionHooks, open provisionOpen) (err error) {
	// Snapshot caller-owned slices before validation or callbacks.
	raw, _ := plan.Bytes()
	var immutable ProvisionPlan
	if DecodeCanonical(raw, &immutable, MaxProvisionBytes) != nil {
		return ErrInvalid
	}
	plan = immutable
	payload = bytes.Clone(payload)
	if ctx == nil || ctx.Err() != nil || hooks.Validate == nil || hooks.CreateRelay == nil || hooks.VerifyRelay == nil || open == nil || validateProvisionPlan(plan, payload) != nil || approved != plan.Digest() {
		return ErrInvalid
	}
	s, e := open(ctx)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return hooks.Validate(ctx)
	}
	if e = guard(); e != nil {
		return e
	}
	current, e := s.Plan(ctx, plan.Policy, plan.Artifact, plan.ObserverReceiptDigest, plan.HTTPAcknowledged)
	if e != nil {
		return e
	}
	currentBytes, _ := current.Bytes()
	if !bytes.Equal(raw, currentBytes) {
		return ErrProvisionReviewChanged
	}
	if e = guard(); e != nil {
		return e
	}
	journal, e := s.CreateJournal(ctx, plan)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	if e = journal.Write("started.json", raw); e != nil {
		return e
	}
	progress := provisionProgress{PlanDigest: approved, Completed: []string{}}
	for _, stage := range provisionStages {
		if e = guard(); e != nil {
			return e
		}
		if e = journal.Verify(); e != nil {
			return e
		}
		progress.Attempted = stage
		value, _ := json.Marshal(progress)
		if e = journal.Write("progress.json", value); e != nil {
			return e
		}
		if e = guard(); e != nil {
			return e
		}
		if stage == "observer-relay" {
			e = hooks.CreateRelay(ctx)
		} else {
			e = s.ApplyStage(ctx, stage, plan, payload)
		}
		if e != nil {
			return e
		}
		if e = guard(); e != nil {
			return e
		}
		if e = journal.Verify(); e != nil {
			return e
		}
		progress.Completed = append(progress.Completed, stage)
		progress.Attempted = ""
		value, _ = json.Marshal(progress)
		if e = journal.Write("progress.json", value); e != nil {
			return e
		}
	}
	if e = guard(); e != nil {
		return e
	}
	if e = s.Verify(ctx, plan); e != nil {
		return e
	}
	if e = hooks.VerifyRelay(ctx); e != nil {
		return e
	}
	if e = guard(); e != nil {
		return e
	}
	receipt, _ := json.Marshal(provisionReceipt{ProvisionVersion, approved, true})
	if e = journal.Write("receipt.json", receipt); e != nil {
		return e
	}
	return journal.Verify()
}

// Every configured record in an existing setup store is mandatory. Missing
// files never mean legacy or fresh state, including a crash after authority
// creation but before the completed provisioning receipt.
func readProvisionRecords(store Storage, policy Policy) (ProvisionPlan, error) {
	raw, e := store.Read("started.json")
	if e != nil {
		return ProvisionPlan{}, ErrIntegrity
	}
	var p ProvisionPlan
	if DecodeCanonical(raw, &p, MaxProvisionBytes) != nil || validateProvisionMetadata(p) != nil {
		return ProvisionPlan{}, ErrBinding
	}
	want, _ := json.Marshal(policy)
	got, _ := json.Marshal(p.Policy)
	if !bytes.Equal(want, got) {
		return ProvisionPlan{}, ErrBinding
	}
	raw, e = store.Read("receipt.json")
	if e != nil {
		return ProvisionPlan{}, ErrIntegrity
	}
	var receipt provisionReceipt
	if DecodeCanonical(raw, &receipt, 4096) != nil || receipt.Version != ProvisionVersion || !receipt.Complete || receipt.PlanDigest != p.Digest() {
		return ProvisionPlan{}, ErrIntegrity
	}
	raw, e = store.Read("progress.json")
	if e != nil {
		return ProvisionPlan{}, ErrIntegrity
	}
	var progress provisionProgress
	if DecodeCanonical(raw, &progress, MaxProvisionBytes) != nil || progress.PlanDigest != p.Digest() || progress.Attempted != "" || len(progress.Completed) != len(provisionStages) {
		return ProvisionPlan{}, ErrIntegrity
	}
	for i, stage := range provisionStages {
		if progress.Completed[i] != stage {
			return ProvisionPlan{}, ErrIntegrity
		}
	}
	if store.Verify() != nil {
		return ProvisionPlan{}, ErrIntegrity
	}
	return p, nil
}
