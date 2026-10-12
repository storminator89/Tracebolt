// Package windowsupdatesetup coordinates explicit fresh post-enrollment setup.
// It never starts an executor, changes SCM or grants observation privileges.
package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
)

const BackgroundVersion = "tracebolt.windows-background-update-provision.v1"
const BackgroundKeyVersion = "tracebolt.windows-background-update-key.v1"
const BackgroundDisclosure = "Run manual selected cached update jobs through a dedicated own-process LocalSystem background service after explicit activation. LocalSystem has high machine privileges and machine-network access; native update/custom code is not sandboxed. The observer receives only query/status/read-control on this service and query-limited/synchronize on its process, never start/control, token, key or state rights. Each exact cached GUID/revision still needs fresh named approval; 32 jobs share the original fixed grant lifetime. No scheduling, downloads, EULA acceptance, reboot, repair or automatic retry/unlock is authorized."

const CoordinatedVersion = "tracebolt.windows-selected-update-provision.v2"
const Version = "tracebolt.windows-selected-update-provision.v1"
const ScheduleDisclosure = job.ScheduleDisclosure
const KeyVersion = "tracebolt.windows-update-executor-key.v1"
const ProcessQueryDisclosure = "A separately launched elevated executor may explicitly grant only PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE to this exact observation service SID for that process lifetime. This setup records acknowledgement only; launch still requires --run-foreground --allow-observer-process-query. No token, thread, SCM, account or observation privilege is granted."

var ErrSetup = errors.New("selected update setup unavailable or incomplete; preserve existing state")
var ErrExisting = errors.New("selected update setup or relay already exists; no adoption or reset")
var ErrChanged = errors.New("selected update setup review or current identity changed")

type Plan struct {
	MutationPlanDigest     string                               `json:"mutationPlanDigest,omitempty"`
	Version                string                               `json:"version"`
	Offer                  job.SetupOffer                       `json:"offer"`
	Artifact               windowspackage.Manifest              `json:"artifact"`
	Identity               lanclient.WindowsUpdateSetupIdentity `json:"identity"`
	Observer               windowsservice.Receipt               `json:"observer"`
	Executable             string                               `json:"executable"`
	StateRoot              string                               `json:"stateRoot"`
	RelayRoot              string                               `json:"relayRoot"`
	InstallDisclosure      string                               `json:"installDisclosure"`
	RelayDisclosure        string                               `json:"relayDisclosure"`
	ProcessQueryDisclosure string                               `json:"processQueryDisclosure"`
	ScheduleScope          string                               `json:"scheduleScope,omitempty"`
	ScheduleDisclosure     string                               `json:"scheduleDisclosure,omitempty"`
}

func NewPlan(o job.SetupOffer, a windowspackage.Manifest, identity lanclient.WindowsUpdateSetupIdentity, r windowsservice.Receipt) (Plan, error) {
	p := Plan{Version: Version, Offer: o, Artifact: a, Identity: identity, Observer: r, Executable: r.Layout.ProgramFiles + `\Tracebolt\tracebolt-windows-update-executor.exe`, StateRoot: strings.TrimSuffix(r.Layout.StateRoot, `\windows-agent`) + `\windows-update-executor`, RelayRoot: r.Layout.StateRoot + "-update-job-relay", InstallDisclosure: job.Disclosure, RelayDisclosure: lanclient.WindowsUpdateRelayDisclosure, ProcessQueryDisclosure: ProcessQueryDisclosure}
	return p, p.Validate()
}

// NewScheduledPlan is fresh create-only provisioning, never an upgrade of an
// existing manual grant. NewPlan retains its original version and JSON bytes.
func NewScheduledPlan(o job.SetupOffer, a windowspackage.Manifest, identity lanclient.WindowsUpdateSetupIdentity, r windowsservice.Receipt) (Plan, error) {
	p, err := NewPlan(o, a, identity, r)
	if err != nil {
		return p, err
	}
	p.ScheduleScope = job.ScheduleScope
	p.ScheduleDisclosure = ScheduleDisclosure
	return p, p.Validate()
}
func (p Plan) Validate() error {
	if p.ScheduleScope == "" && p.ScheduleDisclosure != "" || p.ScheduleScope != "" && (p.ScheduleScope != job.ScheduleScope || p.ScheduleDisclosure != ScheduleDisclosure) {
		return ErrSetup
	}

	i, o, r := p.Identity, p.Offer, p.Observer
	imageName, rootName, relaySuffix, queryDisclosure := windowspackage.UpdateExecutorImageName, "windows-update-executor", "-update-job-relay", ProcessQueryDisclosure
	if p.Version == BackgroundVersion {
		imageName = windowspackage.UpdateServiceImageName
		rootName = "windows-update-service"
		relaySuffix = "-background-update-job-relay"
		queryDisclosure = BackgroundDisclosure
	}
	raw, _ := json.Marshal(p.Artifact)
	if _, e := windowspackage.ParseManifest(raw); e != nil {
		return ErrSetup
	}
	if !(p.Version == Version && p.MutationPlanDigest == "" || p.Version == CoordinatedVersion && actionpermit.ValidDigest(p.MutationPlanDigest) && p.ScheduleScope == "" || p.Version == BackgroundVersion && (p.MutationPlanDigest == "" || actionpermit.ValidDigest(p.MutationPlanDigest)) && p.ScheduleScope == "" && p.ScheduleDisclosure == "") || o.Validate() != nil || p.Artifact.Architecture != runtime.GOARCH || !r.Complete || r.Version != 1 || r.InstallationID == "" || r.ServiceSID == "" || i.ManagerID != o.ManagerID || i.DeviceID != o.DeviceID || i.IncarnationDigest != o.IncarnationDigest || i.ManagerOrigin != o.ManagerOrigin || !actionpermit.ValidDigest(i.ConfigDigest) || !actionpermit.ValidDigest(i.LeafDigest) || !actionpermit.ValidDigest(i.LeafPublicKeyDigest) || i.LeafPublicKeyDigest == actionpermit.Digest(o.ManagerPublicKey) || i.SenderBinding == "" || i.LeafNotBefore <= 0 || i.LeafNotAfter <= i.LeafNotBefore || p.Executable != r.Layout.ProgramFiles+`\Tracebolt\`+imageName || !strings.HasSuffix(r.Layout.StateRoot, `\windows-agent`) || p.StateRoot != strings.TrimSuffix(r.Layout.StateRoot, `\windows-agent`)+`\`+rootName || p.RelayRoot != r.Layout.StateRoot+relaySuffix || p.InstallDisclosure != job.Disclosure || p.RelayDisclosure != lanclient.WindowsUpdateRelayDisclosure || p.ProcessQueryDisclosure != queryDisclosure {
		return ErrSetup
	}
	return nil
}
func (p Plan) Digest() string { b, _ := json.Marshal(p); return actionpermit.Digest(b) }

type Approval struct {
	Digest                       string
	Install, Relay, ProcessQuery bool
	Schedule                     bool
	Background                   bool
}
type Store interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Verify() error
	Close() error
}
type Hooks struct {
	CreateService func(context.Context, windowsupdateipc.Config) error
	VerifyService func(context.Context, windowsupdateipc.Config) error
	// Check proves the exact stopped observer, original bootstrap and current TLS
	// identity equal the reviewed snapshot. Fresh checks all independent absences.
	Check       func(context.Context, Plan) error
	Fresh       func(context.Context, Plan) error
	CreateStore func(context.Context, Plan) (Store, error)
	CreateImage func(context.Context, []byte, windowspackage.Manifest) (windowspackage.UpdateExecutorImageReceipt, error)
	VerifyImage func(context.Context, windowspackage.UpdateExecutorImageReceipt) error
	CreateRelay func(context.Context, lanclient.WindowsUpdateRelayGrant) error
	VerifyRelay func(context.Context, lanclient.WindowsUpdateRelayGrant) error
}
type Progress struct {
	Version    string                                     `json:"version"`
	PlanDigest string                                     `json:"planDigest"`
	Attempted  string                                     `json:"attempted"`
	Completed  []string                                   `json:"completed"`
	Image      *windowspackage.UpdateExecutorImageReceipt `json:"image"`
	Complete   bool                                       `json:"complete"`
}
type keyMaterial struct {
	Version string `json:"version"`
	Key     []byte `json:"key"`
}

var stages = []string{"executor-key", "executor-image", "executor-state", "observer-relay", "final-verification"}

func generateMaterial() (ed25519.PrivateKey, string, string, error) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, "", "", ErrSetup
	}
	var ids [32]byte
	if _, e = rand.Read(ids[:]); e != nil {
		clear(key)
		return nil, "", "", ErrSetup
	}
	return key, "executor_" + hex.EncodeToString(ids[:16]), "grant_" + hex.EncodeToString(ids[16:]), nil
}
func Apply(ctx context.Context, p Plan, payload []byte, a Approval, h Hooks) (job.SetupRegistration, error) {
	return apply(ctx, p, payload, a, h, generateMaterial, time.Now)
}
func apply(ctx context.Context, p Plan, payload []byte, a Approval, h Hooks, generate func() (ed25519.PrivateKey, string, string, error), now func() time.Time, coordinated ...CoordinatedMaterial) (registration job.SetupRegistration, err error) {
	raw, _ := json.Marshal(p)
	var immutable Plan
	if decode(raw, &immutable) != nil {
		return registration, ErrSetup
	}
	p = immutable
	background := p.Version == BackgroundVersion
	if background && (p.MutationPlanDigest == "" || h.CreateService == nil || h.VerifyService == nil) {
		return registration, ErrSetup
	}
	var material *CoordinatedMaterial
	if len(coordinated) > 1 {
		return registration, ErrSetup
	}
	if len(coordinated) == 1 {
		material = &coordinated[0]
	}
	if p.MutationPlanDigest != "" && (material == nil || material.Roster.Validate() != nil || material.Roster.Plan.PlanDigest != p.MutationPlanDigest) || p.MutationPlanDigest == "" && material != nil {
		return registration, ErrSetup
	}
	payload = bytes.Clone(payload)
	if ctx == nil || p.Validate() != nil || p.Artifact.Validate(payload) != nil || a.Digest != p.Digest() || !a.Install || !a.Relay || !a.ProcessQuery || a.Schedule != (p.ScheduleScope != "") || a.Background != background || h.Check == nil || h.Fresh == nil || h.CreateStore == nil || h.CreateImage == nil || h.VerifyImage == nil || h.CreateRelay == nil || h.VerifyRelay == nil || generate == nil || now == nil {
		return registration, ErrSetup
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := h.Check(ctx, p); e != nil {
			return e
		}
		n := now().UTC().Unix()
		if n <= 0 || n < p.Identity.LeafNotBefore || n >= p.Identity.LeafNotAfter || n >= p.Offer.ExpiresAt {
			return job.ErrExpired
		}
		return ctx.Err()
	}
	if e := guard(); e != nil {
		return registration, e
	}
	if e := h.Fresh(ctx, p); e != nil {
		return registration, e
	}
	if e := guard(); e != nil {
		return registration, e
	}
	s, e := h.CreateStore(ctx, p)
	if e != nil || s == nil {
		return registration, ErrSetup
	}
	defer func() {
		err = errors.Join(err, s.Close())
		if err != nil {
			registration = job.SetupRegistration{}
		}
	}()
	if s.Verify() != nil {
		return registration, ErrSetup
	}
	// A create-only root is itself a permanent fence. Save full reviewed intent
	// before any credential generation, image write or independent relay creation.
	if s.Write("provision.json", raw) != nil {
		return registration, ErrSetup
	}
	progress := Progress{Version: p.Version, PlanDigest: p.Digest(), Completed: []string{}}
	save := func() error {
		b, _ := json.Marshal(progress)
		if s.Write("progress.json", b) != nil || s.Verify() != nil {
			return ErrSetup
		}
		return guard()
	}
	if e = save(); e != nil {
		return registration, e
	}
	var key ed25519.PrivateKey
	defer func() { clear(key) }()
	var config windowsupdateipc.Config
	var relay lanclient.WindowsUpdateRelayGrant
	for _, stage := range setupStages(background) {
		progress.Attempted = stage
		if e = save(); e != nil {
			return registration, e
		}
		switch stage {
		case "executor-key":
			var executor, grant string
			key, executor, grant, e = generate()
			if e != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
				return registration, ErrSetup
			}
			pub := key.Public().(ed25519.PublicKey)
			if actionpermit.Digest(pub) == p.Identity.LeafPublicKeyDigest {
				return registration, ErrSetup
			}
			b := job.Binding{ManagerID: p.Offer.ManagerID, DeviceID: p.Offer.DeviceID, IncarnationDigest: p.Offer.IncarnationDigest, ExecutorID: executor, ExecutorKeyID: actionpermit.Digest(pub), GrantID: grant, KeyID: actionpermit.Digest(p.Offer.ManagerPublicKey)}
			consent := job.Consent{Version: job.ConsentVersion, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: p.Offer.ExpiresAt}
			if material != nil {
				consent.Version = job.CoordinatedConsentVersion
				consent.MutationPlanDigest = p.MutationPlanDigest
				consent.PeerBindingDigest = material.Roster.MSI.BindingDigest
			}
			if background {
				consent.Version = job.BackgroundConsentVersion
				consent.BackgroundAcknowledged = true
			}
			if p.ScheduleScope != "" {
				consent.Version = job.ScheduledConsentVersion
				consent.ScheduleScope = p.ScheduleScope
				consent.ScheduleAcknowledged = true
			}
			registration = job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: consent, ExecutorPublicKey: bytes.Clone(pub)}
			if background {
				registration.Version = job.BackgroundRegistrationVersion
			}
			if registration.Validate() != nil {
				return registration, ErrSetup
			}
			config = windowsupdateipc.Config{Version: windowsupdateipc.ConfigVersion, Consent: consent, ManagerPublicKey: bytes.Clone(p.Offer.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(pub), Executable: p.Executable, ExecutableDigest: "sha256:" + p.Artifact.SHA256, ObserverReceipt: p.Observer, ObserverProcessQueryAcknowledged: true}
			if material != nil {
				config.Version = windowsupdateipc.CoordinatedConfigVersion
				if background {
					config.Version = windowsupdateipc.ServiceConfigVersion
					config.ObserverConfigDigest = p.Identity.ConfigDigest
					config.SenderBinding = p.Identity.SenderBinding
					config.ManagerOrigin = p.Identity.ManagerOrigin
				}
				config.Mutation = &material.Roster
				if !job.ValidMutationRoster(config.Mutation, consent) {
					return registration, ErrSetup
				}
			}
			peer, e := config.Peer()
			if e != nil {
				return registration, ErrSetup
			}
			relay = lanclient.WindowsUpdateRelayGrant{Version: lanclient.WindowsUpdateRelayGrantVersion, Scope: lanclient.WindowsUpdateRelayScope, Enabled: true, Acknowledged: true, SenderBinding: p.Identity.SenderBinding, ManagerOrigin: p.Offer.ManagerOrigin, Binding: b, ManagerPublicKey: bytes.Clone(p.Offer.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(pub), ExecutorPeer: peer, ExpiresAt: p.Offer.ExpiresAt}
			if background {
				relay.Version = lanclient.WindowsBackgroundUpdateRelayGrantVersion
			}
			kv := KeyVersion
			if background {
				kv = BackgroundKeyVersion
			}
			secret, _ := json.Marshal(keyMaterial{kv, key})
			e = s.Write("executor-key.json", secret)
			clear(secret)
			if e != nil {
				return registration, ErrSetup
			}
		case "executor-image":
			image, e := h.CreateImage(ctx, payload, p.Artifact)
			if e != nil || image.Validate() != nil || image.Path != p.Executable || image.SHA256 != config.ExecutableDigest {
				return registration, ErrSetup
			}
			progress.Image = &image
		case "executor-state":
			var record job.ExecutorRecord
			var e error
			if material == nil {
				record, e = job.NewExecutorRecord(config.Consent, config.ManagerPublicKey, config.ExecutorPublicKey, now().UTC().Unix())
			} else {
				record, e = job.NewCoordinatedExecutorRecord(config.Consent, config.ManagerPublicKey, config.ExecutorPublicKey, now().UTC().Unix(), material.Roster)
			}
			if e != nil {
				return registration, ErrSetup
			}
			ledger, e := job.EncodeExecutorRecord(record)
			if e != nil {
				return registration, ErrSetup
			}
			c, _ := json.Marshal(config)
			consent, _ := json.Marshal(config.Consent)
			for _, v := range []struct {
				name string
				raw  []byte
			}{{"started.json", consent}, {"config.json", c}, {"executor.json", ledger}} {
				if s.Write(v.name, v.raw) != nil {
					return registration, ErrSetup
				}
				if e = guard(); e != nil {
					return registration, e
				}
			}
		case "disabled-service":
			if e = h.CreateService(ctx, config); e != nil {
				return registration, e
			}
			service, _ := json.Marshal(ServiceReceipt{Version: BackgroundVersion, ConfigDigest: DigestConfig(config), Marker: ServiceMarker(config), Disabled: true})
			if s.Write("service.json", service) != nil {
				return registration, ErrSetup
			}
		case "observer-relay":
			if e = h.CreateRelay(ctx, relay); e != nil {
				return registration, e
			}
		case "final-verification":
			if background && h.VerifyService(ctx, config) != nil {
				return registration, ErrSetup
			}
			if progress.Image == nil || h.VerifyImage(ctx, *progress.Image) != nil || h.VerifyRelay(ctx, relay) != nil || s.Verify() != nil {
				return registration, ErrSetup
			}
			consent, _ := json.Marshal(config.Consent)
			if s.Write("receipt.json", consent) != nil {
				return registration, ErrSetup
			}
		}
		if e = guard(); e != nil {
			return registration, e
		}
		progress.Completed = append(progress.Completed, stage)
		progress.Attempted = ""
		if e = save(); e != nil {
			return registration, e
		}
	}
	progress.Complete = true
	if e = save(); e != nil {
		return registration, e
	}
	if VerifyInstalled(s, config) != nil || guard() != nil {
		return registration, ErrSetup
	}
	return registration, nil
}
func decode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > job.MaxBytes {
		return ErrSetup
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrSetup
	}
	b, e := json.Marshal(v)
	defer clear(b)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrSetup
	}
	return nil
}

// VerifyInstalled is also a runtime gate. Missing final completion or any removal
// intent prevents launch even when individual key/config/ledger writes succeeded.
func VerifyInstalled(s Store, c windowsupdateipc.Config) error {
	if s == nil || s.Verify() != nil || c.Validate() != nil {
		return ErrSetup
	}
	if _, e := s.Read("removed.json"); !errors.Is(e, fs.ErrNotExist) {
		return ErrSetup
	}
	raw, e := s.Read("provision.json")
	var p Plan
	if e != nil || decode(raw, &p) != nil || p.Validate() != nil {
		return ErrSetup
	}
	raw, e = s.Read("progress.json")
	var progress Progress
	if e != nil || decode(raw, &progress) != nil || progress.Version != p.Version || progress.PlanDigest != p.Digest() || !progress.Complete || progress.Attempted != "" || progress.Image == nil || progress.Image.Validate() != nil || progress.Image.Path != p.Executable || progress.Image.SHA256 != "sha256:"+p.Artifact.SHA256 || !sameJSON(progress.Completed, setupStages(p.Version == BackgroundVersion)) || c.Executable != p.Executable || c.ExecutableDigest != progress.Image.SHA256 || c.ObserverReceipt != p.Observer || !c.ObserverProcessQueryAcknowledged {
		return ErrSetup
	}
	r := job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: c.Consent, ExecutorPublicKey: c.ExecutorPublicKey}
	if p.Version == BackgroundVersion {
		r.Version = job.BackgroundRegistrationVersion
		if VerifyServiceReceipt(s, c) != nil {
			return ErrSetup
		}
	}
	if r.Validate() != nil || c.Consent.MutationPlanDigest != p.MutationPlanDigest || c.Consent.ScheduleScope != p.ScheduleScope || c.Consent.ScheduleAcknowledged != (p.ScheduleScope != "") || !bytes.Equal(c.ManagerPublicKey, p.Offer.ManagerPublicKey) {
		return ErrSetup
	}
	return s.Verify()
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func Relay(p Plan, c windowsupdateipc.Config) (lanclient.WindowsUpdateRelayGrant, error) {
	peer, e := c.Peer()
	if e != nil {
		return lanclient.WindowsUpdateRelayGrant{}, e
	}
	v := lanclient.WindowsUpdateRelayGrantVersion
	if p.Version == BackgroundVersion {
		v = lanclient.WindowsBackgroundUpdateRelayGrantVersion
	}
	return lanclient.WindowsUpdateRelayGrant{Version: v, Scope: lanclient.WindowsUpdateRelayScope, Enabled: true, Acknowledged: true, SenderBinding: p.Identity.SenderBinding, ManagerOrigin: p.Offer.ManagerOrigin, Binding: c.Consent.Binding, ManagerPublicKey: bytes.Clone(c.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(c.ExecutorPublicKey), ExecutorPeer: peer, ExpiresAt: p.Offer.ExpiresAt}, nil
}

// Registration returns only the original public handoff from complete protected
// state. A lost terminal/stdout reply does not require rekeying or reapplying.
func Registration(s Store) (job.SetupRegistration, error) {
	var zero job.SetupRegistration
	raw, e := s.Read("config.json")
	if e != nil {
		return zero, ErrSetup
	}
	c, e := windowsupdateipc.DecodeConfig(raw)
	if e != nil || VerifyInstalled(s, c) != nil {
		return zero, ErrSetup
	}
	raw, e = s.Read("provision.json")
	var p Plan
	if e != nil || decode(raw, &p) != nil {
		return zero, ErrSetup
	}
	r := job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: c.Consent, ExecutorPublicKey: bytes.Clone(c.ExecutorPublicKey)}
	if c.Version == windowsupdateipc.ServiceConfigVersion {
		r.Version = job.BackgroundRegistrationVersion
	}
	return r, r.Validate()
}

// CoordinatedMaterial is generated only after the shared permanent setup intent.
// It is consumed by the fresh coordinator, never a migration/adoption route.
type CoordinatedMaterial struct {
	Roster              fence.Roster
	Key                 ed25519.PrivateKey
	ExecutorID, GrantID string
}

func NewCoordinatedPlan(p Plan, digest string) (Plan, error) {
	if p.Validate() != nil || (p.Version != Version && p.Version != BackgroundVersion) || p.ScheduleScope != "" || !actionpermit.ValidDigest(digest) {
		return Plan{}, ErrSetup
	}
	if p.Version != BackgroundVersion {
		p.Version = CoordinatedVersion
	}
	p.MutationPlanDigest = digest
	return p, p.Validate()
}
func ApplyCoordinated(ctx context.Context, p Plan, payload []byte, a Approval, h Hooks, m CoordinatedMaterial) (job.SetupRegistration, error) {
	if (p.Version != CoordinatedVersion && p.Version != BackgroundVersion) || len(m.Key) != ed25519.PrivateKeySize {
		return job.SetupRegistration{}, ErrSetup
	}
	return apply(ctx, p, payload, a, h, func() (ed25519.PrivateKey, string, string, error) {
		return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
	}, time.Now, m)
}

func NewBackgroundPlan(o job.SetupOffer, a windowspackage.Manifest, i lanclient.WindowsUpdateSetupIdentity, r windowsservice.Receipt) (Plan, error) {
	p, e := NewPlan(o, a, i, r)
	if e != nil {
		return p, e
	}
	p.Version = BackgroundVersion
	p.Executable = r.Layout.ProgramFiles + `\Tracebolt\` + windowspackage.UpdateServiceImageName
	p.StateRoot = strings.TrimSuffix(r.Layout.StateRoot, `\windows-agent`) + `\windows-update-service`
	p.RelayRoot = r.Layout.StateRoot + "-background-update-job-relay"
	p.ProcessQueryDisclosure = BackgroundDisclosure
	return p, p.Validate()
}
func setupStages(background bool) []string {
	if !background {
		return stages
	}
	return []string{"executor-key", "executor-image", "executor-state", "disabled-service", "observer-relay", "final-verification"}
}

type ServiceReceipt struct {
	Version      string `json:"version"`
	ConfigDigest string `json:"configDigest"`
	Marker       string `json:"marker"`
	Disabled     bool   `json:"disabled"`
}

func DigestConfig(c windowsupdateipc.Config) string {
	raw, _ := json.Marshal(c)
	return actionpermit.Digest(raw)
}
func ServiceMarker(c windowsupdateipc.Config) string {
	return "Tracebolt cached Windows Update; config=" + DigestConfig(c)
}
func VerifyServiceReceipt(s Store, c windowsupdateipc.Config) error {
	var x ServiceReceipt
	raw, e := s.Read("service.json")
	if e != nil || decode(raw, &x) != nil || c.Version != windowsupdateipc.ServiceConfigVersion || x.Version != BackgroundVersion || x.ConfigDigest != DigestConfig(c) || x.Marker != ServiceMarker(c) || !x.Disabled {
		return ErrSetup
	}
	return nil
}
