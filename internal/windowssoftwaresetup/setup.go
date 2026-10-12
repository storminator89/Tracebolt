// Package windowssoftwaresetup coordinates explicit fresh post-enrollment setup.
// It never starts an executor, changes SCM or grants observation privileges.
package windowssoftwaresetup

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
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssoftwareipc"
	job "localrmm/internal/windowssoftwarejob"
)

const Version = "tracebolt.windows-prepared-msi-provision.v1"
const KeyVersion = "tracebolt.windows-software-executor-key.v1"
const ProcessQueryDisclosure = "A separately launched elevated executor may explicitly grant only PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE to this exact observation service SID for that process lifetime. This setup records acknowledgement only; launch still requires --run-foreground --allow-observer-process-query. No token, thread, SCM, account or observation privilege is granted."

var ErrSetup = errors.New("prepared MSI setup unavailable or incomplete; preserve existing state")
var ErrExisting = errors.New("prepared MSI setup or relay already exists; no adoption or reset")
var ErrChanged = errors.New("prepared MSI setup review or current identity changed")

type Plan struct {
	Version                string                                 `json:"version"`
	Offer                  job.SetupOffer                         `json:"offer"`
	Artifact               windowspackage.Manifest                `json:"artifact"`
	Identity               lanclient.WindowsSoftwareSetupIdentity `json:"identity"`
	Observer               windowsservice.Receipt                 `json:"observer"`
	Executable             string                                 `json:"executable"`
	StateRoot              string                                 `json:"stateRoot"`
	RelayRoot              string                                 `json:"relayRoot"`
	InstallDisclosure      string                                 `json:"installDisclosure"`
	RelayDisclosure        string                                 `json:"relayDisclosure"`
	ProcessQueryDisclosure string                                 `json:"processQueryDisclosure"`
	Package                job.Selection                          `json:"package"`
	NativeAcceptanceDigest string                                 `json:"nativeAcceptanceDigest"`
}

func NewPlan(o job.SetupOffer, a windowspackage.Manifest, identity lanclient.WindowsSoftwareSetupIdentity, r windowsservice.Receipt, selection job.Selection, acceptance string) (Plan, error) {
	p := Plan{Package: selection, NativeAcceptanceDigest: acceptance, Version: Version, Offer: o, Artifact: a, Identity: identity, Observer: r, Executable: r.Layout.ProgramFiles + `\Tracebolt\tracebolt-windows-software-executor.exe`, StateRoot: strings.TrimSuffix(r.Layout.StateRoot, `\windows-agent`) + `\windows-software-executor`, RelayRoot: r.Layout.StateRoot + "-software-job-relay", InstallDisclosure: job.Disclosure, RelayDisclosure: lanclient.WindowsSoftwareRelayDisclosure, ProcessQueryDisclosure: ProcessQueryDisclosure}
	return p, p.Validate()
}

func (p Plan) Validate() error {

	i, o, r := p.Identity, p.Offer, p.Observer
	raw, _ := json.Marshal(p.Artifact)
	if _, e := windowspackage.ParseManifest(raw); e != nil {
		return ErrSetup
	}
	if !job.ValidSelection(p.Package) || !actionpermit.ValidDigest(p.NativeAcceptanceDigest) || p.Artifact.Architecture != "amd64" || p.Version != Version || o.Validate() != nil || p.Artifact.Architecture != runtime.GOARCH || !r.Complete || r.Version != 1 || r.InstallationID == "" || r.ServiceSID == "" || i.ManagerID != o.ManagerID || i.DeviceID != o.DeviceID || i.IncarnationDigest != o.IncarnationDigest || i.ManagerOrigin != o.ManagerOrigin || !actionpermit.ValidDigest(i.ConfigDigest) || !actionpermit.ValidDigest(i.LeafDigest) || !actionpermit.ValidDigest(i.LeafPublicKeyDigest) || i.LeafPublicKeyDigest == actionpermit.Digest(o.ManagerPublicKey) || i.SenderBinding == "" || i.LeafNotBefore <= 0 || i.LeafNotAfter <= i.LeafNotBefore || p.Executable != r.Layout.ProgramFiles+`\Tracebolt\tracebolt-windows-software-executor.exe` || !strings.HasSuffix(r.Layout.StateRoot, `\windows-agent`) || p.StateRoot != strings.TrimSuffix(r.Layout.StateRoot, `\windows-agent`)+`\windows-software-executor` || p.RelayRoot != r.Layout.StateRoot+"-software-job-relay" || p.InstallDisclosure != job.Disclosure || p.RelayDisclosure != lanclient.WindowsSoftwareRelayDisclosure || p.ProcessQueryDisclosure != ProcessQueryDisclosure {
		return ErrSetup
	}
	return nil
}
func (p Plan) Digest() string { b, _ := json.Marshal(p); return actionpermit.Digest(b) }

type Approval struct {
	Digest                          string
	Install, Relay, ProcessQuery    bool
	PackageReview, NativeAcceptance bool
}
type Store interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Verify() error
	Close() error
}
type Hooks struct {
	// Check proves the exact stopped observer, original bootstrap and current TLS
	// identity equal the reviewed snapshot. Fresh checks all independent absences.
	Check         func(context.Context, Plan) error
	Fresh         func(context.Context, Plan) error
	CreateStore   func(context.Context, Plan) (Store, error)
	CreateImage   func(context.Context, []byte, windowspackage.Manifest) (windowspackage.SoftwareExecutorImageReceipt, error)
	VerifyImage   func(context.Context, windowspackage.SoftwareExecutorImageReceipt) error
	CreateRelay   func(context.Context, lanclient.WindowsSoftwareRelayGrant) error
	VerifyRelay   func(context.Context, lanclient.WindowsSoftwareRelayGrant) error
	StagePackage  func(context.Context, []byte, job.Selection) (windowspackage.PreparedMSIReceipt, error)
	VerifyPackage func(context.Context, windowspackage.PreparedMSIReceipt) error
}
type Progress struct {
	Version    string                                       `json:"version"`
	PlanDigest string                                       `json:"planDigest"`
	Attempted  string                                       `json:"attempted"`
	Completed  []string                                     `json:"completed"`
	Image      *windowspackage.SoftwareExecutorImageReceipt `json:"image"`
	Package    *windowspackage.PreparedMSIReceipt           `json:"package"`
	Complete   bool                                         `json:"complete"`
}
type keyMaterial struct {
	Version string `json:"version"`
	Key     []byte `json:"key"`
}

var stages = []string{"executor-key", "executor-image", "package-custody", "executor-state", "observer-relay", "final-verification"}

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
func Apply(ctx context.Context, p Plan, payload, packagePayload []byte, a Approval, h Hooks) (job.SetupRegistration, error) {
	return apply(ctx, p, payload, packagePayload, a, h, generateMaterial, time.Now)
}
func apply(ctx context.Context, p Plan, payload, packagePayload []byte, a Approval, h Hooks, generate func() (ed25519.PrivateKey, string, string, error), now func() time.Time) (registration job.SetupRegistration, err error) {
	raw, _ := json.Marshal(p)
	var immutable Plan
	if decode(raw, &immutable) != nil {
		return registration, ErrSetup
	}
	p = immutable
	payload = bytes.Clone(payload)
	packagePayload = bytes.Clone(packagePayload)
	if ctx == nil || p.Validate() != nil || p.Artifact.Validate(payload) != nil || a.Digest != p.Digest() || !a.Install || !a.Relay || !a.ProcessQuery || !a.PackageReview || !a.NativeAcceptance || windowspackage.ValidatePreparedMSIBytes(packagePayload, p.Package) != nil || h.StagePackage == nil || h.VerifyPackage == nil || h.Check == nil || h.Fresh == nil || h.CreateStore == nil || h.CreateImage == nil || h.VerifyImage == nil || h.CreateRelay == nil || h.VerifyRelay == nil || generate == nil || now == nil {
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
	progress := Progress{Version: Version, PlanDigest: p.Digest(), Completed: []string{}}
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
	var config windowssoftwareipc.Config
	var relay lanclient.WindowsSoftwareRelayGrant
	for _, stage := range stages {
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
			consent := job.Consent{Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, PackageReviewAccepted: true, Version: job.ConsentVersion, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: p.Offer.ExpiresAt}

			registration = job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: consent, ExecutorPublicKey: bytes.Clone(pub)}
			if registration.Validate() != nil {
				return registration, ErrSetup
			}
			config = windowssoftwareipc.Config{Version: windowssoftwareipc.ConfigVersion, Consent: consent, ManagerPublicKey: bytes.Clone(p.Offer.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(pub), Executable: p.Executable, ExecutableDigest: "sha256:" + p.Artifact.SHA256, ObserverReceipt: p.Observer, ObserverProcessQueryAcknowledged: true}
			peer, e := config.Peer()
			if e != nil {
				return registration, ErrSetup
			}
			relay = lanclient.WindowsSoftwareRelayGrant{Version: lanclient.WindowsSoftwareRelayGrantVersion, Scope: lanclient.WindowsSoftwareRelayScope, Enabled: true, Acknowledged: true, SenderBinding: p.Identity.SenderBinding, ManagerOrigin: p.Offer.ManagerOrigin, Binding: b, ManagerPublicKey: bytes.Clone(p.Offer.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(pub), ExecutorPeer: peer, ExpiresAt: p.Offer.ExpiresAt}
			secret, _ := json.Marshal(keyMaterial{KeyVersion, key})
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
		case "package-custody":
			receipt, e := h.StagePackage(ctx, packagePayload, p.Package)
			if e != nil || receipt.Validate() != nil || receipt.Package != p.Package {
				return registration, ErrSetup
			}
			progress.Package = &receipt
			raw, _ := json.Marshal(receipt)
			if s.Write("package.json", raw) != nil {
				return registration, ErrSetup
			}
		case "executor-state":
			record, e := job.NewExecutorRecord(config.Consent, config.ManagerPublicKey, config.ExecutorPublicKey, now().UTC().Unix())
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
		case "observer-relay":
			if e = h.CreateRelay(ctx, relay); e != nil {
				return registration, e
			}
		case "final-verification":
			if progress.Package == nil || h.VerifyPackage(ctx, *progress.Package) != nil || progress.Image == nil || h.VerifyImage(ctx, *progress.Image) != nil || h.VerifyRelay(ctx, relay) != nil || s.Verify() != nil {
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
func VerifyInstalled(s Store, c windowssoftwareipc.Config) error {
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
	if e != nil || decode(raw, &progress) != nil || progress.Version != Version || progress.PlanDigest != p.Digest() || !progress.Complete || progress.Package == nil || progress.Package.Validate() != nil || progress.Package.Package != p.Package || progress.Attempted != "" || progress.Image == nil || progress.Image.Validate() != nil || progress.Image.Path != p.Executable || progress.Image.SHA256 != "sha256:"+p.Artifact.SHA256 || !sameJSON(progress.Completed, stages) || c.Executable != p.Executable || c.ExecutableDigest != progress.Image.SHA256 || c.ObserverReceipt != p.Observer || !c.ObserverProcessQueryAcknowledged {
		return ErrSetup
	}
	packageRaw, e := s.Read("package.json")
	expectedPackage, _ := json.Marshal(progress.Package)
	if e != nil || !bytes.Equal(packageRaw, expectedPackage) {
		return ErrSetup
	}
	r := job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: c.Consent, ExecutorPublicKey: c.ExecutorPublicKey}
	if r.Validate() != nil || c.Consent.Package != p.Package || c.Consent.NativeAcceptanceDigest != p.NativeAcceptanceDigest || !c.Consent.PackageReviewAccepted || !bytes.Equal(c.ManagerPublicKey, p.Offer.ManagerPublicKey) {
		return ErrSetup
	}
	return s.Verify()
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func Relay(p Plan, c windowssoftwareipc.Config) (lanclient.WindowsSoftwareRelayGrant, error) {
	peer, e := c.Peer()
	if e != nil {
		return lanclient.WindowsSoftwareRelayGrant{}, e
	}
	return lanclient.WindowsSoftwareRelayGrant{Version: lanclient.WindowsSoftwareRelayGrantVersion, Scope: lanclient.WindowsSoftwareRelayScope, Enabled: true, Acknowledged: true, SenderBinding: p.Identity.SenderBinding, ManagerOrigin: p.Offer.ManagerOrigin, Binding: c.Consent.Binding, ManagerPublicKey: bytes.Clone(c.ManagerPublicKey), ExecutorPublicKey: bytes.Clone(c.ExecutorPublicKey), ExecutorPeer: peer, ExpiresAt: p.Offer.ExpiresAt}, nil
}

// Registration returns only the original public handoff from complete protected
// state. A lost terminal/stdout reply does not require rekeying or reapplying.
func Registration(s Store) (job.SetupRegistration, error) {
	var zero job.SetupRegistration
	raw, e := s.Read("config.json")
	if e != nil {
		return zero, ErrSetup
	}
	c, e := windowssoftwareipc.DecodeConfig(raw)
	if e != nil || VerifyInstalled(s, c) != nil {
		return zero, ErrSetup
	}
	raw, e = s.Read("provision.json")
	var p Plan
	if e != nil || decode(raw, &p) != nil {
		return zero, ErrSetup
	}
	r := job.SetupRegistration{Version: job.SetupRegistrationVersion, Offer: p.Offer, Consent: c.Consent, ExecutorPublicKey: bytes.Clone(c.ExecutorPublicKey)}
	return r, r.Validate()
}
