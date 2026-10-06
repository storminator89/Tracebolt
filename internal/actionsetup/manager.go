// Package actionsetup contains explicit local provisioning seams. Importing it
// and planning never generates keys, creates state, or starts a process.
package actionsetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
)

var ErrSetup = errors.New("action_setup_blocked_preserve_existing_state")

const Version = "tracebolt.action-manager-setup.v1"

type Operator struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}
type ManagerPlan struct {
	Version              string     `json:"schemaVersion"`
	ManagerID            string     `json:"managerId"`
	ManagerOrigin        string     `json:"managerOrigin"`
	EndpointID           string     `json:"endpointId"`
	IncarnationDigest    string     `json:"incarnationDigest"`
	TransportProfile     string     `json:"transportProfile"`
	HTTPTestAcknowledged bool       `json:"httpTestAcknowledged"`
	UID                  int        `json:"uid"`
	GID                  int        `json:"gid"`
	LANConfig            string     `json:"lanConfig"`
	EnrollmentConfig     string     `json:"enrollmentConfig"`
	StateDirectory       string     `json:"stateDirectory"`
	InputDigest          string     `json:"inputDigest"`
	Operators            []Operator `json:"operators"`
	Digest               string     `json:"digest"`
}

type Bundle struct {
	SchemaVersion        string `json:"schemaVersion"`
	ManagerID            string `json:"managerId"`
	ManagerOrigin        string `json:"managerOrigin"`
	EndpointID           string `json:"endpointId"`
	IncarnationDigest    string `json:"incarnationDigest"`
	TransportProfile     string `json:"transportProfile"`
	HTTPTestAcknowledged bool   `json:"httpTestAcknowledged"`
	CommandPublicKey     string `json:"commandPublicKey"`
	KeyID                string `json:"keyId"`
	BundleDigest         string `json:"bundleDigest"`
}

func NewBundle(p ManagerPlan, key ed25519.PublicKey) Bundle {
	b := Bundle{"tracebolt.action-setup-bundle.v1", p.ManagerID, p.ManagerOrigin, p.EndpointID, p.IncarnationDigest, p.TransportProfile, p.HTTPTestAcknowledged, base64.StdEncoding.EncodeToString(key), actionpermit.Digest(key), ""}
	raw, _ := json.Marshal(b)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	delete(m, "bundleDigest")
	raw, _ = json.Marshal(m)
	b.BundleDigest = actionpermit.Digest(raw)
	return b
}
func (p ManagerPlan) calculatedDigest() string {
	p.Digest = ""
	b, _ := json.Marshal(p)
	return actionpermit.Digest(b)
}
func setupPath(state, name string) string { return filepath.Join(state, "service-action-setup", name) }
func IntentPath(state string) string      { return filepath.Join(state, "service-action-setup-intent.json") }
func CompletePath(state string) string {
	return filepath.Join(state, "service-action-setup-complete.json")
}
func LANPath(state string) string { return setupPath(state, "lan.json") }

type material struct {
	lan        lanconfig.Material
	enrollment enrollmentconfig.Material
	plan       ManagerPlan
	forbidden  []ed25519.PublicKey
}

func load(ctx context.Context, lanPath, enrollmentPath, device string, now time.Time, fresh bool) (material, error) {
	fail := func() (material, error) { return material{}, ErrSetup }
	m, e := lanconfig.Load(lanPath)
	if e != nil || m.Config.ServiceActionsConfigFile != "" || len(m.Operators) == 0 {
		return fail()
	}
	en, e := enrollmentconfig.Load(enrollmentPath, m, now)
	if e != nil || en.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		return fail()
	}
	inspection, e := enrollmentstore.InspectServiceActionSetup(ctx, filepath.Join(m.Config.StateDirectory, enrollmentconfig.DatabaseFile), en.Issuer().IssuerDER(), device, now)
	if e != nil || (fresh && inspection.Status != "absent") || (!fresh && inspection.Status != "fenced") || inspection.Config != en.StoreConfig() {
		return fail()
	}
	p := ManagerPlan{Version: Version, ManagerID: en.StoreConfig().Binding.InstanceID, ManagerOrigin: m.Config.AgentOrigin, EndpointID: device, IncarnationDigest: "sha256:" + inspection.Identity.Issuance.CertificateHash, TransportProfile: actionmanager.Profile(m.Config.Profile), HTTPTestAcknowledged: m.Config.InsecureHTTPAcknowledged, UID: os.Geteuid(), GID: os.Getegid(), LANConfig: lanPath, EnrollmentConfig: enrollmentPath, StateDirectory: m.Config.StateDirectory, Operators: []Operator{}}
	for _, op := range m.Operators {
		for _, cap := range op.Capabilities {
			if cap == operatorauth.RestartService {
				p.Operators = append(p.Operators, Operator{op.ID, op.Username})
			}
		}
	}
	if len(p.Operators) == 0 {
		return fail()
	}
	sort.Slice(p.Operators, func(i, j int) bool { return p.Operators[i].ID < p.Operators[j].ID })
	// Bind all loaded private inputs without exporting their bytes or individual
	// password/key hashes. Keys remain in this process, never in the plan.
	paths := []string{lanPath, enrollmentPath, m.Config.OperatorAuthFile, m.Config.AgentClientCAFile}
	if m.Config.Profile == lanconfig.TLS {
		paths = append(paths, m.Config.TLSCertificateFile, m.Config.TLSPrivateKeyFile)
	}
	var ec enrollmentconfig.Config
	raw, e := lanconfig.ReadProtected(enrollmentPath, false, 16384)
	if e != nil || json.Unmarshal(raw, &ec) != nil {
		return fail()
	}
	paths = append(paths, ec.IssuerCertificateFile, ec.IssuerPrivateKeyFile, ec.IssuerRootFile)
	if ec.BootstrapServerCAFile != "" {
		paths = append(paths, ec.BootstrapServerCAFile)
	}
	var inputs [][]byte
	for _, path := range paths {
		raw, e := lanconfig.ReadProtected(path, false, 65536)
		if e != nil {
			return fail()
		}
		inputs = append(inputs, raw)
	}
	raw, _ = json.Marshal(inputs)
	p.InputDigest = actionpermit.Digest(raw)
	clear(raw)
	for _, b := range inputs {
		clear(b)
	}
	if fresh {
		for _, path := range []string{IntentPath(p.StateDirectory), CompletePath(p.StateDirectory), setupPath(p.StateDirectory, "")} {
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				return fail()
			}
		}
	}
	var forbidden []ed25519.PublicKey
	for _, der := range append([][]byte{en.Issuer().IssuerDER(), en.Issuer().RootDER()}, m.Server.Certificate...) {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return fail()
		}
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			forbidden = append(forbidden, key)
		}
	}
	p.Digest = p.calculatedDigest()
	return material{m, en, p, forbidden}, nil
}

// PlanManager reads existing local files and an existing-only read-only database.
// The caller must establish the actual runtime identity; DockerProbeIdentity does
// that against PID 1 inside the already running supported manager container.
func PlanManager(ctx context.Context, lan, enrollment, device string, now time.Time) (ManagerPlan, error) {
	m, e := load(ctx, lan, enrollment, device, now, true)
	return m.plan, e
}
func DockerProbeIdentity() error {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return ErrSetup
	}
	exe, e := os.Readlink("/proc/1/exe")
	if e != nil || exe != "/tracebolt/manager" {
		return ErrSetup
	}
	b, e := os.ReadFile("/proc/1/status")
	if e != nil {
		return ErrSetup
	}
	uid, gid := false, false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			continue
		}
		if fields[0] == "Uid:" || fields[0] == "Gid:" {
			want := os.Geteuid()
			if fields[0] == "Gid:" {
				want = os.Getegid()
			}
			for _, v := range fields[1:] {
				n, e := strconv.Atoi(v)
				if e != nil || n != want {
					return ErrSetup
				}
			}
			if fields[0] == "Uid:" {
				uid = true
			} else {
				gid = true
			}
		}
	}
	if !uid || !gid {
		return ErrSetup
	}
	return nil
}

// Effects is deliberately small. Production constructs it only from ApplyManager;
// tests inject temporary-file and deterministic-key effects, never host adapters.
type Effects interface {
	Create(string, []byte) error
	Mkdir(string) error
	Generate() (ed25519.PublicKey, ed25519.PrivateKey, error)
	Initialize(context.Context, material, ed25519.PublicKey, time.Time) error
}
type localEffects struct{}

func (localEffects) Create(path string, b []byte) error { return createProtected(path, b) }
func (localEffects) Mkdir(path string) error            { return createDirectory(path) }
func (localEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
func (localEffects) Initialize(ctx context.Context, m material, key ed25519.PublicKey, now time.Time) error {
	s, e := enrollmentstore.Open(filepath.Join(m.plan.StateDirectory, enrollmentconfig.DatabaseFile), m.enrollment.StoreConfig(), m.enrollment.Issuer().IssuerDER())
	if e != nil {
		return ErrSetup
	}
	defer s.Close()
	return s.SetupServiceActionsCreateOnly(ctx, key, m.plan.EndpointID, m.plan.IncarnationDigest, now)
}
func ApplyManager(ctx context.Context, p ManagerPlan, confirmation string, now time.Time) (Bundle, error) {
	// No effect, including generation, until exact current plan and explicit
	// confirmation match. Outer guide additionally binds host/launcher/process plan.
	if confirmation != p.Digest || p.Digest != p.calculatedDigest() {
		return Bundle{}, ErrSetup
	}
	m, e := load(ctx, p.LANConfig, p.EnrollmentConfig, p.EndpointID, now, true)
	if e != nil {
		return Bundle{}, ErrSetup
	}
	a, _ := json.Marshal(m.plan)
	b, _ := json.Marshal(p)
	if !bytes.Equal(a, b) {
		return Bundle{}, ErrSetup
	}
	return apply(ctx, m, p, localEffects{}, now)
}

// Apply orchestration is fixture-tested separately from production file/DB code.
func apply(ctx context.Context, m material, p ManagerPlan, fx Effects, now time.Time) (Bundle, error) {
	fail := func() (Bundle, error) { return Bundle{}, ErrSetup }
	intent, _ := json.Marshal(struct {
		Version string      `json:"version"`
		Plan    ManagerPlan `json:"plan"`
	}{Version, p})
	if fx.Create(IntentPath(p.StateDirectory), intent) != nil {
		return fail()
	}
	if fx.Mkdir(setupPath(p.StateDirectory, "")) != nil {
		return fail()
	}
	pub, key, e := fx.Generate()
	if e != nil {
		return fail()
	}
	defer clear(key)
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		return fail()
	}
	for _, old := range m.forbidden {
		if bytes.Equal(pub, old) {
			return fail()
		}
	}
	if fx.Create(setupPath(p.StateDirectory, "command.key"), key) != nil {
		return fail()
	}
	config := actionmanager.Config{Version: actionmanager.ConfigVersion, Enabled: true, ManagerID: p.ManagerID, TransportProfile: p.TransportProfile, HTTPTestAcknowledged: p.HTTPTestAcknowledged, PrivateKeyFile: setupPath(p.StateDirectory, "command.key")}
	raw, _ := json.Marshal(config)
	if fx.Create(setupPath(p.StateDirectory, "commands.json"), raw) != nil {
		return fail()
	}
	lan := m.lan.Config
	lan.ServiceActionsConfigFile = setupPath(p.StateDirectory, "commands.json")
	raw, _ = json.Marshal(lan)
	if fx.Create(LANPath(p.StateDirectory), raw) != nil {
		return fail()
	}
	bundle := NewBundle(p, pub)
	raw, _ = json.Marshal(bundle)
	if fx.Create(setupPath(p.StateDirectory, "bundle.json"), raw) != nil {
		return fail()
	}
	if fx.Initialize(ctx, m, pub, now) != nil {
		return fail()
	}
	receipt, _ := json.Marshal(struct {
		Version      string `json:"version"`
		PlanDigest   string `json:"planDigest"`
		BundleDigest string `json:"bundleDigest"`
	}{Version, p.Digest, bundle.BundleDigest})
	if fx.Create(CompletePath(p.StateDirectory), receipt) != nil {
		return fail()
	}
	return bundle, nil
}
func RedactedError(w io.Writer) {
	fmt.Fprintln(w, "Action setup blocked; preserve all existing files, keys, receipts and ledgers. Do not rerun initialization to repair partial state.")
}

// StatusManager verifies completed provenance and all authority artifacts using
// read-only loaders. It neither contacts an endpoint nor initializes lost state.
func StatusManager(ctx context.Context, lan, enrollment, device string, now time.Time) (Bundle, error) {
	m, e := load(ctx, lan, enrollment, device, now, false)
	if e != nil {
		return Bundle{}, ErrSetup
	}
	p := m.plan
	read := func(path string) ([]byte, error) { return lanconfig.ReadProtected(path, true, 32768) }
	raw, e := read(IntentPath(p.StateDirectory))
	if e != nil {
		return Bundle{}, ErrSetup
	}
	expected, _ := json.Marshal(struct {
		Version string      `json:"version"`
		Plan    ManagerPlan `json:"plan"`
	}{Version, p})
	if !bytes.Equal(raw, expected) {
		return Bundle{}, ErrSetup
	}
	key, e := read(setupPath(p.StateDirectory, "command.key"))
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return Bundle{}, ErrSetup
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(key, derived) {
		return Bundle{}, ErrSetup
	}
	pub := derived.Public().(ed25519.PublicKey)
	for _, old := range m.forbidden {
		if bytes.Equal(pub, old) {
			return Bundle{}, ErrSetup
		}
	}
	inspection, e := enrollmentstore.InspectServiceActionSetup(ctx, filepath.Join(p.StateDirectory, enrollmentconfig.DatabaseFile), m.enrollment.Issuer().IssuerDER(), device, now)
	if e != nil || !bytes.Equal(inspection.PublicKey, pub) {
		return Bundle{}, ErrSetup
	}
	bundle := NewBundle(p, pub)
	config := actionmanager.Config{Version: actionmanager.ConfigVersion, Enabled: true, ManagerID: p.ManagerID, TransportProfile: p.TransportProfile, HTTPTestAcknowledged: p.HTTPTestAcknowledged, PrivateKeyFile: setupPath(p.StateDirectory, "command.key")}
	updated := m.lan.Config
	updated.ServiceActionsConfigFile = setupPath(p.StateDirectory, "commands.json")
	receipt := struct {
		Version      string `json:"version"`
		PlanDigest   string `json:"planDigest"`
		BundleDigest string `json:"bundleDigest"`
	}{Version, p.Digest, bundle.BundleDigest}
	for path, value := range map[string]any{setupPath(p.StateDirectory, "commands.json"): config, LANPath(p.StateDirectory): updated, setupPath(p.StateDirectory, "bundle.json"): bundle, CompletePath(p.StateDirectory): receipt} {
		raw, e := read(path)
		expected, _ := json.Marshal(value)
		if e != nil || !bytes.Equal(raw, expected) {
			return Bundle{}, ErrSetup
		}
	}
	return bundle, nil
}
