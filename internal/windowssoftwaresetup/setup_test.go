package windowssoftwaresetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssoftwareipc"
	job "localrmm/internal/windowssoftwarejob"
)

type fixtureStore struct {
	files        map[string][]byte
	writes, fail int
	poison       bool
	onWrite      func(string)
}

func (s *fixtureStore) Read(n string) ([]byte, error) {
	if s.poison {
		return nil, ErrSetup
	}
	b, ok := s.files[n]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (s *fixtureStore) Write(n string, b []byte) error {
	s.writes++
	if s.writes == s.fail {
		s.poison = true
		return ErrSetup
	}
	s.files[n] = bytes.Clone(b)
	if s.onWrite != nil {
		s.onWrite(n)
	}
	return nil
}
func (s *fixtureStore) Verify() error {
	if s.poison {
		return ErrSetup
	}
	return nil
}
func (s *fixtureStore) Close() error { return nil }

type setupFixture struct {
	p                                  Plan
	payload                            []byte
	packagePayload                     []byte
	packageReceipt                     windowspackage.PreparedMSIReceipt
	packages                           int
	s                                  *fixtureStore
	now                                time.Time
	image                              windowspackage.SoftwareExecutorImageReceipt
	relay                              lanclient.WindowsSoftwareRelayGrant
	h                                  Hooks
	created, generated, images, relays int
	freshErr, checkErr                 error
	afterRelay                         func()
}

func fixturePayload() []byte {
	p := make([]byte, 1024)
	copy(p, "MZ")
	binary.LittleEndian.PutUint32(p[0x3c:], 0x80)
	copy(p[0x80:], "PE\x00\x00")
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if runtime.GOARCH == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	var h bytes.Buffer
	_ = binary.Write(&h, binary.LittleEndian, pe.FileHeader{Machine: machine, NumberOfSections: 1, SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE})
	_ = binary.Write(&h, binary.LittleEndian, pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: 0x1000, ImageBase: 0x140000000, SectionAlignment: 4096, FileAlignment: 512, SizeOfImage: 8192, SizeOfHeaders: 512, Subsystem: 3, NumberOfRvaAndSizes: 16})
	copy(p[0x84:], h.Bytes())
	s := 0x84 + 20 + 240
	copy(p[s:], ".text")
	binary.LittleEndian.PutUint32(p[s+8:], 1)
	binary.LittleEndian.PutUint32(p[s+12:], 0x1000)
	binary.LittleEndian.PutUint32(p[s+16:], 512)
	binary.LittleEndian.PutUint32(p[s+20:], 512)
	binary.LittleEndian.PutUint32(p[s+36:], 0x60000020)
	return p
}
func newSetupFixture(t *testing.T) *setupFixture {
	t.Helper()
	f := &setupFixture{s: &fixtureStore{files: map[string][]byte{}}, now: time.Unix(1800000000, 0), payload: fixturePayload()}
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32)).Public().(ed25519.PublicKey)
	o := job.SetupOffer{Version: job.SetupOfferVersion, ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("original anchor")), ManagerOrigin: "https://manager.invalid", ManagerPublicKey: manager, ExpiresAt: f.now.Unix() + 300}
	i := lanclient.WindowsSoftwareSetupIdentity{ManagerID: o.ManagerID, DeviceID: o.DeviceID, IncarnationDigest: o.IncarnationDigest, ManagerOrigin: o.ManagerOrigin, SenderBinding: "original sender", ConfigDigest: actionpermit.Digest([]byte("config")), LeafDigest: actionpermit.Digest([]byte("current leaf")), LeafPublicKeyDigest: actionpermit.Digest([]byte("TLS public key")), LeafNotBefore: f.now.Unix() - 60, LeafNotAfter: f.now.Unix() + 600}
	l := windowsservice.Layout{ProgramFiles: `C:\Program Files`, ProgramData: `C:\ProgramData`, Executable: `C:\Program Files\Tracebolt\tracebolt-windows-service.exe`, StateRoot: `C:\ProgramData\Tracebolt\windows-agent`, EnrollmentRoot: `C:\ProgramData\Tracebolt\windows-agent\enrollment`, SenderRoot: `C:\ProgramData\Tracebolt\windows-agent\enrollment\telemetry`}
	r := windowsservice.Receipt{Version: 1, InstallationID: strings.Repeat("4", 32), Layout: l, ConfigurationSHA256: strings.Repeat("5", 64), ExecutableSHA256: strings.Repeat("6", 64), ServiceSID: "S-1-5-80-1-2-3-4-5", Complete: true}
	digest := sha256.Sum256(f.payload)
	m := windowspackage.Manifest{SchemaVersion: windowspackage.ManifestSchema, Version: "v0.1.0-fixture", SourceCommit: strings.Repeat("a", 40), Architecture: runtime.GOARCH, SHA256: hex.EncodeToString(digest[:])}
	var e error
	f.packagePayload = make([]byte, 512)
	copy(f.packagePayload, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	selection := job.Selection{SHA256: actionpermit.Digest(f.packagePayload), Size: 512, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture package", TermsReviewDigest: actionpermit.Digest([]byte("reviewed terms")), ReviewReference: "fixture review"}
	f.packageReceipt = windowspackage.PreparedMSIReceipt{Version: windowspackage.PreparedMSIVersion, Package: selection, VolumeSerialNumber: 1, FileIndexLow: 4, DirectoryVolumeSerialNumber: 1, DirectoryFileIndexLow: 5}
	f.p, e = NewPlan(o, m, i, r, selection, actionpermit.Digest([]byte("native fixture acceptance")))
	if e != nil {
		t.Fatal(e)
	}
	f.image = windowspackage.SoftwareExecutorImageReceipt{Version: windowspackage.SoftwareExecutorImageVersion, Path: f.p.Executable, SHA256: "sha256:" + m.SHA256, Size: int64(len(f.payload)), VolumeSerialNumber: 1, FileIndexHigh: 2, FileIndexLow: 3}
	f.h = Hooks{StagePackage: func(_ context.Context, payload []byte, selection job.Selection) (windowspackage.PreparedMSIReceipt, error) {
		f.packages++
		if !bytes.Equal(payload, f.packagePayload) || selection != f.p.Package {
			return windowspackage.PreparedMSIReceipt{}, ErrSetup
		}
		return f.packageReceipt, nil
	}, VerifyPackage: func(_ context.Context, r windowspackage.PreparedMSIReceipt) error {
		if r != f.packageReceipt {
			return ErrSetup
		}
		return nil
	}, Check: func(context.Context, Plan) error { return f.checkErr }, Fresh: func(context.Context, Plan) error { return f.freshErr }, CreateStore: func(context.Context, Plan) (Store, error) { f.created++; return f.s, nil }, CreateImage: func(context.Context, []byte, windowspackage.Manifest) (windowspackage.SoftwareExecutorImageReceipt, error) {
		f.images++
		return f.image, nil
	}, VerifyImage: func(context.Context, windowspackage.SoftwareExecutorImageReceipt) error { return nil }, CreateRelay: func(_ context.Context, g lanclient.WindowsSoftwareRelayGrant) error {
		f.relays++
		f.relay = g
		if f.afterRelay != nil {
			f.afterRelay()
		}
		return nil
	}, VerifyRelay: func(_ context.Context, g lanclient.WindowsSoftwareRelayGrant) error {
		if !sameJSON(g, f.relay) {
			return ErrSetup
		}
		return nil
	}}
	return f
}
func (f *setupFixture) apply() (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, f.packagePayload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, PackageReview: true, NativeAcceptance: true}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		f.generated++
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32)), "executor_" + strings.Repeat("7", 32), "grant_" + strings.Repeat("8", 32), nil
	}, func() time.Time { return f.now })
}
func (f *setupFixture) config(t *testing.T) windowssoftwareipc.Config {
	t.Helper()
	c, e := windowssoftwareipc.DecodeConfig(f.s.files["config.json"])
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestFreshSoftwareSetupCoreSuccess(t *testing.T) {
	f := newSetupFixture(t)
	r, e := f.apply()
	if e != nil || r.Validate() != nil || f.generated != 1 || f.images != 1 || f.relays != 1 {
		t.Fatal(e, f.generated, f.images, f.relays)
	}
	c := f.config(t)
	if VerifyInstalled(f.s, c) != nil || r.Consent.ExpiresAt != f.p.Offer.ExpiresAt || f.relay.ExpiresAt != r.Consent.ExpiresAt || f.relay.Binding != r.Consent.Binding || f.relay.ExecutorPeer.ConfigurationDigest == "" || c.ObserverReceipt != f.p.Observer || !c.ObserverProcessQueryAcknowledged {
		t.Fatal("bindings/scopes drifted")
	}
	if !bytes.Equal(f.s.files["started.json"], f.s.files["receipt.json"]) {
		t.Fatal("original consent changed")
	}
	var ledger job.ExecutorRecord
	if json.Unmarshal(f.s.files["executor.json"], &ledger) != nil || ledger.Validate() != nil || len(ledger.Attempts) != 0 || ledger.Sequence != 0 || ledger.ReadinessSequence != 0 {
		t.Fatal("used ledger invalid")
	}
	for _, name := range []string{"provision.json", "progress.json", "config.json", "executor.json", "started.json", "receipt.json"} {
		if bytes.Contains(f.s.files[name], []byte(`"key":`)) {
			t.Fatal("private key in public state", name)
		}
	}
	if f.relay.Scope != lanclient.WindowsSoftwareRelayScope || c.Consent.Scope != job.Scope {
		t.Fatal("scope expanded")
	}
}
func TestFreshSoftwareSetupRejectsIdentityExpiryAndExisting(t *testing.T) {
	for _, name := range []string{"manager", "device", "anchor", "origin", "expired", "current-leaf", "existing", "partial", "changed-check", "approval"} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t)
			switch name {
			case "manager":
				f.p.Identity.ManagerID = "manager_" + strings.Repeat("f", 32)
			case "device":
				f.p.Identity.DeviceID = "agent_" + strings.Repeat("f", 32)
			case "anchor":
				f.p.Identity.IncarnationDigest = actionpermit.Digest([]byte("other"))
			case "origin":
				f.p.Identity.ManagerOrigin = "https://other.invalid"
			case "expired":
				f.now = time.Unix(f.p.Offer.ExpiresAt, 0)
			case "current-leaf":
				f.now = time.Unix(f.p.Identity.LeafNotAfter, 0)
			case "existing", "partial":
				f.freshErr = ErrExisting
			case "changed-check":
				f.checkErr = ErrChanged
			case "approval":
				f.p.Offer.ManagerPublicKey = f.p.Offer.ManagerPublicKey[:1]
			}
			if _, e := f.apply(); e == nil || f.created != 0 || f.generated != 0 || f.images != 0 || f.relays != 0 {
				t.Fatal("invalid setup reached mutation", e)
			}
		})
	}
}
func TestFreshSoftwareSetupRetainsFailedTransactionEvidence(t *testing.T) {
	good := newSetupFixture(t)
	if _, e := good.apply(); e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= good.s.writes; n++ {
		t.Run(string(rune('A'+n)), func(t *testing.T) {
			f := newSetupFixture(t)
			f.s.fail = n
			r, e := f.apply()
			if e == nil || r.Version != "" || !f.s.poison || f.created != 1 {
				t.Fatal("uncertain write reported success", n, e)
			}
			if n == 1 && f.generated != 0 {
				t.Fatal("key generated before intent")
			}
			if n > 1 && len(f.s.files["provision.json"]) == 0 {
				t.Fatal("intent removed")
			}
			if len(f.s.files["config.json"]) > 0 && VerifyInstalled(f.s, f.config(t)) == nil {
				t.Fatal("partial admitted")
			}
		})
	}
	f := newSetupFixture(t)
	f.afterRelay = func() { f.now = time.Unix(f.p.Offer.ExpiresAt, 0) }
	r, e := f.apply()
	if !errors.Is(e, job.ErrExpired) || r.Version != "" || len(f.s.files["receipt.json"]) != 0 || len(f.s.files["provision.json"]) == 0 {
		t.Fatal("post-wait expiry refreshed", e)
	}
}

func TestPreparedMSIExplicitAcknowledgementsBeforeAnyMutation(t *testing.T) {
	for _, field := range []string{"install", "relay", "query", "risk", "acceptance", "digest"} {
		t.Run(field, func(t *testing.T) {
			f := newSetupFixture(t)
			a := Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, PackageReview: true, NativeAcceptance: true}
			switch field {
			case "install":
				a.Install = false
			case "relay":
				a.Relay = false
			case "query":
				a.ProcessQuery = false
			case "risk":
				a.PackageReview = false
			case "acceptance":
				a.NativeAcceptance = false
			case "digest":
				a.Digest = actionpermit.Digest([]byte("other"))
			}
			if _, e := apply(context.Background(), f.p, f.payload, f.packagePayload, a, f.h, generateMaterial, func() time.Time { return f.now }); e == nil || f.created != 0 || f.packages != 0 {
				t.Fatal("unchecked approval reached mutation", e)
			}
		})
	}
}
func TestPreparedMSIReceiptAndManifestStayExactlyBound(t *testing.T) {
	for _, kind := range []string{"payload", "receipt-selection", "receipt-identity", "saved-receipt", "consent", "acceptance"} {
		t.Run(kind, func(t *testing.T) {
			f := newSetupFixture(t)
			switch kind {
			case "payload":
				f.packagePayload[40]++
			case "receipt-selection":
				f.packageReceipt.Package.Version = "1.2.4"
			case "receipt-identity":
				f.packageReceipt.VolumeSerialNumber = 0
				f.packageReceipt.FileIndexLow = 0
			}
			r, e := f.apply()
			if kind == "payload" || kind == "receipt-selection" || kind == "receipt-identity" {
				if e == nil || r.Version != "" {
					t.Fatal("mismatched custody accepted")
				}
				return
			}
			if e != nil || f.packages != 1 {
				t.Fatal(e)
			}
			c := f.config(t)
			switch kind {
			case "saved-receipt":
				f.s.files["package.json"] = []byte("{}")
			case "consent":
				c.Consent.Package.Version = "1.2.4"
			case "acceptance":
				c.Consent.NativeAcceptanceDigest = actionpermit.Digest([]byte("other"))
			}
			if VerifyInstalled(f.s, c) == nil {
				t.Fatal("altered package authority admitted")
			}
		})
	}
}
