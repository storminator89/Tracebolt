package windowsupdatesetup

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
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
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
	s                                  *fixtureStore
	now                                time.Time
	image                              windowspackage.UpdateExecutorImageReceipt
	relay                              lanclient.WindowsUpdateRelayGrant
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
	i := lanclient.WindowsUpdateSetupIdentity{ManagerID: o.ManagerID, DeviceID: o.DeviceID, IncarnationDigest: o.IncarnationDigest, ManagerOrigin: o.ManagerOrigin, SenderBinding: "original sender", ConfigDigest: actionpermit.Digest([]byte("config")), LeafDigest: actionpermit.Digest([]byte("current leaf")), LeafPublicKeyDigest: actionpermit.Digest([]byte("TLS public key")), LeafNotBefore: f.now.Unix() - 60, LeafNotAfter: f.now.Unix() + 600}
	l := windowsservice.Layout{ProgramFiles: `C:\Program Files`, ProgramData: `C:\ProgramData`, Executable: `C:\Program Files\Tracebolt\tracebolt-windows-service.exe`, StateRoot: `C:\ProgramData\Tracebolt\windows-agent`, EnrollmentRoot: `C:\ProgramData\Tracebolt\windows-agent\enrollment`, SenderRoot: `C:\ProgramData\Tracebolt\windows-agent\enrollment\telemetry`}
	r := windowsservice.Receipt{Version: 1, InstallationID: strings.Repeat("4", 32), Layout: l, ConfigurationSHA256: strings.Repeat("5", 64), ExecutableSHA256: strings.Repeat("6", 64), ServiceSID: "S-1-5-80-1-2-3-4-5", Complete: true}
	digest := sha256.Sum256(f.payload)
	m := windowspackage.Manifest{SchemaVersion: windowspackage.ManifestSchema, Version: "v0.1.0-fixture", SourceCommit: strings.Repeat("a", 40), Architecture: runtime.GOARCH, SHA256: hex.EncodeToString(digest[:])}
	var e error
	f.p, e = NewPlan(o, m, i, r)
	if e != nil {
		t.Fatal(e)
	}
	f.image = windowspackage.UpdateExecutorImageReceipt{Version: windowspackage.UpdateExecutorImageVersion, Path: f.p.Executable, SHA256: "sha256:" + m.SHA256, Size: int64(len(f.payload)), VolumeSerialNumber: 1, FileIndexHigh: 2, FileIndexLow: 3}
	f.h = Hooks{Check: func(context.Context, Plan) error { return f.checkErr }, Fresh: func(context.Context, Plan) error { return f.freshErr }, CreateStore: func(context.Context, Plan) (Store, error) { f.created++; return f.s, nil }, CreateImage: func(context.Context, []byte, windowspackage.Manifest) (windowspackage.UpdateExecutorImageReceipt, error) {
		f.images++
		return f.image, nil
	}, VerifyImage: func(context.Context, windowspackage.UpdateExecutorImageReceipt) error { return nil }, CreateRelay: func(_ context.Context, g lanclient.WindowsUpdateRelayGrant) error {
		f.relays++
		f.relay = g
		if f.afterRelay != nil {
			f.afterRelay()
		}
		return nil
	}, VerifyRelay: func(_ context.Context, g lanclient.WindowsUpdateRelayGrant) error {
		if !sameJSON(g, f.relay) {
			return ErrSetup
		}
		return nil
	}}
	return f
}
func (f *setupFixture) apply() (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true, Schedule: f.p.ScheduleScope != ""}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		f.generated++
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32)), "executor_" + strings.Repeat("7", 32), "grant_" + strings.Repeat("8", 32), nil
	}, func() time.Time { return f.now })
}
func (f *setupFixture) config(t *testing.T) windowsupdateipc.Config {
	t.Helper()
	c, e := windowsupdateipc.DecodeConfig(f.s.files["config.json"])
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestFreshUpdateSetupCoreSuccess(t *testing.T) {
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
	if f.relay.Scope != lanclient.WindowsUpdateRelayScope || c.Consent.Scope != job.Scope {
		t.Fatal("scope expanded")
	}
}
func TestFreshUpdateSetupRejectsIdentityExpiryAndExisting(t *testing.T) {
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
func TestFreshUpdateSetupRetainsFailedTransactionEvidence(t *testing.T) {
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
func TestFreshUpdateSetupRemovalPreservesUsedState(t *testing.T) {
	f := newSetupFixture(t)
	if _, e := f.apply(); e != nil {
		t.Fatal(e)
	}
	c := f.config(t)
	original := bytes.Clone(f.s.files["executor.json"])
	p, _, _, e := InspectRemoval(f.s)
	if e != nil {
		t.Fatal(e)
	}
	retired, removed := 0, 0
	h := RemovalHooks{Check: func(context.Context, Plan) error { return nil }, VerifyImage: f.h.VerifyImage, RetireRelay: func(_ context.Context, g lanclient.WindowsUpdateRelayGrant) error {
		if !sameJSON(g, f.relay) {
			t.Fatal("wrong relay")
		}
		retired++
		return nil
	}, RemoveImage: func(_ context.Context, i windowspackage.UpdateExecutorImageReceipt) error {
		if i != f.image {
			t.Fatal("unknown image")
		}
		removed++
		return nil
	}, ImageAbsent: func(context.Context) error { return nil }}
	if e = remove(context.Background(), f.s, p.Digest(), h, func() time.Time { return f.now }); e != nil || retired != 1 || removed != 1 || VerifyRemoved(f.s) != nil || VerifyInstalled(f.s, c) == nil || !bytes.Equal(original, f.s.files["executor.json"]) {
		t.Fatal("removal boundary", e)
	}
	if _, _, _, e = InspectRemoval(f.s); e == nil {
		t.Fatal("tombstone adopted")
	}
}

func TestFreshUpdateSetupRemovalRejectsUnresolvedConsumedAttempts(t *testing.T) {
	for _, outcome := range []string{"consumed-not-attempted", "consumed-attempted", "uncertain", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			f := newSetupFixture(t)
			if _, e := f.apply(); e != nil {
				t.Fatal(e)
			}
			c := f.config(t)
			selection := job.Selection{UpdateID: "11111111-1111-1111-1111-111111111111", Revision: 1}
			readiness := job.Readiness{Selection: selection, CapturedAt: f.now.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, BundledCount: 0, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "can", OfflineVerified: job.Yes}
			preview := job.Preview{ID: "update_" + strings.Repeat("9", 32), ActorID: "operator_" + strings.Repeat("a", 32), Binding: c.Consent.Binding, Readiness: readiness, CreatedAt: f.now.Unix(), ExpiresAt: f.now.Unix() + 60}
			raw, _ := json.Marshal(preview)
			preview.Digest = actionpermit.Digest(append([]byte("Tracebolt selected WUA preview v1\x00"), raw...))
			permit := job.Permit{Version: job.Version, Preview: preview, Sequence: 1, ApprovedAt: f.now.Unix()}
			envelope, e := job.Sign(permit, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32)))
			if e != nil {
				t.Fatal(e)
			}
			attempt := job.Attempt{Envelope: envelope, ClaimedAt: f.now.Unix(), Attempted: outcome != "consumed-not-attempted"}
			if outcome == "uncertain" || outcome == "failed" {
				attempt.Result = &job.Result{JobID: preview.ID, EnvelopeDigest: actionpermit.Digest(envelope), Attempted: true, Outcome: outcome, OperationResult: 4, RebootRequired: job.Unknown, CompletedAt: f.now.Unix()}
				statement := job.Statement{Version: job.RelayVersion, Kind: "result", Binding: c.Consent.Binding, JobID: preview.ID, ReferenceDigest: actionpermit.Digest(envelope), Deadline: preview.ExpiresAt, IssuedAt: f.now.Unix(), ExpiresAt: f.now.Unix() + 300, Result: attempt.Result}
				attempt.ResultReport, e = job.SignStatement(statement, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32)))
				if e != nil {
					t.Fatal(e)
				}
			}
			var record job.ExecutorRecord
			if json.Unmarshal(f.s.files["executor.json"], &record) != nil {
				t.Fatal("ledger")
			}
			record.Sequence = 1
			record.Attempts = []job.Attempt{attempt}
			raw, e = job.EncodeExecutorRecord(record)
			if e != nil {
				t.Fatal("fixture must be a valid consumed ledger", e)
			}
			f.s.files["executor.json"] = raw
			before := f.s.writes
			mutations := 0
			hooks := RemovalHooks{Check: func(context.Context, Plan) error { return nil }, VerifyImage: func(context.Context, windowspackage.UpdateExecutorImageReceipt) error { return nil }, RetireRelay: func(context.Context, lanclient.WindowsUpdateRelayGrant) error { mutations++; return nil }, RemoveImage: func(context.Context, windowspackage.UpdateExecutorImageReceipt) error { mutations++; return nil }, ImageAbsent: func(context.Context) error { return nil }}
			if _, _, _, e = InspectRemoval(f.s); !errors.Is(e, job.ErrUncertain) {
				t.Fatal("consumed uncertainty was not identified", e)
			}
			if e = remove(context.Background(), f.s, actionpermit.Digest([]byte("irrelevant")), hooks, func() time.Time { return f.now }); e == nil || mutations != 0 || f.s.writes != before || len(f.s.files["removed.json"]) != 0 {
				t.Fatal("unresolved attempt retired authority", e)
			}
		})
	}
}

func TestFreshScheduledSetupNeverPromotesManualPlan(t *testing.T) {
	f := newSetupFixture(t)
	manual, _ := json.Marshal(f.p)
	if bytes.Contains(manual, []byte("schedule")) {
		t.Fatal("manual plan bytes gained schedule fields")
	}
	scheduled, err := NewScheduledPlan(f.p.Offer, f.p.Artifact, f.p.Identity, f.p.Observer)
	if err != nil || scheduled.Digest() == f.p.Digest() || scheduled.ScheduleScope != job.ScheduleScope || scheduled.ScheduleDisclosure != job.ScheduleDisclosure {
		t.Fatal("schedule plan lacks distinct review", err)
	}
	for _, tc := range []struct {
		plan        Plan
		acknowledge bool
	}{{scheduled, false}, {f.p, true}} {
		if _, err := apply(context.Background(), tc.plan, f.payload, Approval{Digest: tc.plan.Digest(), Install: true, Relay: true, ProcessQuery: true, Schedule: tc.acknowledge}, f.h, generateMaterial, func() time.Time { return f.now }); err == nil || f.created != 0 || f.generated != 0 {
			t.Fatal("schedule acknowledgement inferred or added to manual setup")
		}
	}
	f.p = scheduled
	r, err := f.apply()
	if err != nil || r.Consent.Version != job.ScheduledConsentVersion || r.Consent.ScheduleScope != job.ScheduleScope || !r.Consent.ScheduleAcknowledged || r.Consent.ExpiresAt != scheduled.Offer.ExpiresAt {
		t.Fatal("fresh scheduling registration", err)
	}
	if VerifyInstalled(f.s, f.config(t)) != nil {
		t.Fatal("fresh scheduling setup did not verify")
	}
	var saved Plan
	if decode(f.s.files["provision.json"], &saved) != nil {
		t.Fatal("plan")
	}
	saved.ScheduleScope = ""
	saved.ScheduleDisclosure = ""
	f.s.files["provision.json"], _ = json.Marshal(saved)
	if VerifyInstalled(f.s, f.config(t)) == nil {
		t.Fatal("manual plan adopted scheduling consent")
	}
}
