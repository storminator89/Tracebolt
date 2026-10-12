package windowsaction

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"localrmm/internal/windowspackage"
)

func provisionFixture(t *testing.T) (ProvisionPlan, []byte) {
	t.Helper()
	policy := newFixture(t).p
	policy.BrokerSID, policy.AgentSID = FixedServiceSIDs()
	policy.ProvisioningVersion = ProvisionVersion
	policy.Binding.GrantDigest = GrantDigest(policy)
	payload := make([]byte, 1024)
	copy(payload, "MZ")
	binary.LittleEndian.PutUint32(payload[0x3c:], 0x80)
	copy(payload[0x80:], "PE\x00\x00")
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if runtime.GOARCH == "arm64" {
		machine = pe.IMAGE_FILE_MACHINE_ARM64
	}
	var header bytes.Buffer
	binary.Write(&header, binary.LittleEndian, pe.FileHeader{Machine: machine, NumberOfSections: 1, SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE})
	binary.Write(&header, binary.LittleEndian, pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: 0x1000, ImageBase: 0x140000000, SectionAlignment: 4096, FileAlignment: 512, SizeOfImage: 8192, SizeOfHeaders: 512, Subsystem: 3, NumberOfRvaAndSizes: 16})
	copy(payload[0x84:], header.Bytes())
	off := 0x84 + 20 + 240
	copy(payload[off:], ".text")
	binary.LittleEndian.PutUint32(payload[off+8:], 1)
	binary.LittleEndian.PutUint32(payload[off+12:], 0x1000)
	binary.LittleEndian.PutUint32(payload[off+16:], 512)
	binary.LittleEndian.PutUint32(payload[off+20:], 512)
	binary.LittleEndian.PutUint32(payload[off+36:], 0x60000020)
	payload[512] = 0xc3
	artifact := windowspackage.Manifest{SchemaVersion: windowspackage.ManifestSchema, Version: "v0.1.0-source", SourceCommit: strings.Repeat("a", 40), Architecture: runtime.GOARCH, SHA256: strings.TrimPrefix(Digest(payload), "sha256:")}
	delta := func(mask uint32) ACLDelta { return ACLDelta{"before", "after", policy.BrokerSID, mask} }
	p := ProvisionPlan{Version: ProvisionVersion, Consent: ProvisionConsent, Policy: policy, Artifact: artifact, ObserverReceiptDigest: Digest([]byte("observer receipt")), Executable: `C:\Program Files\Tracebolt\` + BrokerImageName, Account: BrokerAccount, Description: provisionDescription(policy, artifact), BrokerServiceSDDL: brokerServiceSDDL(policy.BrokerSID, policy.AgentSID), ImageDirectory: delta(0x1200a9), TargetService: delta(0x2003d), ObserverService: delta(0x20005), PeerProcessQueryRights: PeerProcessQueryRights}
	if e := validateProvisionPlan(p, payload); e != nil {
		t.Fatal(e)
	}
	return p, payload
}

type provisionFake struct {
	plan        ProvisionPlan
	files       map[string][]byte
	events      []string
	fail        string
	created     bool
	cancel      context.CancelFunc
	cancelStage string
}

func (f *provisionFake) Plan(context.Context, Policy, windowspackage.Manifest, string, bool) (ProvisionPlan, error) {
	f.events = append(f.events, "plan")
	if f.created || f.fail == "plan" {
		return ProvisionPlan{}, ErrBinding
	}
	return f.plan, nil
}
func (f *provisionFake) CreateJournal(context.Context, ProvisionPlan) (provisionJournal, error) {
	f.events = append(f.events, "fence")
	if f.created || f.fail == "fence" {
		return nil, ErrBinding
	}
	f.created = true
	return provisionFakeJournal{f}, nil
}
func (f *provisionFake) Write(n string, b []byte) error {
	f.events = append(f.events, "write:"+n)
	if f.fail == "write:"+n {
		return ErrIntegrity
	}
	f.files[n] = bytes.Clone(b)
	return nil
}

// Separate adapter avoids overloading Store.Verify and Session.Verify.
type provisionFakeSession struct{ *provisionFake }

func (f provisionFakeSession) Verify(context.Context, ProvisionPlan) error {
	f.events = append(f.events, "final-verify")
	if f.fail == "final-verify" {
		return ErrBinding
	}
	return nil
}
func (f *provisionFake) ApplyStage(_ context.Context, stage string, p ProvisionPlan, _ []byte) error {
	f.events = append(f.events, "effect:"+stage)
	var progress provisionProgress
	if DecodeCanonical(f.files["progress.json"], &progress, MaxProvisionBytes) != nil || progress.Attempted != stage || progress.PlanDigest != p.Digest() {
		return ErrIntegrity
	}
	if f.cancelStage == stage {
		f.cancel()
	}
	if f.fail == stage {
		return ErrBinding
	}
	return nil
}
func (f *provisionFake) Close() error { return nil }

// Exact Store method, exposed through the journal adapter only.
type provisionFakeJournal struct{ *provisionFake }

func (f provisionFakeJournal) Verify() error { return nil }
func (f provisionFakeSession) CreateJournal(ctx context.Context, p ProvisionPlan) (provisionJournal, error) {
	_, e := f.provisionFake.CreateJournal(ctx, p)
	if e != nil {
		return nil, e
	}
	return provisionFakeJournal{f.provisionFake}, nil
}
func newProvisionFake(p ProvisionPlan) *provisionFake {
	return &provisionFake{plan: p, files: map[string][]byte{}}
}
func runProvisionFake(ctx context.Context, f *provisionFake, p ProvisionPlan, payload []byte, approval string) error {
	hooks := ProvisionHooks{Validate: func(ctx context.Context) error { return ctx.Err() }, CreateRelay: func(ctx context.Context) error { return f.ApplyStage(ctx, "observer-relay", p, nil) }, VerifyRelay: func(context.Context) error {
		if f.fail == "relay-verify" {
			return ErrBinding
		}
		return nil
	}}
	return applyProvision(ctx, p, payload, approval, hooks, func(context.Context) (provisionSession, error) { return provisionFakeSession{f}, nil })
}
func TestProvisionCreatesOnlyAfterExactApprovalAndKeepsStages(t *testing.T) {
	p, payload := provisionFixture(t)
	f := newProvisionFake(p)
	if runProvisionFake(context.Background(), f, p, payload, Digest([]byte("wrong"))) == nil || len(f.events) != 0 {
		t.Fatal("wrong approval reached host")
	}
	if e := runProvisionFake(context.Background(), f, p, payload, p.Digest()); e != nil {
		t.Fatal(e)
	}
	var progress provisionProgress
	if DecodeCanonical(f.files["progress.json"], &progress, MaxProvisionBytes) != nil || !reflect.DeepEqual(progress.Completed, provisionStages) || progress.Attempted != "" {
		t.Fatal("missing exact phase receipt")
	}
	var receipt provisionReceipt
	if DecodeCanonical(f.files["receipt.json"], &receipt, 4096) != nil || !receipt.Complete || receipt.PlanDigest != p.Digest() {
		t.Fatal("missing receipt")
	}
	if runProvisionFake(context.Background(), f, p, payload, p.Digest()) == nil {
		t.Fatal("adopted existing setup")
	}
}
func TestProvisionFailureAndCancellationNeverRetryOrComplete(t *testing.T) {
	p, payload := provisionFixture(t)
	for _, stage := range append(append([]string{}, provisionStages...), "final-verify", "relay-verify", "write:receipt.json") {
		f := newProvisionFake(p)
		f.fail = stage
		if runProvisionFake(context.Background(), f, p, payload, p.Digest()) == nil {
			t.Fatal(stage)
		}
		if !f.created || len(f.files["started.json"]) == 0 || len(f.files["receipt.json"]) != 0 {
			t.Fatal("partial lost or completed", stage)
		}
		count := len(f.events)
		if runProvisionFake(context.Background(), f, p, payload, p.Digest()) == nil {
			t.Fatal("fresh retry", stage)
		}
		for _, event := range f.events[count:] {
			if strings.HasPrefix(event, "effect:") {
				t.Fatal("repeated effect", stage)
			}
		}
	}
	for _, stage := range provisionStages {
		ctx, cancel := context.WithCancel(context.Background())
		f := newProvisionFake(p)
		f.cancel = cancel
		f.cancelStage = stage
		e := runProvisionFake(ctx, f, p, payload, p.Digest())
		cancel()
		if !errors.Is(e, context.Canceled) || len(f.files["receipt.json"]) != 0 {
			t.Fatal("cancel admitted completion", stage, e)
		}
	}
}
func TestProvisionRechecksDriftAndArtifactBeforeAnyFence(t *testing.T) {
	p, payload := provisionFixture(t)
	for _, change := range []func(*ProvisionPlan){func(q *ProvisionPlan) { q.TargetService.Before = "changed" }, func(q *ProvisionPlan) { q.ObserverReceiptDigest = Digest([]byte("new observer")) }, func(q *ProvisionPlan) { q.ImageDirectory.After = "changed" }, func(q *ProvisionPlan) { q.HTTPAcknowledged = true }} {
		f := newProvisionFake(p)
		change(&f.plan)
		if runProvisionFake(context.Background(), f, p, payload, p.Digest()) == nil || f.created {
			t.Fatal("changed review admitted")
		}
	}
	changed := bytes.Clone(payload)
	changed[len(changed)-1] ^= 1
	f := newProvisionFake(p)
	if runProvisionFake(context.Background(), f, p, changed, p.Digest()) == nil || len(f.events) != 0 {
		t.Fatal("changed image admitted")
	}
}
func TestProvisionFixedServiceSIDAndLegacyPolicyBytes(t *testing.T) {
	if derivedServiceSID("TrustedInstaller") != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Fatal("service SID derivation")
	}
	p := newFixture(t).p
	raw, _ := json.Marshal(p)
	if bytes.Contains(raw, []byte("provisioningVersion")) {
		t.Fatal("old policy bytes promoted")
	}
	before := GrantDigest(p)
	p.ProvisioningVersion = ProvisionVersion
	if GrantDigest(p) == before {
		t.Fatal("fresh consent did not change grant binding")
	}
	p.Binding.GrantDigest = GrantDigest(p)
	if ValidatePolicy(p) != nil {
		t.Fatal("fresh policy rejected")
	}
	p.ProvisioningVersion = "unknown"
	p.Binding.GrantDigest = GrantDigest(p)
	if ValidatePolicy(p) == nil {
		t.Fatal("unknown setup authority")
	}
}

type missingProvisionMemory struct{ *memory }

func (m missingProvisionMemory) Read(name string) ([]byte, error) {
	if _, ok := m.files[name]; !ok {
		return nil, os.ErrNotExist
	}
	return m.memory.Read(name)
}
func TestProvisionUsedReceiptNeverFallsBackToLegacy(t *testing.T) {
	p, payload := provisionFixture(t)
	f := newProvisionFake(p)
	if e := runProvisionFake(context.Background(), f, p, payload, p.Digest()); e != nil {
		t.Fatal(e)
	}
	m := missingProvisionMemory{&memory{files: f.files}}
	if _, e := readProvisionRecords(m, p.Policy); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"started.json", "progress.json", "receipt.json"} {
		raw := m.files[name]
		delete(m.files, name)
		if _, e := readProvisionRecords(m, p.Policy); e == nil || errors.Is(e, os.ErrNotExist) {
			t.Fatal("missing used record became legacy", name, e)
		}
		m.files[name] = raw
	}
	raw := m.files["progress.json"]
	var progress provisionProgress
	json.Unmarshal(raw, &progress)
	progress.Attempted = "observer-relay"
	m.files["progress.json"], _ = json.Marshal(progress)
	if _, e := readProvisionRecords(m, p.Policy); e == nil {
		t.Fatal("attempted stage accepted")
	}
	m.files["progress.json"] = raw
	changed := p.Policy
	changed.ProvisioningVersion = ""
	changed.Binding.GrantDigest = GrantDigest(changed)
	if _, e := readProvisionRecords(m, changed); e == nil {
		t.Fatal("legacy policy promoted")
	}
}

func TestProvisionJournalFailureAndLeaseLossPrecedeEffects(t *testing.T) {
	p, payload := provisionFixture(t)
	for _, failure := range []string{"fence", "write:started.json", "write:progress.json"} {
		f := newProvisionFake(p)
		f.fail = failure
		if runProvisionFake(context.Background(), f, p, payload, p.Digest()) == nil {
			t.Fatal(failure)
		}
		for _, event := range f.events {
			if strings.HasPrefix(event, "effect:") {
				t.Fatal("effect preceded durable phase", failure)
			}
		}
	}
	for failAt := 1; failAt <= 4; failAt++ {
		f := newProvisionFake(p)
		calls := 0
		hooks := ProvisionHooks{Validate: func(context.Context) error {
			calls++
			if calls == failAt {
				return ErrBinding
			}
			return nil
		}, CreateRelay: func(context.Context) error { return nil }, VerifyRelay: func(context.Context) error { return nil }}
		e := applyProvision(context.Background(), p, payload, p.Digest(), hooks, func(context.Context) (provisionSession, error) { return provisionFakeSession{f}, nil })
		if e == nil {
			t.Fatal("lost lease accepted", failAt)
		}
		for _, event := range f.events {
			if strings.HasPrefix(event, "effect:") {
				t.Fatal("effect followed lost early lease", failAt)
			}
		}
	}
}
