package windowsmanagedmsi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	data   map[string][]byte
	writes int
	failAt int
}

func (s *memoryStore) Read(n string) ([]byte, error) {
	v, ok := s.data[n]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(v), nil
}
func (s *memoryStore) Write(n string, b []byte) error {
	s.writes++
	if s.failAt == s.writes {
		return ErrUncertain
	}
	s.data[n] = bytes.Clone(b)
	return nil
}
func (s *memoryStore) Verify() error { return nil }

type memoryPayload struct {
	bytes    []byte
	offset   int64
	complete bool
}

func (p *memoryPayload) Create(context.Context, Selection) (json.RawMessage, error) {
	if p.bytes != nil {
		return nil, ErrConflict
	}
	p.bytes = []byte{}
	return json.RawMessage(`{"object":1}`), nil
}
func (p *memoryPayload) Open(_ context.Context, r json.RawMessage, n int64, d string, pending *ChunkIntent) error {
	if string(r) != `{"object":1}` || int64(len(p.bytes)) < n || Digest(p.bytes[:n]) != d {
		return ErrIntegrity
	}
	if int64(len(p.bytes)) > n && (pending == nil || int64(pending.Size) != int64(len(p.bytes))-n || Digest(p.bytes[n:]) != pending.Digest) {
		return ErrIntegrity
	}
	p.offset = n
	return nil
}
func (p *memoryPayload) Append(_ context.Context, offset int64, b []byte) (string, error) {
	if offset < p.offset {
		if offset+int64(len(b)) != p.offset || !bytes.Equal(p.bytes[offset:p.offset], b) {
			return "", ErrConflict
		}
		return Digest(p.bytes[:p.offset]), nil
	}
	if offset != p.offset {
		return "", ErrConflict
	}
	if int64(len(p.bytes)) == offset {
		p.bytes = append(p.bytes, b...)
	} else if !bytes.Equal(p.bytes[offset:], b) {
		return "", ErrIntegrity
	}
	p.offset = offset + int64(len(b))
	return Digest(p.bytes[:p.offset]), nil
}
func (p *memoryPayload) Complete(_ context.Context, s Selection) (json.RawMessage, error) {
	if int64(len(p.bytes)) != s.Size || Digest(p.bytes) != s.SHA256 {
		return nil, ErrIntegrity
	}
	p.complete = true
	return json.RawMessage(`{"object":1,"verified":true}`), nil
}
func (p *memoryPayload) Close() error { return nil }

type fixtureInstaller struct {
	mu           sync.Mutex
	calls        int
	at           *time.Time
	code         uint32
	registration Fact
	before       func()
	block        <-chan struct{}
}

func (i *fixtureInstaller) Inspect(_ context.Context, _ json.RawMessage, s Selection, until int64) (Readiness, error) {
	return Readiness{Selection: s, CapturedAt: i.at.Unix(), PackageVerified: Yes, MachineAbsent: Yes, InstallerBusy: No, NativeAcceptance: Yes, PackageReviewAccepted: Yes, MaintenanceWindowEnd: until}, nil
}
func (i *fixtureInstaller) Install(ctx context.Context, _ json.RawMessage, _ Readiness) (NativeResult, error) {
	if i.before != nil {
		i.before()
	}
	if e := CheckInstallStart(ctx, *i.at); e != nil {
		return NativeResult{RegistrationVerified: Unknown}, e
	}
	i.mu.Lock()
	i.calls++
	i.mu.Unlock()
	if i.block != nil {
		<-i.block
	}
	return NativeResult{ReturnCodeKnown: true, ReturnCode: i.code, RegistrationVerified: i.registration}, nil
}

type endpointFixture struct {
	at                time.Time
	manager, executor ed25519.PrivateKey
	g                 Grant
	p                 Permit
	raw, data         []byte
	store             *memoryStore
	blob              *memoryPayload
	installer         *fixtureInstaller
	current           Current
	x                 *Endpoint
}

func fixture(t *testing.T) *endpointFixture {
	t.Helper()
	f := &endpointFixture{at: time.Unix(1700000000, 0)}
	f.manager = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	f.executor = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: Digest([]byte("anchor")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: Digest(f.executor.Public().(ed25519.PublicKey)), KeyID: Digest(f.manager.Public().(ed25519.PublicKey)), DeliveryGrantID: "grant_" + strings.Repeat("4", 32), InstallGrantID: "grant_" + strings.Repeat("5", 32)}
	f.g = Grant{Version: GrantVersion, Binding: b, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: f.at.Unix() + 3600}
	f.current = Current{Binding: b, LeafDigest: Digest([]byte("leaf")), LeafGeneration: 1, LeafNotBefore: f.at.Unix() - 10, LeafNotAfter: f.at.Unix() + 7200, Enabled: true}
	f.data = bytes.Repeat([]byte{7}, MaxChunkBytes+512)
	copy(f.data, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	selection := Selection{SHA256: Digest(f.data), Size: int64(len(f.data)), ProductCode: "{11111111-1111-1111-1111-111111111111}", PackageCode: "{22222222-2222-2222-2222-222222222222}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture MSI", TermsReviewDigest: Digest([]byte("terms")), ReviewReference: "fixture only"}
	f.p = Permit{Version: Version, Kind: "deliver", TransferID: "transfer_" + strings.Repeat("6", 32), Binding: b, LeafDigest: f.current.LeafDigest, Package: selection, NativeAcceptanceDigest: Digest([]byte("native fixture")), ActorID: "operator_" + strings.Repeat("7", 32), IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 600}
	var e error
	f.raw, e = SignPermit(f.p, f.manager)
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewEndpointRecord(f.g, f.manager.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(r)
	f.store = &memoryStore{data: map[string][]byte{"endpoint.json": raw}}
	f.blob = &memoryPayload{}
	f.installer = &fixtureInstaller{at: &f.at, registration: Yes}
	f.open(t)
	return f
}
func (f *endpointFixture) open(t *testing.T) {
	t.Helper()
	var e error
	f.x, e = OpenEndpoint(f.store, f.blob, f.installer, func(context.Context, Binding) (Current, error) { return f.current, nil }, f.executor, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
}
func (f *endpointFixture) chunk(index uint32) Chunk {
	at := int(index) * MaxChunkBytes
	data := bytes.Clone(f.data[at:min(at+MaxChunkBytes, len(f.data))])
	return Chunk{f.p.TransferID, index, Digest(f.raw), Digest(data), data}
}
func (f *endpointFixture) deliver(t *testing.T) {
	t.Helper()
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	for i := uint32(0); int(i)*MaxChunkBytes < len(f.data); i++ {
		if e := f.x.Chunk(context.Background(), f.chunk(i)); e != nil {
			t.Fatal(e)
		}
	}
	status, e := f.x.Status(context.Background())
	if e != nil || status.State != "imported" {
		t.Fatalf("%+v %v", status, e)
	}
}
func (f *endpointFixture) approve(t *testing.T) []byte {
	t.Helper()
	p := f.p
	p.Kind = "readiness"
	p.Sequence = 1
	p.ExpiresAt = f.at.Unix() + 60
	p.MaintenanceUntil = f.at.Unix() + 600
	p.PackageReviewAccepted = true
	p.TermsAccepted = true
	raw, e := SignPermit(p, f.manager)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.x.Accept(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
	status, e := f.x.Status(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	p.Kind = "install"
	p.ReadinessDigest = Digest(status.Report)
	raw, e = SignPermit(p, f.manager)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestManagedDeliverySeparateReviewAndSingleAttempt(t *testing.T) {
	f := fixture(t)
	f.deliver(t)
	if f.installer.calls != 0 {
		t.Fatal("delivery installed")
	}
	raw := f.approve(t)
	if e := f.x.Accept(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
	f.x.Wait()
	if f.installer.calls != 1 {
		t.Fatal(f.installer.calls)
	}
	status, e := f.x.Status(context.Background())
	if e != nil || status.State != "succeeded" {
		t.Fatalf("%+v %v", status, e)
	}
	f.x.Close()
	f.open(t)
	if e = f.x.Accept(context.Background(), raw); !errors.Is(e, ErrConsumed) {
		t.Fatal(e)
	}
	if f.installer.calls != 1 {
		t.Fatal("replayed")
	}
}
func TestManagedPendingChunkExactResume(t *testing.T) {
	f := fixture(t)
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	c := f.chunk(0)
	f.x.record.Pending = &ChunkIntent{c.Index, c.Digest, len(c.Data)}
	if e := f.x.save(); e != nil {
		t.Fatal(e)
	}
	if _, e := f.blob.Append(context.Background(), 0, c.Data); e != nil {
		t.Fatal(e)
	}
	f.x.Close()
	f.open(t)
	if e := f.x.Chunk(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Chunk(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	c.Data[0] ^= 1
	c.Digest = Digest(c.Data)
	if e := f.x.Chunk(context.Background(), c); e == nil {
		t.Fatal("changed retry accepted")
	}
}
func TestManagedUnexplainedPayloadFences(t *testing.T) {
	f := fixture(t)
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	f.blob.bytes = []byte{1}
	f.x.Close()
	f.open(t)
	s, e := f.x.Status(context.Background())
	if e != nil || s.State != "intervention_required" {
		t.Fatalf("%+v %v", s, e)
	}
}
func TestManagedFinalCurrentFenceAndNoRestart(t *testing.T) {
	for _, kind := range []string{"revoke", "renew", "expire"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			f.deliver(t)
			raw := f.approve(t)
			f.installer.before = func() {
				switch kind {
				case "revoke":
					f.current.Revoked = true
				case "renew":
					f.current.LeafDigest = Digest([]byte("renewed"))
					f.current.LeafGeneration++
				case "expire":
					f.at = f.at.Add(time.Minute)
				}
			}
			if e := f.x.Accept(context.Background(), raw); e != nil {
				t.Fatal(e)
			}
			f.x.Wait()
			if f.installer.calls != 0 || !f.x.record.Attempted {
				t.Fatal("final fence lost")
			}
		})
	}
}
func TestManagedNativeOutcomeVocabulary(t *testing.T) {
	for code, want := range map[uint32]string{0: "succeeded", 3010: "restart_required", 1641: "unexpected_restart", 1618: "busy", 1603: "failed"} {
		t.Run(want, func(t *testing.T) {
			f := fixture(t)
			f.installer.code = code
			f.deliver(t)
			raw := f.approve(t)
			if e := f.x.Accept(context.Background(), raw); e != nil {
				t.Fatal(e)
			}
			f.x.Wait()
			s, e := f.x.Status(context.Background())
			if e != nil || s.State != want || f.installer.calls != 1 {
				t.Fatalf("%+v %v", s, e)
			}
		})
	}
}
func TestManagedPartialCreationAndFailedCheckpointFence(t *testing.T) {
	f := fixture(t)
	f.store.failAt = 2
	if e := f.x.Accept(context.Background(), f.raw); e == nil {
		t.Fatal("failed checkpoint accepted")
	}
	f.x.Close()
	f.store.failAt = 0
	f.open(t)
	s, e := f.x.Status(context.Background())
	if e != nil || s.State != "intervention_required" {
		t.Fatalf("%+v %v", s, e)
	}
}
func TestManagedContractDomainsAndBounds(t *testing.T) {
	f := fixture(t)
	for _, change := range []func(*Permit){func(p *Permit) { p.Version = "tracebolt.windows-prepared-msi-job.v1" }, func(p *Permit) { p.TermsAccepted = true }, func(p *Permit) { p.Package.Size = MaxArtifactBytes + 1 }, func(p *Permit) { p.Binding.InstallGrantID = p.Binding.DeliveryGrantID }} {
		p := f.p
		change(&p)
		if _, e := SignPermit(p, f.manager); e == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	c := f.chunk(0)
	b, _ := json.Marshal(struct {
		Chunk Chunk `json:"chunk"`
	}{c})
	if len(b) > MaxFrameBytes {
		t.Fatal(len(b))
	}
	if _, e := VerifyPermit(append(f.raw, '\n'), f.manager.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("noncanonical")
	}
}

type failingCompletePayload struct {
	*memoryPayload
	calls int
}

func (p *failingCompletePayload) Complete(context.Context, Selection) (json.RawMessage, error) {
	p.calls++
	return nil, errors.New("fixture completed native verification but custody close failed")
}
func TestManagedUncertainFinalizationNeverRestarts(t *testing.T) {
	f := fixture(t)
	bad := &failingCompletePayload{memoryPayload: f.blob}
	f.x.payload = bad
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Chunk(context.Background(), f.chunk(0)); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Chunk(context.Background(), f.chunk(1)); e == nil || bad.calls != 1 {
		t.Fatal("close failure not fenced", e, bad.calls)
	}
	f.x.Close()
	var e error
	f.x, e = OpenEndpoint(f.store, bad, f.installer, func(context.Context, Binding) (Current, error) { return f.current, nil }, f.executor, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.x.Status(context.Background())
	if e != nil || s.State != "intervention_required" || bad.calls != 1 || !f.x.record.FinalizationStarted {
		t.Fatal("uncertain finalization replayed", s, e, bad.calls)
	}
}
func TestManagedFinalizationCrashMarkerNeverRestarts(t *testing.T) {
	f := fixture(t)
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	for i := uint32(0); i < 2; i++ {
		c := f.chunk(i)
		digest, e := f.blob.Append(context.Background(), int64(i)*MaxChunkBytes, c.Data)
		if e != nil {
			t.Fatal(e)
		}
		f.x.record.Offset += int64(len(c.Data))
		f.x.record.PrefixDigest = digest
	}
	f.x.record.FinalizationStarted = true
	if e := f.x.save(); e != nil {
		t.Fatal(e)
	}
	f.x.Close()
	f.open(t)
	s, e := f.x.Status(context.Background())
	if e != nil || s.State != "intervention_required" || f.blob.complete {
		t.Fatal("crashed finalization replayed", s, e)
	}
}

func TestManagedFinalizationFailureReportIsDurableAndExact(t *testing.T) {
	f := fixture(t)
	bad := &failingCompletePayload{memoryPayload: f.blob}
	f.x.payload = bad
	if e := f.x.Accept(context.Background(), f.raw); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Chunk(context.Background(), f.chunk(0)); e != nil {
		t.Fatal(e)
	}
	if e := f.x.Chunk(context.Background(), f.chunk(1)); e == nil {
		t.Fatal("failure missing")
	}
	s, e := f.x.Status(context.Background())
	if e != nil || s.State != "intervention_required" || len(s.Report) == 0 || s.TransferID != f.p.TransferID {
		t.Fatal("missing durable terminal", s, e)
	}
	r, e := VerifyReport(s.Report, f.executor.Public().(ed25519.PublicKey))
	if e != nil || r.State != "intervention_required" || r.PermitDigest != Digest(f.raw) || r.Package != f.p.Package {
		t.Fatal("unbound failure", r, e)
	}
	original := bytes.Clone(s.Report)
	f.x.Close()
	f.at = f.at.Add(time.Second)
	f.open(t)
	s, e = f.x.Status(context.Background())
	if e != nil || !bytes.Equal(original, s.Report) {
		t.Fatal("terminal bytes refreshed", e)
	}
}

func TestManagedReusableConsentAndSignatureDomainsStaySeparate(t *testing.T) {
	f := fixture(t)
	legacy, _ := json.Marshal(f.g)
	if bytes.Contains(legacy, []byte("reusable")) {
		t.Fatal("legacy grant bytes expanded")
	}
	g := f.g
	g.Version = ReusableGrantVersion
	g.MutationPlanDigest = Digest([]byte("plan"))
	g.PeerBindingDigest = Digest([]byte("peer"))
	if g.Validate() == nil {
		t.Fatal("reusable without explicit consent")
	}
	g.ReusableAcknowledged = true
	if g.Validate() != nil {
		t.Fatal("fresh reusable grant")
	}
	p := f.p
	p.Version = ReusableVersion
	p.JobSequence = 1
	p.PublisherStatus = "verified"
	p.PublisherEvidenceDigest = Digest([]byte("evidence"))
	if _, e := SignPermit(p, f.manager); e == nil {
		t.Fatal("invented publisher verification")
	}
	p.PublisherStatus = "unverified"
	raw, e := SignPermit(p, f.manager)
	if e != nil {
		t.Fatal(e)
	}
	var signed signedPermit
	if json.Unmarshal(raw, &signed) != nil {
		t.Fatal("decode")
	}
	signed.Permit.Version = Version
	signed.Permit.JobSequence = 0
	signed.Permit.PublisherStatus = ""
	signed.Permit.PublisherEvidenceDigest = ""
	downgraded, _ := json.Marshal(signed)
	if _, e := VerifyPermit(downgraded, f.manager.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("cross-domain signature")
	}
	if e = f.x.Accept(context.Background(), raw); e == nil {
		t.Fatal("v3 permit on old endpoint")
	}
}
