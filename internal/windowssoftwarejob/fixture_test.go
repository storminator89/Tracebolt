package windowssoftwarejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"strings"
	"testing"
	"time"
)

type memoryStore struct {
	files         map[string][]byte
	writes        int
	fail          int
	commitFailure bool
}

func (s *memoryStore) Read(name string) ([]byte, error) {
	b, ok := s.files[name]
	if !ok {
		return nil, ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (s *memoryStore) Write(name string, b []byte) error {
	s.writes++
	if s.fail == s.writes {
		if s.commitFailure {
			s.files[name] = bytes.Clone(b)
		}
		return ErrUncertain
	}
	s.files[name] = bytes.Clone(b)
	return nil
}
func (s *memoryStore) Verify() error { return nil }

type authorityFixture struct {
	current Current
	calls   int
	before  func(int)
}

func (g *authorityFixture) WithCurrent(ctx context.Context, b Binding, fn func(Current) error) error {
	g.calls++
	if g.before != nil {
		g.before(g.calls)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return fn(g.current)
}

type readinessFixture struct {
	value Readiness
	calls int
	err   error
}

func (s *readinessFixture) Readiness(context.Context, Binding, Selection) (Readiness, error) {
	s.calls++
	return s.value, s.err
}

type workflowFixture struct {
	m         *Manager
	store     *memoryStore
	guard     *authorityFixture
	source    *readinessFixture
	key       ed25519.PrivateKey
	at        time.Time
	consent   Consent
	id, actor string
}

func fixture(t *testing.T) *workflowFixture {
	t.Helper()
	f := &workflowFixture{at: time.Unix(1800000000, 0).UTC(), id: "software_" + strings.Repeat("4", 32), actor: "operator_" + strings.Repeat("5", 32)}
	f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("original")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(executorKey().Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: actionpermit.Digest(f.key.Public().(ed25519.PublicKey))}
	f.consent = Consent{Package: testSelection(), NativeAcceptanceDigest: actionpermit.Digest([]byte("native acceptance")), PackageReviewAccepted: true, Version: ConsentVersion, Scope: Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.at.Unix() + 3600}
	f.guard = &authorityFixture{current: Current{Binding: b, LeafDigest: actionpermit.Digest([]byte("leaf")), LeafGeneration: 1, LeafNotBefore: f.at.Unix() - 1, LeafNotAfter: f.at.Unix() + 300, Enabled: true}}
	f.source = &readinessFixture{value: Readiness{Selection: testSelection(), CapturedAt: f.at.Unix(), PackageVerified: Yes, MachineAbsent: Yes, InstallerBusy: No, NativeAcceptance: Yes, PackageReviewAccepted: Yes, MaintenanceWindowEnd: f.at.Unix() + 600}}
	r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeRecord(r)
	c, _ := json.Marshal(f.consent)
	f.store = &memoryStore{files: map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}}
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *workflowFixture) request(t *testing.T) {
	t.Helper()
	if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e != nil {
		t.Fatal(e)
	}
}
func (f *workflowFixture) approve(t *testing.T) []byte {
	t.Helper()
	f.request(t)
	p := f.m.record.Jobs[len(f.m.record.Jobs)-1].Preview
	if p == nil {
		t.Fatal("missing preview")
	}
	if e := f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	return bytes.Clone(f.m.record.Jobs[len(f.m.record.Jobs)-1].Envelope)
}

type nativeFixture struct {
	readiness       Readiness
	opens, installs int
	err             error
	onInspect       func()
	onInstall       func()
	result          NativeResult
}

func (n *nativeFixture) PrepareExact(context.Context, Selection) (PreparedPackage, error) {
	n.opens++
	return n, nil
}
func (n *nativeFixture) Inspect(context.Context) (Readiness, error) {
	if n.onInspect != nil {
		n.onInspect()
	}
	return n.readiness, nil
}
func (n *nativeFixture) InstallOnce(context.Context) (NativeResult, error) {
	n.installs++
	if n.onInstall != nil {
		n.onInstall()
	}
	return n.result, n.err
}
func (n *nativeFixture) Close() error { return nil }
func executorFixture(t *testing.T, f *workflowFixture, n ExecutorAdapter) (*Executor, *memoryStore) {
	t.Helper()
	r, e := NewExecutorRecord(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeExecutorRecord(r)
	c, _ := json.Marshal(f.consent)
	s := &memoryStore{files: map[string][]byte{"executor.json": raw, "started.json": c, "receipt.json": c}}
	x, e := OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return x, s
}

func executorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32)) }
func reopenExecutor(t *testing.T, f *workflowFixture, s *memoryStore, n ExecutorAdapter) *Executor {
	t.Helper()
	x, e := OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func requestChallenge(t *testing.T, f *workflowFixture) []byte {
	t.Helper()
	f.m.source = nil
	f.request(t)
	raw, e := f.m.ClaimReadiness(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func testSelection() Selection {
	return Selection{SHA256: actionpermit.Digest([]byte("MSI")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Reviewed package", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "Administrator review 1"}
}
