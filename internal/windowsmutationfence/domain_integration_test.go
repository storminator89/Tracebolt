package windowsmutationfence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	wua "localrmm/internal/windowsupdatejob"
)

// All adapters below are inert. These tests exercise real public domain kernels,
// their signing/claim/result ledgers, and one shared in-memory fence only.
type domainStore struct {
	mu     sync.Mutex
	files  map[string][]byte
	before func(string, []byte) error
}

func (s *domainStore) Read(n string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[n]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(v), nil
}
func (s *domainStore) Write(n string, b []byte) error {
	if s.before != nil {
		if e := s.before(n, bytes.Clone(b)); e != nil {
			return e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[n] = bytes.Clone(b)
	return nil
}
func (s *domainStore) Verify() error                { return nil }
func digest(s string) string                        { return actionpermit.Digest([]byte(s)) }
func objectDigest(v any) string                     { b, _ := json.Marshal(v); return actionpermit.Digest(b) }
func id(prefix string, n int) string                { return fmt.Sprintf("%s%032x", prefix, n) }
func key(n byte) ed25519.PrivateKey                 { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func public(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

type memoryPayload struct{ data []byte }

func (p *memoryPayload) Create(context.Context, msi.Selection) (json.RawMessage, error) {
	if p.data != nil {
		return nil, msi.ErrConflict
	}
	p.data = []byte{}
	return json.RawMessage(`{"object":1}`), nil
}
func (p *memoryPayload) Open(context.Context, json.RawMessage, int64, string, *msi.ChunkIntent) error {
	return nil
}
func (p *memoryPayload) Append(_ context.Context, offset int64, b []byte) (string, error) {
	if offset != int64(len(p.data)) {
		return "", msi.ErrConflict
	}
	p.data = append(p.data, b...)
	return actionpermit.Digest(p.data), nil
}
func (p *memoryPayload) Complete(_ context.Context, s msi.Selection) (json.RawMessage, error) {
	if int64(len(p.data)) != s.Size || actionpermit.Digest(p.data) != s.SHA256 {
		return nil, msi.ErrIntegrity
	}
	return json.RawMessage(`{"object":1,"verified":true}`), nil
}
func (*memoryPayload) Close() error { return nil }

type inertMSI struct {
	now           func() time.Time
	calls         atomic.Int64
	entered       chan struct{}
	release       <-chan struct{}
	beforeStart   func()
	skipFinalGate bool
	nativeError   error
}

func (i *inertMSI) Inspect(_ context.Context, _ json.RawMessage, s msi.Selection, until int64) (msi.Readiness, error) {
	return msi.Readiness{Selection: s, CapturedAt: i.now().Unix(), PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: until}, nil
}
func (i *inertMSI) Install(ctx context.Context, _ json.RawMessage, _ msi.Readiness) (msi.NativeResult, error) {
	if e := msi.CheckInstallStart(ctx, i.now()); e != nil {
		return msi.NativeResult{RegistrationVerified: msi.Unknown}, e
	}
	if i.beforeStart != nil {
		i.beforeStart()
	}
	if !i.skipFinalGate {
		if e := msi.CheckNativeInstallStart(ctx, i.now()); e != nil {
			return msi.NativeResult{RegistrationVerified: msi.Unknown}, e
		}
	}
	i.calls.Add(1)
	if i.entered != nil {
		close(i.entered)
	}
	if i.release != nil {
		<-i.release
	}
	return msi.NativeResult{ReturnCodeKnown: true, ReturnCode: 0, RegistrationVerified: msi.Yes}, i.nativeError
}

type inertWUA struct {
	now           func() time.Time
	readiness     wua.Readiness
	prepares      atomic.Int64
	calls         atomic.Int64
	entered       chan struct{}
	release       <-chan struct{}
	beforeStart   func()
	skipFinalGate bool
	closeError    error
}

func (i *inertWUA) PrepareExact(_ context.Context, s wua.Selection) (wua.PreparedUpdate, error) {
	if s != i.readiness.Selection {
		return nil, wua.ErrInvalid
	}
	i.prepares.Add(1)
	return i, nil
}
func (i *inertWUA) Inspect(context.Context) (wua.Readiness, error) {
	r := i.readiness
	r.CapturedAt = i.now().Unix()
	return r, nil
}
func (i *inertWUA) InstallOnce(ctx context.Context) (wua.NativeResult, error) {
	if e := wua.CheckInstallStart(ctx, i.now()); e != nil {
		return wua.NativeResult{RebootRequired: wua.Unknown}, e
	}
	if i.beforeStart != nil {
		i.beforeStart()
	}
	if !i.skipFinalGate {
		if e := wua.CheckNativeInstallStart(ctx, i.now()); e != nil {
			return wua.NativeResult{RebootRequired: wua.Unknown}, e
		}
	}
	i.calls.Add(1)
	if i.entered != nil {
		close(i.entered)
	}
	if i.release != nil {
		<-i.release
	}
	return wua.NativeResult{OperationResult: 2, RebootRequired: wua.No}, nil
}
func (i *inertWUA) Close() error { return i.closeError }

type currentWUA struct{ value wua.Current }

func (a *currentWUA) WithCurrent(ctx context.Context, b wua.Binding, fn func(wua.Current) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if b != a.value.Binding {
		return wua.ErrAuthority
	}
	return fn(a.value)
}

type readySource struct{ value wua.Readiness }

func (a readySource) Readiness(context.Context, wua.Binding, wua.Selection) (wua.Readiness, error) {
	return a.value, nil
}

type pairedDomains struct {
	at                                             atomic.Int64
	shared                                         *fence.IntegrationFence
	msiSession, wuaSession                         *fence.Session
	msiKey, msiExecutorKey, wuaKey, wuaExecutorKey ed25519.PrivateKey
	grant                                          msi.Grant
	consent                                        wua.Consent
	msiStore, wuaStore                             *domainStore
	payload                                        *memoryPayload
	msiNative                                      *inertMSI
	wuaNative                                      *inertWUA
	msiCurrent                                     msi.Current
	wuaAuthority                                   *currentWUA
	endpoint                                       *msi.Endpoint
	executor                                       *wua.Executor
	msiPermit, wuaPermit                           []byte
}

func (f *pairedDomains) now() time.Time { return time.Unix(f.at.Load(), 0) }
func newPair(t *testing.T) *pairedDomains {
	t.Helper()
	f := &pairedDomains{msiKey: key(1), msiExecutorKey: key(2), wuaKey: key(3), wuaExecutorKey: key(4)}
	f.at.Store(1800000000)
	identity := fence.Identity{ManagerID: id("manager_", 1), DeviceID: id("agent_", 2), IncarnationDigest: digest("original anchor")}
	mb := msi.Binding{ManagerID: identity.ManagerID, DeviceID: identity.DeviceID, IncarnationDigest: identity.IncarnationDigest, ExecutorID: id("executor_", 3), ExecutorKeyID: actionpermit.Digest(public(f.msiExecutorKey)), KeyID: actionpermit.Digest(public(f.msiKey)), DeliveryGrantID: id("grant_", 4), InstallGrantID: id("grant_", 5)}
	wb := wua.Binding{ManagerID: identity.ManagerID, DeviceID: identity.DeviceID, IncarnationDigest: identity.IncarnationDigest, ExecutorID: id("executor_", 6), ExecutorKeyID: actionpermit.Digest(public(f.wuaExecutorKey)), KeyID: actionpermit.Digest(public(f.wuaKey)), GrantID: id("grant_", 7)}
	plan := fence.Plan{Identity: identity, PlanDigest: digest("exact combined plan"), MSIOfferDigest: digest("msi offer"), WUAOfferDigest: digest("wua offer"), MSIArtifactDigest: digest("msi image"), WUAArtifactDigest: digest("wua image")}
	f.grant = msi.Grant{Version: msi.CoordinatedGrantVersion, MutationPlanDigest: plan.PlanDigest, PeerBindingDigest: objectDigest(wb), Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: f.at.Load() + 3600}
	f.consent = wua.Consent{Version: wua.CoordinatedConsentVersion, MutationPlanDigest: plan.PlanDigest, PeerBindingDigest: objectDigest(mb), Scope: wua.Scope, Binding: wb, Enabled: true, Acknowledged: true, ExpiresAt: f.at.Load() + 3600}
	f.shared = fence.NewIntegrationFence(t, plan, msi.MutationParticipant(f.grant), wua.MutationParticipant(f.consent), f.now)
	f.msiSession = f.shared.Session(t, fence.ManagedMSI)
	f.wuaSession = f.shared.Session(t, fence.CachedWUA)
	mr, e := msi.NewCoordinatedEndpointRecord(f.grant, public(f.msiKey), public(f.msiExecutorKey), f.at.Load(), f.shared.Roster)
	if e != nil {
		t.Fatal(e)
	}
	mbRaw, _ := json.Marshal(mr)
	wr, e := wua.NewCoordinatedExecutorRecord(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.at.Load(), f.shared.Roster)
	if e != nil {
		t.Fatal(e)
	}
	wbRaw, e := wua.EncodeExecutorRecord(wr)
	if e != nil {
		t.Fatal(e)
	}
	consentRaw, _ := json.Marshal(f.consent)
	f.msiStore = &domainStore{files: map[string][]byte{"endpoint.json": mbRaw}}
	f.wuaStore = &domainStore{files: map[string][]byte{"executor.json": wbRaw, "started.json": consentRaw, "receipt.json": consentRaw}}
	f.payload = &memoryPayload{}
	f.msiNative = &inertMSI{now: f.now}
	readiness := wua.Readiness{Selection: wua.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}, CapturedAt: f.at.Load(), Software: wua.Yes, Installed: wua.No, Hidden: wua.No, Downloaded: wua.Yes, EULAAccepted: wua.Yes, CanRequestUserInput: wua.No, CanRequireSource: wua.No, RequiresNetwork: wua.No, BundledCount: 0, InstallerBusy: wua.No, RebootRequiredBefore: wua.No, RebootBehavior: "can", OfflineVerified: wua.Yes}
	f.wuaNative = &inertWUA{now: f.now, readiness: readiness}
	f.msiCurrent = msi.Current{Binding: mb, LeafDigest: digest("current leaf"), LeafGeneration: 1, LeafNotBefore: f.at.Load() - 1, LeafNotAfter: f.at.Load() + 7200, Enabled: true}
	f.wuaAuthority = &currentWUA{value: wua.Current{Binding: wb, LeafDigest: digest("current leaf"), LeafGeneration: 1, LeafNotBefore: f.at.Load() - 1, LeafNotAfter: f.at.Load() + 7200, Enabled: true}}
	f.openMSI(t)
	f.openWUA(t)
	f.prepareMSI(t)
	f.prepareWUA(t)
	return f
}
func (f *pairedDomains) openMSI(t *testing.T) {
	t.Helper()
	var e error
	f.endpoint, e = msi.OpenCoordinatedEndpoint(f.msiStore, f.payload, f.msiNative, func(context.Context, msi.Binding) (msi.Current, error) { return f.msiCurrent, nil }, f.msiExecutorKey, f.now, f.msiSession)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *pairedDomains) openWUA(t *testing.T) {
	t.Helper()
	var e error
	f.executor, e = wua.OpenCoordinatedExecutor(f.wuaStore, f.wuaAuthority, f.wuaNative, f.wuaExecutorKey, f.now, f.wuaSession)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *pairedDomains) prepareMSI(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	data := bytes.Repeat([]byte{7}, 512)
	copy(data, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	sel := msi.Selection{SHA256: actionpermit.Digest(data), Size: int64(len(data)), ProductCode: "{11111111-1111-1111-1111-111111111111}", PackageCode: "{22222222-2222-2222-2222-222222222222}", Version: "1.2.3", Architecture: "amd64", Name: "Inert fixture MSI", TermsReviewDigest: digest("reviewed terms fixture"), ReviewReference: "inert only"}
	p := msi.Permit{Version: msi.Version, Kind: "deliver", TransferID: id("transfer_", 9), Binding: f.grant.Binding, LeafDigest: f.msiCurrent.LeafDigest, Package: sel, NativeAcceptanceDigest: digest("inert acceptance fixture"), ActorID: id("operator_", 10), IssuedAt: f.at.Load(), ExpiresAt: f.at.Load() + 600}
	raw, e := msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Chunk(ctx, msi.Chunk{TransferID: p.TransferID, Index: 0, PermitDigest: actionpermit.Digest(raw), Digest: actionpermit.Digest(data), Data: data}); e != nil {
		t.Fatal(e)
	}
	p.Kind = "readiness"
	p.Sequence = 1
	p.ExpiresAt = f.at.Load() + 60
	p.MaintenanceUntil = f.at.Load() + 600
	p.PackageReviewAccepted = true
	p.TermsAccepted = true
	p.SynchronousReviewDigest = msi.SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest)
	raw, e = msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e != nil {
		t.Fatal(e)
	}
	st, e := f.endpoint.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p.Kind = "install"
	p.ReadinessDigest = actionpermit.Digest(st.Report)
	f.msiPermit, e = msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *pairedDomains) prepareWUA(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	r, e := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.at.Load())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wua.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	consentRaw, _ := json.Marshal(f.consent)
	store := &domainStore{files: map[string][]byte{"jobs.json": raw, "started.json": consentRaw, "receipt.json": consentRaw}}
	manager, e := wua.Open(store, f.wuaAuthority, readySource{f.wuaNative.readiness}, f.wuaKey, f.now)
	if e != nil {
		t.Fatal(e)
	}
	actor, job := id("operator_", 10), id("update_", 11)
	device := f.consent.Binding.DeviceID
	if e = manager.Request(ctx, device, actor, job, f.wuaNative.readiness.Selection); e != nil {
		t.Fatal(e)
	}
	view, e := manager.View(ctx, device, actor)
	if e != nil || view.Job == nil || view.Job.Preview == nil {
		t.Fatal("no real signed preview", e)
	}
	// Relay an executor-signed snapshot of the real shared test fence, bound to
	// this manager's exact durable readiness challenge. Coordinated approval
	// must pass the same fresh active-idle gate as production.
	raw, e = store.Read("jobs.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e = wua.DecodeRecord(raw)
	if e != nil || len(r.Jobs) != 1 {
		t.Fatal("missing exact readiness challenge", e)
	}
	challengeRaw := r.Jobs[0].Challenge
	challenge, e := wua.VerifyChallenge(challengeRaw, public(f.wuaKey))
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := f.wuaSession.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := wua.SignStatement(wua.Statement{Version: wua.RelayVersion, Kind: "mutation", Binding: f.consent.Binding, JobID: job, ReferenceDigest: actionpermit.Digest(challengeRaw), Deadline: challenge.Deadline, IssuedAt: f.at.Load(), ExpiresAt: f.at.Load() + 60, Mutation: &snapshot}, f.wuaExecutorKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.Report(ctx, signed); e != nil {
		t.Fatal(e)
	}
	if e = manager.Approve(ctx, device, actor, job, view.Job.Preview.Digest, true); e != nil {
		t.Fatal(e)
	}
	f.wuaPermit, e = manager.Claim(ctx, job)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *pairedDomains) fenceStatus(t *testing.T) fence.Status {
	t.Helper()
	s, e := f.msiSession.Status(context.Background())
	if e != nil || s.Validate() != nil {
		t.Fatal(s, e)
	}
	return s
}
func readMSI(t *testing.T, s *domainStore) msi.EndpointRecord {
	t.Helper()
	raw, e := s.Read("endpoint.json")
	var r msi.EndpointRecord
	if e != nil || json.Unmarshal(raw, &r) != nil || r.Validate() != nil {
		t.Fatal("invalid MSI durable record", e)
	}
	return r
}
func readWUA(t *testing.T, s *domainStore) wua.ExecutorRecord {
	t.Helper()
	raw, e := s.Read("executor.json")
	var r wua.ExecutorRecord
	if e != nil || json.Unmarshal(raw, &r) != nil || r.Validate() != nil {
		t.Fatal("invalid WUA durable record", e)
	}
	return r
}
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("inert native callback not reached")
	}
}

func TestActualKernelsExcludeBothDirections(t *testing.T) {
	for _, first := range []string{fence.ManagedMSI, fence.CachedWUA} {
		t.Run(first, func(t *testing.T) {
			f := newPair(t)
			ctx := context.Background()
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			if first == fence.ManagedMSI {
				f.msiNative.entered = entered
				f.msiNative.release = release
				if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
					t.Fatal(e)
				}
				await(t, entered)
				r, e := f.executor.Execute(ctx, f.wuaPermit)
				if e != nil || r.Outcome != "not_attempted" || r.Attempted || f.wuaNative.prepares.Load() != 0 {
					close(release)
					t.Fatal("WUA crossed MSI owner", r, e)
				}
				st := f.fenceStatus(t)
				if !st.Blocked || st.Domain != first {
					close(release)
					t.Fatal(st)
				}
				close(release)
				f.endpoint.Wait()
				r2 := readMSI(t, f.msiStore)
				if r2.MutationCompletion == nil {
					t.Fatal("MSI completion missing")
				}
			} else {
				f.wuaNative.entered = entered
				f.wuaNative.release = release
				go func() { _, e := f.executor.Execute(ctx, f.wuaPermit); done <- e }()
				await(t, entered)
				if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
					close(release)
					t.Fatal(e)
				}
				f.endpoint.Wait()
				r := readMSI(t, f.msiStore)
				report, e := msi.VerifyReport(r.ResultReport, public(f.msiExecutorKey))
				if e != nil || report.State != "not_attempted" || r.Attempted || f.msiNative.calls.Load() != 0 {
					close(release)
					t.Fatal("MSI crossed WUA owner", e)
				}
				st := f.fenceStatus(t)
				if !st.Blocked || st.Domain != first {
					close(release)
					t.Fatal(st)
				}
				close(release)
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				r2 := readWUA(t, f.wuaStore)
				if r2.Attempts[0].MutationCompletion == nil {
					t.Fatal("WUA completion missing")
				}
			}
			st := f.fenceStatus(t)
			if st.Blocked || st.Retained != 1 {
				t.Fatal("completed owner not released", st)
			}
			if f.msiNative.calls.Load()+f.wuaNative.calls.Load() != 1 {
				t.Fatal("native dispatch overlapped")
			}
		})
	}
}

func TestActualDomainCompletionIsDurableBeforeSharedRelease(t *testing.T) {
	for _, domain := range []string{fence.ManagedMSI, fence.CachedWUA} {
		t.Run(domain, func(t *testing.T) {
			f := newPair(t)
			observed := atomic.Bool{}
			check := func(name string, raw []byte) error {
				terminal := false
				if domain == fence.ManagedMSI {
					var r msi.EndpointRecord
					if name == "endpoint.json" && json.Unmarshal(raw, &r) == nil {
						terminal = r.MutationCompletion != nil
					}
				} else {
					var r wua.ExecutorRecord
					if name == "executor.json" && json.Unmarshal(raw, &r) == nil && len(r.Attempts) > 0 {
						terminal = r.Attempts[0].MutationCompletion != nil
					}
				}
				if terminal {
					st, e := f.msiSession.Status(context.Background())
					if e != nil || !st.Blocked || st.Domain != domain || st.Phase != "dispatch_intent" {
						return errors.New("shared owner released before domain completion write")
					}
					observed.Store(true)
				}
				return nil
			}
			if domain == fence.ManagedMSI {
				f.msiStore.before = check
				if e := f.endpoint.Accept(context.Background(), f.msiPermit); e != nil {
					t.Fatal(e)
				}
				f.endpoint.Wait()
			} else {
				f.wuaStore.before = check
				if _, e := f.executor.Execute(context.Background(), f.wuaPermit); e != nil {
					t.Fatal(e)
				}
			}
			if !observed.Load() {
				t.Fatal("no durable result+receipt boundary observed")
			}
			if st := f.fenceStatus(t); st.Blocked {
				t.Fatal(st)
			}
		})
	}
}

func TestActualKernelsRecoverOnlySavedLostRelease(t *testing.T) {
	for _, domain := range []string{fence.ManagedMSI, fence.CachedWUA} {
		t.Run(domain, func(t *testing.T) {
			f := newPair(t)
			injected := false
			before := func(name string, raw []byte) error {
				hasReceipt := false
				if domain == fence.ManagedMSI {
					var r msi.EndpointRecord
					if name == "endpoint.json" && json.Unmarshal(raw, &r) == nil {
						hasReceipt = r.MutationCompletion != nil
					}
				} else {
					var r wua.ExecutorRecord
					if name == "executor.json" && json.Unmarshal(raw, &r) == nil && len(r.Attempts) > 0 {
						hasReceipt = r.Attempts[0].MutationCompletion != nil
					}
				}
				if hasReceipt && !injected {
					injected = true
					f.shared.FailNextRelease()
				}
				return nil
			}
			if domain == fence.ManagedMSI {
				f.msiStore.before = before
				if e := f.endpoint.Accept(context.Background(), f.msiPermit); e != nil {
					t.Fatal(e)
				}
				f.endpoint.Wait()
			} else {
				f.wuaStore.before = before
				if _, e := f.executor.Execute(context.Background(), f.wuaPermit); e != nil {
					t.Fatal(e)
				}
			}
			st := f.fenceStatus(t)
			if !injected || !st.Blocked || st.Phase != "completion_recorded" {
				t.Fatal("release fault not retained", st)
			}
			if domain == fence.ManagedMSI {
				f.endpoint.Close()
				f.msiSession = f.shared.Session(t, fence.ManagedMSI)
				f.openMSI(t)
				if e := f.endpoint.Accept(context.Background(), f.msiPermit); !errors.Is(e, msi.ErrConsumed) {
					t.Fatal("MSI recovery replayed", e)
				}
			} else {
				f.executor.Close()
				f.wuaSession = f.shared.Session(t, fence.CachedWUA)
				f.openWUA(t)
				if _, e := f.executor.Execute(context.Background(), f.wuaPermit); !errors.Is(e, wua.ErrConsumed) {
					t.Fatal("WUA recovery replayed", e)
				}
			}
			if st = f.fenceStatus(t); st.Blocked {
				t.Fatal("exact saved completion did not release", st)
			}
			if f.msiNative.calls.Load()+f.wuaNative.calls.Load() != 1 {
				t.Fatal("recovery dispatched native work")
			}
		})
	}
}

func TestActualNoStartAndCleanupUncertaintyRemainFenced(t *testing.T) {
	for _, scenario := range []string{"msi-expired", "wua-expired", "msi-cleanup", "wua-cleanup", "msi-result-write", "wua-result-write"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPair(t)
			ctx := context.Background()
			isMSI := strings.HasPrefix(scenario, "msi-")
			if strings.HasSuffix(scenario, "expired") {
				if isMSI {
					f.msiNative.beforeStart = func() { f.at.Add(60) }
				} else {
					f.wuaNative.beforeStart = func() { f.at.Add(60) }
				}
			}
			if strings.HasSuffix(scenario, "cleanup") {
				if isMSI {
					f.msiNative.nativeError = errors.New("inert custody cleanup uncertainty")
				} else {
					f.wuaNative.closeError = errors.New("inert COM cleanup uncertainty")
				}
			}
			if strings.HasSuffix(scenario, "result-write") {
				reject := func(name string, raw []byte) error {
					if isMSI {
						var r msi.EndpointRecord
						if name == "endpoint.json" && json.Unmarshal(raw, &r) == nil && r.MutationCompletion != nil {
							return errors.New("domain result write failed")
						}
					} else {
						var r wua.ExecutorRecord
						if name == "executor.json" && json.Unmarshal(raw, &r) == nil && len(r.Attempts) > 0 && r.Attempts[0].MutationCompletion != nil {
							return errors.New("domain result write failed")
						}
					}
					return nil
				}
				if isMSI {
					f.msiStore.before = reject
				} else {
					f.wuaStore.before = reject
				}
			}
			if isMSI {
				if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
					t.Fatal(e)
				}
				f.endpoint.Wait()
			} else {
				_, e := f.executor.Execute(ctx, f.wuaPermit)
				if strings.HasSuffix(scenario, "result-write") {
					if e == nil {
						t.Fatal("lost write reported success")
					}
				} else if e != nil {
					t.Fatal(e)
				}
			}
			st := f.fenceStatus(t)
			if !st.Blocked || st.Phase != "dispatch_intent" {
				t.Fatal("uncertainty auto-released", st)
			}
			calls := f.msiNative.calls.Load() + f.wuaNative.calls.Load()
			if strings.HasSuffix(scenario, "expired") {
				if calls != 0 {
					t.Fatal("expired native start")
				}
			} else if calls != 1 {
				t.Fatal("expected exactly one inert call", calls)
			}
			if isMSI {
				r := readMSI(t, f.msiStore)
				if r.MutationCompletion != nil {
					t.Fatal("uncertain MSI generated saved release proof")
				}
			} else {
				r := readWUA(t, f.wuaStore)
				if r.Attempts[0].MutationCompletion != nil {
					t.Fatal("uncertain WUA generated saved release proof")
				}
			}
		})
	}
}

func TestPublicCoordinatedConstructorsRejectWrongSession(t *testing.T) {
	f := newPair(t)
	if _, e := msi.OpenCoordinatedEndpoint(f.msiStore, f.payload, f.msiNative, func(context.Context, msi.Binding) (msi.Current, error) { return f.msiCurrent, nil }, f.msiExecutorKey, f.now, f.wuaSession); e == nil {
		t.Fatal("MSI accepted WUA session")
	}
	if _, e := wua.OpenCoordinatedExecutor(f.wuaStore, f.wuaAuthority, f.wuaNative, f.wuaExecutorKey, f.now, f.msiSession); e == nil {
		t.Fatal("WUA accepted MSI session")
	}
	if _, e := msi.OpenEndpoint(f.msiStore, f.payload, f.msiNative, func(context.Context, msi.Binding) (msi.Current, error) { return f.msiCurrent, nil }, f.msiExecutorKey, f.now); e == nil {
		t.Fatal("coordinated MSI bypassed fence through standalone open")
	}
	if _, e := wua.OpenExecutor(f.wuaStore, f.wuaAuthority, f.wuaNative, f.wuaExecutorKey, f.now); e == nil {
		t.Fatal("coordinated WUA bypassed fence through standalone open")
	}
}

func TestNominalAdapterSuccessWithoutFinalGateCannotRelease(t *testing.T) {
	for _, domain := range []string{fence.ManagedMSI, fence.CachedWUA} {
		t.Run(domain, func(t *testing.T) {
			f := newPair(t)
			if domain == fence.ManagedMSI {
				f.msiNative.skipFinalGate = true
				if e := f.endpoint.Accept(context.Background(), f.msiPermit); e != nil {
					t.Fatal(e)
				}
				f.endpoint.Wait()
				r := readMSI(t, f.msiStore)
				if r.MutationCompletion != nil {
					t.Fatal("adapter bypass minted MSI release receipt")
				}
			} else {
				f.wuaNative.skipFinalGate = true
				if _, e := f.executor.Execute(context.Background(), f.wuaPermit); e == nil {
					t.Fatal("adapter bypass reported WUA success")
				}
				before, _ := f.wuaStore.Read("executor.json")
				f.at.Add(1) // A status clock-floor write must not persist a rejected result.
				status, statusErr := f.executor.Status(context.Background())
				if statusErr == nil && len(status.Attempts) > 0 && status.Attempts[0].Result != nil && status.Attempts[0].Result.Outcome == "succeeded" {
					t.Fatal("adapter bypass surfaced uncommitted WUA success through later status")
				}
				after, _ := f.wuaStore.Read("executor.json")
				if !bytes.Equal(before, after) {
					t.Fatal("status persisted a WUA result rejected by the final gate")
				}
				r := readWUA(t, f.wuaStore)
				if r.Attempts[0].MutationCompletion != nil {
					t.Fatal("adapter bypass minted WUA release receipt")
				}
			}
			st := f.fenceStatus(t)
			if !st.Blocked || st.Domain != domain || st.Phase != "dispatch_intent" {
				t.Fatal("adapter bypass released shared owner", st)
			}
		})
	}
}
