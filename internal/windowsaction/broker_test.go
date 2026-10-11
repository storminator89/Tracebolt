package windowsaction

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type memory struct {
	files   map[string][]byte
	fail    bool
	writes  int
	onWrite func()
}

func (m *memory) Read(n string) ([]byte, error) {
	b, ok := m.files[n]
	if !ok || m.fail {
		return nil, ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (m *memory) Write(n string, b []byte) error {
	m.writes++
	if m.fail {
		return ErrIntegrity
	}
	m.files[n] = bytes.Clone(b)
	if m.onWrite != nil {
		m.onWrite()
	}
	return nil
}
func (m *memory) Verify() error {
	if m.fail {
		return ErrIntegrity
	}
	return nil
}

type fakeService struct {
	state                        uint32
	stopAccepted                 bool
	stops, starts, opens, closed int
	denied, drift, closeError    bool
	onStop, onStart              func()
	inspect                      func() error
	checkDispatch                func()
}

func (f *fakeService) Open(Target, string, string) (Service, error) {
	f.opens++
	if f.denied {
		return nil, ErrUnavailable
	}
	return f, nil
}
func (f *fakeService) Inspect() (Snapshot, error) {
	if f.drift {
		return Snapshot{}, ErrBinding
	}
	if f.inspect != nil {
		if e := f.inspect(); e != nil {
			return Snapshot{}, e
		}
	}
	pid := uint32(0)
	if f.state == 4 {
		pid = 42
	}
	return Snapshot{f.state, f.stopAccepted, pid}, nil
}
func (f *fakeService) Start() error {
	if f.checkDispatch != nil {
		f.checkDispatch()
	}
	f.starts++
	f.state = 4
	if f.onStart != nil {
		f.onStart()
	}
	return nil
}
func (f *fakeService) Stop() error {
	if f.checkDispatch != nil {
		f.checkDispatch()
	}
	f.stops++
	f.state = 1
	if f.onStop != nil {
		f.onStop()
	}
	return nil
}
func (f *fakeService) Close() error {
	f.closed++
	if f.closeError {
		return ErrUnavailable
	}
	return nil
}

type fixture struct {
	b           *Broker
	root, state *memory
	service     *fakeService
	key         ed25519.PrivateKey
	p           Policy
	now         time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	pub := key.Public().(ed25519.PublicKey)
	p := Policy{Version: PolicyVersion, Enabled: true, Binding: Binding{ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: Digest(pub), EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: Digest([]byte("incarnation")), InstallationID: "broker_" + strings.Repeat("3", 32), Target: "FixtureApplication"}, PublicKey: pub, BrokerSID: "S-1-5-80-1-2-3-4-5", AgentSID: "S-1-5-80-2-3-4-5-6", Target: Target{Name: "FixtureApplication", Executable: `C:\Program Files\Fixture\app.exe`, ExecutableDigest: Digest([]byte("file")), ConfigurationDigest: Digest([]byte("config")), Classification: "reviewed-standalone-application"}, ReviewDigest: Digest([]byte("review"))}
	p.Binding.TargetDigest = TargetDigest(p.Target)
	p.Binding.GrantDigest = GrantDigest(p)
	if e := ValidatePolicy(p); e != nil {
		t.Fatal(e)
	}
	root := &memory{files: map[string][]byte{}}
	state := &memory{files: map[string][]byte{}}
	raw, _ := json.Marshal(p)
	root.files["policy.json"] = raw
	raw, _ = json.Marshal(p.Binding)
	root.files["started.json"] = raw
	root.files["receipt.json"] = raw
	now := time.Unix(1800000000, 0).UTC()
	raw, _ = json.Marshal(ledger{Version: LedgerVersion, Binding: p.Binding, ClockFloor: now.Unix(), Jobs: []record{}})
	state.files["ledger.json"] = raw
	f := &fixture{root: root, state: state, service: &fakeService{state: 4, stopAccepted: true}, key: key, p: p, now: now}
	var e error
	f.b, e = NewBroker(root, state, f.service, func() time.Time { return f.now })
	if e != nil {
		t.Fatal(e)
	}
	f.b.wait = func(context.Context, time.Duration) error { f.now = f.now.Add(250 * time.Millisecond); return nil }
	return f
}
func (f *fixture) envelope(t *testing.T, op string) []byte {
	t.Helper()
	p := Permit{Version: Version, Binding: f.p.Binding, Operation: op, JobID: "action_" + strings.Repeat("4", 32), Sequence: 1, OperatorID: "operator_" + strings.Repeat("5", 32), ApprovalDigest: Digest([]byte("approval")), IssuedAt: f.now.Unix(), NotBefore: f.now.Unix(), Deadline: f.now.Add(time.Minute).Unix()}
	m, e := SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := Encode(p, ed25519.Sign(f.key, m))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestThreeOperationsPersistBeforeEffectAndDurableResult(t *testing.T) {
	for _, op := range []string{Start, Stop, Restart} {
		t.Run(op, func(t *testing.T) {
			f := newFixture(t)
			if op == Start {
				f.service.state = 1
			}
			raw := f.envelope(t, op)
			f.service.checkDispatch = func() {
				var l ledger
				if DecodeCanonical(f.state.files["ledger.json"], &l, 512<<10) != nil || l.Sequence != 1 || l.Jobs[0].Result.Phase != "dispatching" || !l.Jobs[0].Result.StartAttempted && !l.Jobs[0].Result.StopAttempted {
					t.Fatal("control without durable attempt")
				}
			}
			r, e := f.b.Submit(context.Background(), raw)
			if e != nil {
				t.Fatal(e, r)
			}
			want := "running-observed"
			if op == Stop {
				want = "stopped-observed"
			}
			if r.Outcome != want || r.Phase != "complete" || r.Deadline != f.now.Add(time.Minute).Unix() {
				t.Fatal(r)
			}
			if f.service.opens != 1 || f.service.closed != 1 || f.service.starts > 1 || f.service.stops > 1 {
				t.Fatal("not one held handle and one control")
			}
			if op != Stop && !r.RunningObserved || op != Start && !r.StoppedObserved {
				t.Fatal(r)
			}
			b, e := NewBroker(f.root, f.state, f.service, func() time.Time { return f.now })
			if e != nil {
				t.Fatal(e)
			}
			again, e := b.Status(r.Identity)
			if e != nil || again != r {
				t.Fatal("result lost", e)
			}
			if _, e = b.Submit(context.Background(), raw); !errors.Is(e, ErrConsumed) {
				t.Fatal("replay", e)
			}
			if f.service.opens != 1 {
				t.Fatal("reopened replay")
			}
		})
	}
}
func TestBindingsCanonicalAndNoLinuxAdmission(t *testing.T) {
	for _, field := range []string{"signature", "domain", "manager", "endpoint", "incarnation", "grant", "target", "installation", "key", "unknown", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			raw := f.envelope(t, Start)
			var env envelope
			json.Unmarshal(raw, &env)
			switch field {
			case "signature":
				env.Signature = strings.Repeat("A", 86)
			case "domain":
				env.Permit.Version = "tracebolt.execution-permit.v1"
			case "manager":
				env.Permit.Binding.ManagerID = "manager_" + strings.Repeat("9", 32)
			case "endpoint":
				env.Permit.Binding.EndpointID = "agent_" + strings.Repeat("9", 32)
			case "incarnation":
				env.Permit.Binding.IncarnationDigest = Digest([]byte("other"))
			case "grant":
				env.Permit.Binding.GrantDigest = Digest([]byte("other"))
			case "target":
				env.Permit.Binding.Target = "AnotherApplication"
			case "installation":
				env.Permit.Binding.InstallationID = "broker_" + strings.Repeat("9", 32)
			case "key":
				env.Permit.Binding.KeyID = Digest([]byte("other"))
			}
			if field != "signature" && field != "domain" {
				m, e := SigningMessage(env.Permit)
				if e == nil {
					raw, _ = Encode(env.Permit, ed25519.Sign(f.key, m))
				}
			} else {
				raw, _ = json.Marshal(env)
			}
			if field == "unknown" {
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			}
			if field == "duplicate" {
				raw = append([]byte(`{"signature":"x",`), raw[1:]...)
			}
			if _, e := f.b.Submit(context.Background(), raw); e == nil || f.service.opens != 0 {
				t.Fatal("accepted", field, e)
			}
		})
	}
}
func TestInitialPendingPausedUnknownAndStoppedRestartNeverControl(t *testing.T) {
	for _, state := range []uint32{1, 2, 3, 5, 6, 7, 999} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			f := newFixture(t)
			f.service.state = state
			r, e := f.b.Submit(context.Background(), f.envelope(t, Restart))
			if e == nil || r.StartAttempted || r.StopAttempted || f.service.starts+f.service.stops != 0 {
				t.Fatal(r, e)
			}
		})
	}
}
func TestPartialRestartDriftLateRevocationAndAccessDenied(t *testing.T) {
	for _, failure := range []string{"drift", "late", "revocation", "access", "close", "peer"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			switch failure {
			case "access":
				f.service.denied = true
			case "close":
				f.service.closeError = true
			case "drift":
				f.service.onStop = func() { f.service.drift = true }
			case "late":
				f.service.onStop = func() { f.now = f.now.Add(time.Minute) }
			case "revocation":
				f.service.onStop = func() { delete(f.root.files, "policy.json") }
			case "peer":
				ok := true
				ctx = context.WithValue(ctx, peerCheckKey{}, func() error {
					if !ok {
						return ErrBinding
					}
					return nil
				})
				f.service.onStop = func() { ok = false }
			}
			r, e := f.b.Submit(ctx, f.envelope(t, Restart))
			if e == nil {
				t.Fatal("failure accepted")
			}
			if failure == "access" {
				if r.StopAttempted || r.StartAttempted {
					t.Fatal(r)
				}
			} else {
				if !r.StopAttempted || !r.StopRequested || r.Outcome != "intervention-required" {
					t.Fatal(r)
				}
				if failure != "close" && f.service.starts != 0 {
					t.Fatal("second control after failure")
				}
			}
			if f.service.stops > 1 || f.service.starts > 1 {
				t.Fatal("control repeated")
			}
		})
	}
}
func TestMissingUsedStateCrashAndDisabledNeverInitialize(t *testing.T) {
	for _, which := range []string{"ledger", "fence", "receipt", "dispatching", "admitted", "disabled"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			switch which {
			case "ledger":
				delete(f.state.files, "ledger.json")
			case "fence":
				delete(f.root.files, "started.json")
			case "receipt":
				delete(f.root.files, "receipt.json")
			case "disabled":
				f.p.Enabled = false
				raw, _ := json.Marshal(f.p)
				f.root.files["policy.json"] = raw
			case "dispatching", "admitted":
				raw := f.envelope(t, Restart)
				id, _ := IdentityFor(raw)
				r := Result{Version: ResultVersion, Identity: id, Operation: Restart, Target: f.p.Target.Name, Deadline: f.now.Add(time.Minute).Unix(), Phase: which, Outcome: "not-requested"}
				f.b.ledger.Sequence = 1
				f.b.ledger.Jobs = []record{{raw, r}}
				if e := f.b.save(); e != nil {
					t.Fatal(e)
				}
			}
			before := f.state.writes
			b, e := NewBroker(f.root, f.state, f.service, func() time.Time { return f.now })
			if which == "ledger" || which == "fence" || which == "receipt" {
				if e == nil || f.state.writes != before {
					t.Fatal("missing used reset")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if which != "disabled" {
				r, e := b.Status(f.b.ledger.Jobs[0].Result.Identity)
				if e != nil || r.Outcome != "intervention-required" || r.Phase != "complete" {
					t.Fatal(r, e)
				}
			}
			if _, e = b.Submit(context.Background(), f.envelope(t, Restart)); e == nil {
				t.Fatal("executed reopened or disabled")
			}
			if f.service.opens != 0 {
				t.Fatal("native opened")
			}
		})
	}
}
func TestClockFloorAndOriginalDeadline(t *testing.T) {
	f := newFixture(t)
	raw := f.envelope(t, Restart)
	f.now = f.now.Add(time.Minute)
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if _, e := f.b.Capabilities(); e != nil {
		t.Fatal(e)
	}
	f.now = f.now.Add(-time.Minute)
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if f.service.opens != 0 {
		t.Fatal("revived expiry")
	}
}
func TestPipeACLAndStrictIPC(t *testing.T) {
	s, e := pipeSDDL("S-1-5-80-1-2-3-4-5", "S-1-5-80-2-3-4-5-6")
	if e != nil || !strings.Contains(s, "D:P") || strings.Contains(s, "S-1-5-19") || pipeClientAccess&4 != 0 {
		t.Fatal(s, e)
	}
	for _, sid := range []string{"S-1-5-19", "S-1-5-80-1-2-3-4-5-6", "S-1-5-80-01-2-3-4-5", "S-1-5-80-4294967296-2-3-4-5"} {
		if _, e := pipeSDDL(sid, "S-1-5-80-2-3-4-5-6"); e == nil {
			t.Fatal("account/invalid SID allowed", sid)
		}
	}
	f := newFixture(t)
	for _, raw := range []string{`{"version":"tracebolt.windows-service-action-ipc.v1","operation":"shell"}`, `{"version":"tracebolt.windows-service-action-ipc.v1","operation":"capabilities","envelope":"YQ=="}`, `{"version":"tracebolt.windows-service-action-ipc.v1","operation":"capabilities","args":[]}`} {
		if r := dispatch(context.Background(), f.b, []byte(raw)); r.Error != "invalid" {
			t.Fatal(r)
		}
	}
}
func TestStorageFailureBeforeEffectCannotControl(t *testing.T) {
	f := newFixture(t)
	f.state.fail = true
	if _, e := f.b.Submit(context.Background(), f.envelope(t, Restart)); e == nil || f.service.opens != 0 {
		t.Fatal("write failure allowed control")
	}
}

func TestSequenceGapsAndRejectedExpiryCannotRevive(t *testing.T) {
	f := newFixture(t)
	raw := f.envelope(t, Restart)
	f.now = f.now.Add(time.Minute)
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	f.now = f.now.Add(-time.Minute)
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal("rejected expiry revived without an intervening capability report", e)
	}
	f.now = f.now.Add(2 * time.Minute)
	p, _ := Decode(f.envelope(t, Restart))
	p.Sequence = 3
	m, _ := SigningMessage(p)
	raw, _ = Encode(p, ed25519.Sign(f.key, m))
	r, e := f.b.Submit(context.Background(), raw)
	if e != nil || r.Identity.Sequence != 3 {
		t.Fatal("expired undelivered earlier sequence blocked next valid job", r, e)
	}
	if _, e = NewBroker(f.root, f.state, f.service, func() time.Time { return f.now }); e != nil {
		t.Fatal("gap ledger did not reopen", e)
	}
}
func TestHeldNormalVolumeRootDoesNotConfuseAddDirectoryWithFileAppend(t *testing.T) {
	if untrustedPathWriteMask(true)&0x4 != 0 || untrustedPathWriteMask(false)&0x4 == 0 {
		t.Fatal("file/directory append semantics mixed")
	}
	for _, right := range []uint32{0x40, 0x10000, 0x40000, 0x80000, 0x2, 0x10, 0x100, 0x10000000, 0x40000000} {
		if untrustedPathWriteMask(true)&right == 0 {
			t.Fatalf("directory replacement/security/data write allowed: %#x", right)
		}
	}
}

func TestBrokerSCMDescriptorNeverGrantsObservationConfigControl(t *testing.T) {
	broker, agent := "S-1-5-80-1-2-3-4-5", "S-1-5-80-2-3-4-5-6"
	base := []serviceACE{{"S-1-5-18", serviceAllRights, 0, 0}, {"S-1-5-32-544", serviceAllRights, 0, 0}, {broker, brokerQueryRights, 0, 0}, {agent, brokerQueryRights, 0, 0}}
	if e := validateBrokerServiceACL("S-1-5-32-544", true, base, broker, agent); e != nil {
		t.Fatal(e)
	}
	for _, which := range []string{"change-config", "write-dac", "write-owner", "start", "stop", "LocalService", "owner", "inheritance", "extra"} {
		t.Run(which, func(t *testing.T) {
			entries := append([]serviceACE(nil), base...)
			owner := "S-1-5-32-544"
			switch which {
			case "change-config":
				entries[3].Mask |= 2
			case "write-dac":
				entries[3].Mask |= 0x40000
			case "write-owner":
				entries[3].Mask |= 0x80000
			case "start":
				entries[3].Mask |= 0x10
			case "stop":
				entries[3].Mask |= 0x20
			case "LocalService":
				entries[3].SID = "S-1-5-19"
			case "owner":
				owner = agent
			case "inheritance":
				entries[3].Flags = 0x10
			case "extra":
				entries = append(entries, serviceACE{"S-1-5-19", serviceAllRights, 0, 0})
			}
			if validateBrokerServiceACL(owner, true, entries, broker, agent) == nil {
				t.Fatal("broker SID escalation route admitted")
			}
		})
	}
}
func TestResponseConsumptionACKKeepsBufferedReplyAliveAndBounded(t *testing.T) {
	raw := []byte(`{"version":"tracebolt.windows-service-action-ipc.v1","error":"unavailable"}`)
	sent, read := false, false
	ack, _ := json.Marshal(consumedACK{IPCVersion, Digest(raw)})
	e := respondAwaitACK(context.Background(), raw, func(_ context.Context, b []byte) error { sent = bytes.Equal(raw, b); return nil }, func(context.Context) ([]byte, error) {
		if !sent {
			t.Fatal("read before complete response write")
		}
		read = true
		return ack, nil
	})
	if e != nil || !read {
		t.Fatal("disconnected before consumed response", e)
	}
	for _, bad := range [][]byte{[]byte(`{}`), append(bytes.Clone(ack), ' '), bytes.Replace(ack, []byte(Digest(raw)), []byte(Digest([]byte("other"))), 1)} {
		if respondAwaitACK(context.Background(), raw, func(context.Context, []byte) error { return nil }, func(context.Context) ([]byte, error) { return bad, nil }) == nil {
			t.Fatal("invalid acknowledgment accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if respondAwaitACK(ctx, raw, func(context.Context, []byte) error { calls++; return nil }, func(context.Context) ([]byte, error) { calls++; return nil, nil }) == nil || calls != 0 {
		t.Fatal("deadline ignored")
	}
}
func TestBrokerServiceNeverReportsCleanUnexpectedExit(t *testing.T) {
	for _, e := range []error{nil, ErrBinding, ErrUnavailable, context.Canceled} {
		if serviceExitCode(false, e, nil) == 0 {
			t.Fatal("unexpected runtime exit reported success", e)
		}
	}
	if serviceExitCode(true, context.Canceled, nil) != 0 || serviceExitCode(true, ErrUnavailable, nil) == 0 || serviceExitCode(true, context.Canceled, ErrIntegrity) == 0 {
		t.Fatal("stop masked runtime or closure failure")
	}
}
func TestPipeBusyRetriesOnlyBeforeConnectionWithinOriginalContext(t *testing.T) {
	busy := errors.New("pipe busy")
	calls, waits := 0, 0
	h, e := connectBeforeWrite(context.Background(), func() (uintptr, error) {
		calls++
		if calls < 3 {
			return 0, busy
		}
		return 17, nil
	}, func(e error) bool { return e == busy }, func(context.Context, time.Duration) error { waits++; return nil })
	if e != nil || h != 17 || calls != 3 || waits != 2 {
		t.Fatal(h, e, calls, waits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, e = connectBeforeWrite(ctx, func() (uintptr, error) { calls++; return 0, busy }, func(e error) bool { return e == busy }, func(context.Context, time.Duration) error { cancel(); return ctx.Err() })
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatal("prewrite cancellation retried", e, calls)
	}
	calls = 0
	_, e = connectBeforeWrite(context.Background(), func() (uintptr, error) { calls++; return 0, ErrBinding }, func(e error) bool { return e == busy }, func(context.Context, time.Duration) error { t.Fatal("non-busy error retried"); return nil })
	if e != ErrBinding || calls != 1 {
		t.Fatal(e, calls)
	}
}

func TestClockAdvancingDuringSaveCannotReviveRejectedPermit(t *testing.T) {
	f := newFixture(t)
	raw := f.envelope(t, Restart)
	original := f.now
	permit, _ := Decode(raw)
	f.state.onWrite = func() { f.now = original.Add(time.Minute); f.state.onWrite = nil }
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal("did not reject expiry crossed during save", e)
	}
	var saved ledger
	if DecodeCanonical(f.state.files["ledger.json"], &saved, 512<<10) != nil || saved.ClockFloor < permit.Deadline {
		t.Fatal("exact rejecting clock was not durable", saved.ClockFloor, permit.Deadline)
	}
	f.now = original
	if _, e := f.b.Submit(context.Background(), raw); !errors.Is(e, ErrExpired) || f.service.starts+f.service.stops != 0 {
		t.Fatal("save-time crossing revived after rollback", e)
	}
}
func TestDedicatedBrokerObjectIsolationRejectsSharedAccountAndStealingRights(t *testing.T) {
	broker, agent := "S-1-5-80-1-2-3-4-5", "S-1-5-80-2-3-4-5-6"
	for _, kind := range []string{"process", "token", "thread", "default"} {
		base := []serviceACE{{broker, 0x10000000, 0, 0}, {"S-1-5-18", 0x10000000, 0, 0}, {"S-1-5-32-544", 0x10000000, 0, 0}, {agent, 0x20000, 0, 0}}
		if e := validateKernelACL(broker, base, broker, kind, ""); e != nil {
			t.Fatal(kind, e)
		}
		if validateKernelACL("S-1-5-19", base, broker, kind, "") == nil {
			t.Fatal("shared account owner admitted", kind)
		}
		for _, mask := range []uint32{0x10000000, 0x40000, 0x80000, 0x2, 0x20, 0x80, 0x4} {
			bad := append([]serviceACE(nil), base...)
			bad[3].Mask |= mask
			if validateKernelACL(broker, bad, broker, kind, "") == nil {
				t.Fatalf("%s dangerous untrusted mask %#x", kind, mask)
			}
		}
		bad := append([]serviceACE(nil), base...)
		bad[3].Kind = 5
		if validateKernelACL(broker, bad, broker, kind, "") == nil {
			t.Fatal("unknown ACE admitted")
		}
	}
}

func TestRestrictedBrokerLogonSIDIsExactAndTokenOnly(t *testing.T) {
	broker := "S-1-5-80-1-2-3-4-5"
	logon := "S-1-5-5-7-91"
	groups := []tokenGroup{{broker, 0xe}, {logon, 0xc0000007}}
	if got, e := brokerLogonSID(broker, broker, groups); e != nil || got != logon {
		t.Fatal(got, e)
	}
	for _, user := range []string{"S-1-5-19", "S-1-5-20", "S-1-5-80-9-8-7-6-5"} {
		if _, e := brokerLogonSID(user, broker, groups); e == nil {
			t.Fatal("unbound token user admitted")
		}
	}
	for _, bad := range [][]tokenGroup{{{logon, 0xc0000017}}, {{logon, 0xc0000003}}, {{"S-1-5-6", 0xc0000007}}, {{"S-1-5-5-07-91", 0xc0000007}}, {{logon, 0xc0000007}, {"S-1-5-5-8-92", 0xc0000007}}} {
		if _, e := brokerLogonSID(broker, broker, bad); e == nil {
			t.Fatal("invalid logon identity admitted", bad)
		}
	}
	entries := []serviceACE{{broker, 0x10000000, 0, 0}, {"S-1-5-18", 0x10000000, 0, 0}, {logon, 0x10000000, 0, 0}}
	if e := validateKernelACL(broker, entries, broker, "token", logon); e != nil {
		t.Fatal("documented restricted-token ACE rejected", e)
	}
	for _, kind := range []string{"process", "thread", "default"} {
		if validateKernelACL(broker, entries, broker, kind, logon) == nil {
			t.Fatal("token exception escaped", kind)
		}
	}
	for _, other := range []string{"", "S-1-5-5-8-92", "S-1-5-19", "S-1-5-6"} {
		if validateKernelACL(broker, entries, broker, "token", other) == nil {
			t.Fatal("unbound logon ACE admitted")
		}
	}
	if validateKernelACL(logon, entries, broker, "token", logon) == nil {
		t.Fatal("logon SID became owner authority")
	}
}
