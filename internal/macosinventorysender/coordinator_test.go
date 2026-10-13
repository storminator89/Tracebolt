package macosinventorysender

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	inventory "localrmm/internal/macosinventory"
	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
)

type memoryDisk struct {
	mu    sync.Mutex
	raw   []byte
	used  bool
	fail  bool
	after bool
}

func (d *memoryDisk) CreateFresh(raw []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.used {
		return errors.New("used")
	}
	d.used = true
	d.raw = bytes.Clone(raw)
	return nil
}
func (d *memoryDisk) Commit(expected, next []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.used || !bytes.Equal(expected, d.raw) {
		return errors.New("mismatch")
	}
	if !d.fail || d.after {
		d.raw = bytes.Clone(next)
	}
	if d.fail {
		return errors.New("private provider text")
	}
	return nil
}
func (d *memoryDisk) read() []byte { d.mu.Lock(); defer d.mu.Unlock(); return bytes.Clone(d.raw) }

type testAuthority struct {
	evidence Evidence
	clock    *testClock
	check    func()
	exchange func(context.Context, string, []byte) ([]byte, error)
	paths    []string
	bodies   [][]byte
	calls    int
	reject   bool
}

func (a *testAuthority) WithCurrent(ctx context.Context, fn func(ActiveAuthority) error) error {
	if a.reject {
		return errors.New("private local approval data")
	}
	return fn(a)
}
func (a *testAuthority) Check(time.Time) (Evidence, error) {
	a.calls++
	if a.check != nil {
		a.check()
	}
	return a.evidence, nil
}
func (a *testAuthority) Exchange(ctx context.Context, path string, raw []byte) ([]byte, error) {
	a.paths = append(a.paths, path)
	a.bodies = append(a.bodies, bytes.Clone(raw))
	if a.exchange != nil {
		return a.exchange(ctx, path, raw)
	}
	return receiptFor(raw, a.clock.now())
}
func receiptFor(raw []byte, now time.Time) ([]byte, error) {
	r, e := wire.ReceiptFor(raw, now)
	if e != nil {
		return nil, e
	}
	return wire.EncodeReceipt(r, raw)
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	c         *Coordinator
	a         *testAuthority
	d         *memoryDisk
	s         *state.State
	clock     *testClock
	original  []byte
	enable    wire.Control
	captures  int
	releases  int
	request   inventory.Request
	successor []byte
}

func fixtureSender(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{d: &memoryDisk{}, clock: &testClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}}
	now := f.clock.now()
	device := "agent_" + strings.Repeat("a", 32)
	issuerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic dedicated issuer"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte{1, 2, 3, 4}}
	issuerDER, e := x509.CreateCertificate(nil, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := x509.ParseCertificate(issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	leaf := func(serial int64, until time.Time) []byte {
		v := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: device}, NotBefore: now.Add(-time.Hour), NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		raw, e := x509.CreateCertificate(nil, v, issuer, clientKey.Public(), issuerKey)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	anchorDER := leaf(2, now.Add(2*time.Hour))
	f.successor = leaf(3, now.Add(48*time.Hour))
	anchor, _ := x509.ParseCertificate(anchorDER)
	binding, e := OriginalBinding("https://manager.example:8443", device, anchor)
	if e != nil {
		t.Fatal(e)
	}
	f.enable = wire.Control{SchemaVersion: wire.ControlVersion, Binding: binding, GrantID: strings.Repeat("b", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: now}
	f.original, e = wire.EncodeControl(f.enable)
	if e != nil {
		t.Fatal(e)
	}
	f.s, e = state.InitializeFresh(f.d, f.original, now)
	if e != nil {
		t.Fatal(e)
	}
	consent, e := inventory.EncodeConsent(inventory.Consent{SchemaVersion: inventory.ConsentVersion, Scope: inventory.Scope, SenderBinding: binding.SenderBinding, GrantID: f.enable.GrantID, Enabled: true}, binding.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	f.a = &testAuthority{clock: f.clock, evidence: Evidence{ManagerOrigin: "https://manager.example:8443", OriginalEnable: bytes.Clone(f.original), Consent: consent, AnchorDER: anchorDER, CurrentDER: anchorDER, IssuerDER: issuerDER, CredentialGeneration: 1}}
	f.c, e = newCoordinator(f.s, f.original, f.a, func() error { f.releases++; return nil }, f.clock.now, func(ctx context.Context, r inventory.Request) (inventory.Snapshot, error) {
		f.captures++
		f.request = r
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.c.Close() })
	return f
}

func TestEnableThenExactReservedCollection(t *testing.T) {
	f := fixtureSender(t)
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path == ControlPath && f.captures != 0 {
			t.Fatal("collected before enable receipt")
		}
		if path == ReportPath {
			status, e := f.s.Inspect(f.clock.now())
			if e != nil || status.AttemptStatus != "pending" {
				t.Fatal("sent before durable stage", status, e)
			}
		}
		return receiptFor(raw, f.clock.now())
	}
	if e := f.c.Cycle(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.captures != 1 || len(f.a.paths) != 2 || f.a.paths[0] != ControlPath || f.a.paths[1] != ReportPath {
		t.Fatal("wrong work order")
	}
	report, e := wire.DecodeReport(f.a.bodies[1])
	if e != nil {
		t.Fatal(e)
	}
	if report.CaptureSequence != 1 || report.GenerationID != f.request.GenerationID || !report.CollectedAt.Equal(f.request.CollectedAt) || report.Snapshot.GrantID != f.request.Consent.GrantID {
		t.Fatal("lost lease binding")
	}
	if e = f.c.Cycle(context.Background()); !errors.Is(e, state.ErrPacing) {
		t.Fatal(e)
	}
	f.clock.add(time.Minute)
	if e = f.c.Cycle(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.captures != 2 {
		t.Fatal("capture count")
	}
}
func TestEnableFailureHasNoCapture(t *testing.T) {
	f := fixtureSender(t)
	f.a.exchange = func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("secret network detail") }
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	if f.captures != 0 {
		t.Fatal("captured")
	}
	status, _ := f.s.Inspect(f.clock.now())
	if status.Floor != 0 || status.EnableAcknowledged {
		t.Fatal(status)
	}
}
func TestCollectionFailureConsumedAndPaced(t *testing.T) {
	f := fixtureSender(t)
	f.c.collect = func(context.Context, inventory.Request) (inventory.Snapshot, error) {
		f.captures++
		return inventory.Snapshot{}, errors.New("private process text")
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrCollection) {
		t.Fatal(e)
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrPacing) {
		t.Fatal(e)
	}
	status, _ := f.s.Inspect(f.clock.now())
	if status.Floor != 1 || status.FailureReason != state.FailureCollection {
		t.Fatal(status)
	}
	f.clock.add(time.Minute)
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrCollection) {
		t.Fatal(e)
	}
	if f.captures != 2 {
		t.Fatal("failure retried too fast")
	}
}
func TestLostReportReplyReopenRenewalKeepsExactBytes(t *testing.T) {
	f := fixtureSender(t)
	var pending, enableReceipt []byte
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path == ReportPath {
			pending = bytes.Clone(raw)
			return nil, errors.New("reply lost")
		}
		r, e := receiptFor(raw, f.clock.now())
		enableReceipt = bytes.Clone(r)
		return r, e
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	if e := f.c.Close(); e != nil {
		t.Fatal(e)
	}
	f.clock.add(3 * time.Hour)
	f.a.evidence.CurrentDER = bytes.Clone(f.successor)
	f.a.evidence.CredentialGeneration = 2
	s, e := state.Restore(f.d, f.original, f.d.read(), f.clock.now())
	if e != nil {
		t.Fatal(e)
	}
	f.s = s
	f.c, e = newCoordinator(s, f.original, f.a, func() error { f.releases++; return nil }, f.clock.now, func(context.Context, inventory.Request) (inventory.Snapshot, error) {
		t.Fatal("recaptured pending result")
		return inventory.Snapshot{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path != ReportPath || !bytes.Equal(raw, pending) {
			t.Fatal("rewritten pending")
		}
		return receiptFor(raw, f.clock.now())
	}
	if e = f.c.Cycle(context.Background()); e != nil {
		t.Fatal(e)
	}
	checkpoint, _ := s.CheckpointBytes()
	if !bytes.Contains(checkpoint, []byte(`"floor":1`)) {
		t.Fatal("floor reset")
	}
	// Original enable receipt remains exactly accepted, even after renewed leaf.
	if e = s.AcknowledgeControl(enableReceipt, f.clock.now()); e != nil {
		t.Fatal(e)
	}
}
func TestDisableCancelsJoinsAndConsumesActiveCapture(t *testing.T) {
	f := fixtureSender(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	f.c.collect = func(ctx context.Context, r inventory.Request) (inventory.Snapshot, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	cycle := make(chan error, 1)
	go func() { cycle <- f.c.Cycle(context.Background()) }()
	<-entered
	disabled := make(chan error, 1)
	go func() { disabled <- f.c.Disable() }()
	<-canceled
	select {
	case e := <-disabled:
		t.Fatal("disable returned before collector joined", e)
	default:
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	close(release)
	if e := <-cycle; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := <-disabled; e != nil {
		t.Fatal(e)
	}
	status, _ := f.s.Inspect(f.clock.now())
	if !status.Terminal || status.Floor != 1 || status.AttemptStatus != "lost" {
		t.Fatal(status)
	}
	if e := f.c.Cycle(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, p := range f.a.paths {
		if p == ReportPath {
			t.Fatal("reported after disable")
		}
	}
	control, _ := wire.DecodeControl(f.a.bodies[len(f.a.bodies)-1])
	if control.Enabled || control.CaptureFloor != 1 {
		t.Fatal("wrong disable floor")
	}
}
func TestCloseCancelsJoinsTransportBeforeRelease(t *testing.T) {
	f := fixtureSender(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	f.a.exchange = func(ctx context.Context, path string, raw []byte) ([]byte, error) {
		if path == ControlPath {
			return receiptFor(raw, f.clock.now())
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	}
	cycle := make(chan error, 1)
	go func() { cycle <- f.c.Cycle(context.Background()) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- f.c.Close() }()
	<-canceled
	select {
	case e := <-closed:
		t.Fatal("closed before transport joined", e)
	default:
	}
	if f.releases != 0 {
		t.Fatal("released early")
	}
	close(release)
	if e := <-cycle; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := <-closed; e != nil {
		t.Fatal(e)
	}
	if f.releases != 1 {
		t.Fatal("lock release count")
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	restored, e := state.Restore(f.d, f.original, f.d.read(), f.clock.now())
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	status, _ := restored.Inspect(f.clock.now())
	if status.Terminal || status.AttemptStatus != "pending" || status.Floor != 1 {
		t.Fatal(status)
	}
}
func TestAuthorityChangedDuringCapturePreventsStage(t *testing.T) {
	f := fixtureSender(t)
	f.c.collect = func(_ context.Context, r inventory.Request) (inventory.Snapshot, error) {
		f.a.evidence.CurrentDER = bytes.Clone(f.successor)
		f.a.evidence.CredentialGeneration = 2
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	status, _ := f.s.Inspect(f.clock.now())
	if status.AttemptStatus != "lost" || status.Floor != 1 {
		t.Fatal(status)
	}
	if len(f.a.paths) != 1 {
		t.Fatal("stale current leaf sent")
	}
}
func TestMalformedCollectorBindingNeverRepaired(t *testing.T) {
	f := fixtureSender(t)
	f.c.collect = func(_ context.Context, r inventory.Request) (inventory.Snapshot, error) {
		r.GenerationID = "sample_" + strings.Repeat("f", 32)
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrCollection) {
		t.Fatal(e)
	}
	if len(f.a.paths) != 1 {
		t.Fatal("malformed report sent")
	}
}
func TestStageAfterWriteFailureNeverSends(t *testing.T) {
	f := fixtureSender(t)
	f.c.collect = func(_ context.Context, r inventory.Request) (inventory.Snapshot, error) {
		f.d.fail, f.d.after = true, true
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrUncertain) {
		t.Fatal(e)
	}
	if len(f.a.paths) != 1 {
		t.Fatal("uncertain stage sent")
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrUncertain) {
		t.Fatal(e)
	}
}
func TestExpiredPendingPrunedWithoutLiveAuthority(t *testing.T) {
	f := fixtureSender(t)
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path == ReportPath {
			return nil, ErrTransport
		}
		return receiptFor(raw, f.clock.now())
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	f.clock.add(wire.Retention)
	f.a.reject = true
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	raw := f.d.read()
	if !bytes.Contains(raw, []byte(`"body":null`)) {
		t.Fatal("expired source bytes retained")
	}
	status, e := f.c.Maintain(context.Background())
	if e != nil || status.Freshness != "expired" || status.Floor != 1 {
		t.Fatal(status, e)
	}
}
func TestAuthorityFailuresBeforeAnyCollection(t *testing.T) {
	for _, name := range []string{"missing consent", "different original", "basic profile", "expired leaf", "future leaf", "different key", "wrong generation", "wrong origin", "untrusted issuer", "disabled consent", "missing adapter"} {
		t.Run(name, func(t *testing.T) {
			f := fixtureSender(t)
			switch name {
			case "missing consent":
				f.a.evidence.Consent = nil
			case "different original":
				f.a.evidence.OriginalEnable = []byte(`{}`)
			case "basic profile":
				c := f.enable
				c.Binding.Profile = "basic-readonly-v1"
				f.a.evidence.OriginalEnable = []byte(c.Binding.Profile)
			case "expired leaf":
				f.clock.add(2 * time.Hour)
			case "future leaf":
				f.clock.add(-2 * time.Hour)
			case "different key":
				f.a.evidence.CurrentDER = f.a.evidence.IssuerDER
			case "wrong generation":
				f.a.evidence.CredentialGeneration = 0
			case "wrong origin":
				f.a.evidence.ManagerOrigin = "https://other.example"
			case "untrusted issuer":
				f.a.evidence.IssuerDER = f.a.evidence.AnchorDER
			case "disabled consent":
				c, _ := inventory.DecodeConsent(f.a.evidence.Consent, f.enable.Binding.SenderBinding)
				c.Enabled = false
				f.a.evidence.Consent, _ = inventory.EncodeConsent(c, f.enable.Binding.SenderBinding)
			case "missing adapter":
				f.a.reject = true
			}
			e := f.c.Cycle(context.Background())
			if e == nil {
				t.Fatal("admitted")
			}
			if f.captures != 0 || len(f.a.paths) != 0 {
				t.Fatal("unauthorized edge")
			}
		})
	}
}

func TestDisableJoinsLateReceiptAndNeverAcknowledgesReport(t *testing.T) {
	f := fixtureSender(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	f.a.exchange = func(ctx context.Context, path string, raw []byte) ([]byte, error) {
		if path == ControlPath {
			return receiptFor(raw, f.clock.now())
		}
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return receiptFor(raw, f.clock.now())
	}
	cycle := make(chan error, 1)
	go func() { cycle <- f.c.Cycle(context.Background()) }()
	<-entered
	disable := make(chan error, 1)
	go func() { disable <- f.c.Disable() }()
	<-canceled
	select {
	case e := <-disable:
		t.Fatal("disabled before late reply joined", e)
	default:
	}
	close(release)
	if e := <-cycle; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := <-disable; e != nil {
		t.Fatal(e)
	}
	status, e := f.c.Maintain(context.Background())
	if e != nil || !status.Terminal || status.AttemptStatus != "abandoned" || status.Floor != 1 {
		t.Fatal(status, e)
	}
	if _, e = f.s.PendingReport(f.clock.now()); !errors.Is(e, state.ErrDisabled) {
		t.Fatal(e)
	}
}

func TestAuthorityChangedAtSendEdgeKeepsPendingBytes(t *testing.T) {
	f := fixtureSender(t)
	f.a.check = func() {
		status, e := f.s.Inspect(f.clock.now())
		if e != nil {
			t.Fatal(e)
		}
		if status.AttemptStatus == "pending" {
			f.a.evidence.CurrentDER = bytes.Clone(f.successor)
			f.a.evidence.CredentialGeneration = 2
		}
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	if len(f.a.paths) != 1 {
		t.Fatal("stale leaf exchanged report")
	}
	pending, e := f.s.PendingReport(f.clock.now())
	if e != nil || len(pending) == 0 {
		t.Fatal("pending bytes lost", e)
	}
	report, e := wire.DecodeReport(pending)
	if e != nil || report.CaptureSequence != 1 || !report.CollectedAt.Equal(f.clock.now()) {
		t.Fatal(e)
	}
}

func TestInvalidEnableReceiptCannotCollect(t *testing.T) {
	f := fixtureSender(t)
	f.a.exchange = func(_ context.Context, _ string, raw []byte) ([]byte, error) {
		r, e := receiptFor(raw, f.clock.now())
		if e != nil {
			t.Fatal(e)
		}
		return append(r, '\n'), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrInvalid) {
		t.Fatal(e)
	}
	if f.captures != 0 {
		t.Fatal("invalid receipt enabled source")
	}
}

func TestCoordinatorRequiresExactExistingOriginal(t *testing.T) {
	f := fixtureSender(t)
	foreign := f.enable
	foreign.GrantID = strings.Repeat("f", 32)
	raw, _ := wire.EncodeControl(foreign)
	if c, e := newCoordinator(f.s, raw, f.a, func() error { return nil }, f.clock.now, f.c.collect); c != nil || !errors.Is(e, ErrAuthority) {
		t.Fatal("foreign state accepted")
	}
	if c, e := newCoordinator(f.s, f.original, nil, func() error { return nil }, f.clock.now, f.c.collect); c != nil || !errors.Is(e, ErrAuthority) {
		t.Fatal("missing authority accepted")
	}
}

func TestSlowFinalAuthorityCheckCannotTransmitExpiredOriginalReport(t *testing.T) {
	f := fixtureSender(t)
	f.a.evidence.CurrentDER = bytes.Clone(f.successor)
	f.a.evidence.CredentialGeneration = 2
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path == ReportPath {
			return nil, ErrTransport
		}
		return receiptFor(raw, f.clock.now())
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	original := bytes.Clone(f.a.bodies[1])
	f.clock.add(wire.Retention - time.Second)
	checks := 0
	f.a.check = func() {
		checks++
		if checks == 2 {
			f.clock.add(time.Second)
		}
	}
	before := len(f.a.paths)
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrExpired) {
		t.Fatal(e)
	}
	if len(f.a.paths) != before {
		t.Fatal("report transmitted beyond original expiry")
	}
	report, _ := wire.DecodeReport(original)
	if !report.ExpiresAt.Equal(report.CollectedAt.Add(wire.Retention)) {
		t.Fatal("lifetime rewritten")
	}
	if !bytes.Contains(f.d.read(), []byte(`"body":null`)) {
		t.Fatal("expired bytes not pruned")
	}
}

func TestSlowAuthorityCheckCannotHideCurrentLeafExpiry(t *testing.T) {
	f := fixtureSender(t)
	f.clock.add(2*time.Hour - time.Second)
	f.a.check = func() { f.clock.add(time.Second) }
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	if len(f.a.paths) != 0 || f.captures != 0 {
		t.Fatal("expired current credential admitted")
	}
}

func TestChangedCaptureTimeFailsReservationInsteadOfWedgingOwner(t *testing.T) {
	f := fixtureSender(t)
	f.c.collect = func(_ context.Context, r inventory.Request) (inventory.Snapshot, error) {
		r.CollectedAt = r.CollectedAt.Add(time.Second)
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrCollection) {
		t.Fatal(e)
	}
	status, e := f.c.Maintain(context.Background())
	if e != nil || status.AttemptStatus != "failed" || status.Floor != 1 {
		t.Fatal(status, e)
	}
	f.clock.add(time.Minute)
	if e = f.c.Cycle(context.Background()); !errors.Is(e, ErrCollection) {
		t.Fatal("owner wedged after malformed result", e)
	}
}

func TestCaptureExpiredDuringCollectionIsSettledLost(t *testing.T) {
	f := fixtureSender(t)
	f.a.evidence.CurrentDER = bytes.Clone(f.successor)
	f.a.evidence.CredentialGeneration = 2
	f.c.collect = func(_ context.Context, r inventory.Request) (inventory.Snapshot, error) {
		f.clock.add(wire.Retention)
		return inventory.Empty(r, inventory.ErrUnavailable.Error()), nil
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrExpired) {
		t.Fatal(e)
	}
	status, e := f.c.Maintain(context.Background())
	if e != nil || status.AttemptStatus != "lost" || status.Floor != 1 {
		t.Fatal(status, e)
	}
	if len(f.a.paths) != 1 {
		t.Fatal("expired capture sent")
	}
}

func TestZeroCoordinatorFailsClosed(t *testing.T) {
	c := new(Coordinator)
	if e := c.Cycle(context.Background()); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if _, e := c.Maintain(context.Background()); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if e := c.Disable(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
	if e := c.Close(); !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}

func TestFinalCheckClockRollbackCannotSendBelowDurableWatermark(t *testing.T) {
	f := fixtureSender(t)
	f.a.exchange = func(_ context.Context, path string, raw []byte) ([]byte, error) {
		if path == ReportPath {
			return nil, ErrTransport
		}
		return receiptFor(raw, f.clock.now())
	}
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrTransport) {
		t.Fatal(e)
	}
	f.clock.add(time.Minute)
	checks := 0
	f.a.check = func() {
		checks++
		if checks == 2 {
			f.clock.add(-30 * time.Second)
		}
	}
	before := len(f.a.paths)
	if e := f.c.Cycle(context.Background()); !errors.Is(e, state.ErrClock) {
		t.Fatal(e)
	}
	if len(f.a.paths) != before {
		t.Fatal("sent below durable clock")
	}
}

func TestFailedDisableKeepsAdmissionStoppedUntilExplicitRetry(t *testing.T) {
	f := fixtureSender(t)
	f.clock.add(-time.Second)
	if e := f.c.Disable(); !errors.Is(e, state.ErrClock) {
		t.Fatal(e)
	}
	f.clock.add(time.Second)
	if e := f.c.Cycle(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatal("failed disable reopened reporting", e)
	}
	if f.captures != 0 || len(f.a.paths) != 0 {
		t.Fatal("reported despite requested stop")
	}
	if e := f.c.Disable(); e != nil {
		t.Fatal(e)
	}
	if e := f.c.Cycle(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.captures != 0 || len(f.a.paths) != 1 {
		t.Fatal("terminal control retry")
	}
	control, e := wire.DecodeControl(f.a.bodies[0])
	if e != nil || control.Enabled {
		t.Fatal("enable sent after failed stop", e)
	}
}
