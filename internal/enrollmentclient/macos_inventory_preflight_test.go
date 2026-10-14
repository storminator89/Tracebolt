package enrollmentclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentissuer"
	state "localrmm/internal/macosinventorystate"
	"localrmm/internal/renewalidentity"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This fake only holds disposable fixture bytes in memory. Writes and directory
// creation are rejected; the real authority, artifact and checkpoint validators
// still run. No native enrollment, storage, provider, network or service is used.
type macOSPreflightMemoryStore struct {
	storeRedaction
	t        *testing.T
	files    map[string][]byte
	closed   bool
	onClose  func() error
	onRead   func(string)
	closeErr error
}

func (s *macOSPreflightMemoryStore) Read(name string) ([]byte, error) {
	if s.closed {
		s.t.Fatal("read after enrollment lock released")
	}
	if s.onRead != nil {
		s.onRead(name)
	}
	raw, ok := s.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s *macOSPreflightMemoryStore) Write(string, []byte) error {
	s.t.Fatal("preflight wrote enrollment state")
	return ErrState
}
func (s *macOSPreflightMemoryStore) EnsureTelemetry() error {
	s.t.Fatal("preflight initialized telemetry")
	return ErrState
}
func (s *macOSPreflightMemoryStore) TelemetryExists() (bool, error) {
	return !s.closed, nil
}
func (s *macOSPreflightMemoryStore) Close() error {
	if s.closed {
		s.t.Fatal("enrollment closed twice")
	}
	s.closed = true
	if s.onClose != nil {
		return s.onClose()
	}
	return s.closeErr
}

type macOSPreflightCloser func() error

func (f macOSPreflightCloser) Close() error { return f() }

type macOSPreflightFixture struct {
	s                    *session
	issuer               *enrollmentissuer.Issuer
	store                *macOSPreflightMemoryStore
	now                  time.Time
	checkpoint, enable   []byte
	events               []string
	storageErr, closeErr error
	onStorageOpen        func()
	onStorageClose       func()
	before               map[string][]byte
}

func newMacOSPreflightFixture(t *testing.T, renewable bool) *macOSPreflightFixture {
	t.Helper()
	s, issuer, now := macOSInventoryFixture(t)
	s.opts.ResumeOnly = true
	s.opts.inventoryAuthorityReading = true
	s.l.Seed = base64.RawStdEncoding.EncodeToString(s.key.Seed())
	s.l.CSR = base64.RawStdEncoding.EncodeToString(s.csr)
	s.l.ClaimRequestID = "request_" + strings.Repeat("1", 32)
	s.l.StatusRequestID = "request_" + strings.Repeat("2", 32)
	s.l.CredentialRequestID = "request_" + strings.Repeat("3", 32)
	s.l.ActivationRequestID = "request_" + strings.Repeat("5", 32)
	s.l.SenderInitializationStarted, s.l.HandoffPrepared = true, true
	if renewable {
		s.l.Version = renewableLedgerVersion
		s.l.Bootstrap.SchemaVersion = RenewableBootstrapVersion
		s.l.Bootstrap.RenewalPolicy = renewalidentity.Policy
		s.l.RenewalReadyPublished = true
	}
	f := &macOSPreflightFixture{s: s, issuer: issuer, now: now}
	f.store = &macOSPreflightMemoryStore{t: t, files: map[string][]byte{}}
	s.store = f.store
	s.renewalNow = func() time.Time { return f.now }
	_, files, ready, e := s.handoff()
	if e != nil {
		t.Fatal(e)
	}
	defer clearArtifacts(files)
	for _, file := range files {
		f.store.files[file.name] = bytes.Clone(file.raw)
	}
	f.store.files["ready.json"] = bytes.Clone(ready)
	f.store.files["ledger.json"], e = json.Marshal(ledgerDisk(*s.l.ledgerData))
	if e != nil {
		t.Fatal(e)
	}
	_, _, f.enable, e = s.macOSInventoryOriginal()
	if e != nil {
		t.Fatal(e)
	}
	memory := &macOSInventoryMemory{}
	checkpoint, e := state.InitializeFresh(memory, f.enable, now)
	if e != nil {
		t.Fatal(e)
	}
	checkpoint.Close()
	f.checkpoint = bytes.Clone(memory.raw)
	if renewable {
		m, e := s.initialRenewalManifest()
		if e != nil {
			t.Fatal(e)
		}
		f.setCredential(t, m, "healthy")
	}
	// Exercise the real existing-only historical load used by the native opener.
	if e = s.load(s.l.Bootstrap); e != nil {
		t.Fatal("invalid in-memory retained enrollment", e)
	}
	if e = s.initializeMacOSInventoryTrust(); e != nil {
		t.Fatal(e)
	}
	f.before = f.snapshot()
	return f
}

func (f *macOSPreflightFixture) snapshot() map[string][]byte {
	copy := map[string][]byte{}
	for name, raw := range f.store.files {
		copy[name] = bytes.Clone(raw)
	}
	return copy
}

func (f *macOSPreflightFixture) setCredential(t *testing.T, m renewalidentity.Manifest, status string) {
	t.Helper()
	tx := initialRenewalTransaction(m)
	tx.State = status
	var e error
	f.store.files[renewalidentity.ManifestName], e = json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	f.store.files[renewalidentity.LedgerName], e = json.Marshal(tx)
	if e != nil {
		t.Fatal(e)
	}
}

func (f *macOSPreflightFixture) successor(t *testing.T) renewalidentity.Manifest {
	t.Helper()
	m, e := f.s.initialRenewalManifest()
	if e != nil {
		t.Fatal(e)
	}
	at := time.Unix(m.AnchorIntent.NotAfter, 0).UTC().Add(-time.Hour)
	m.Intent.RequestID = "request_" + strings.Repeat("8", 32)
	m.Intent.IntentID = "intent_" + strings.Repeat("9", 32)
	m.Intent.SerialHex = strings.Repeat("8", 32)
	m.Intent.NotBefore = at.Add(-time.Minute).Unix()
	m.Intent.NotAfter = at.Add(7*24*time.Hour - time.Minute).Unix()
	issued, e := f.issuer.Sign(context.Background(), m.Intent, at)
	if e != nil {
		t.Fatal(e)
	}
	m.CertificateDER = issued.DER()
	m.CredentialGeneration = 2
	m.Revision++
	m.LastServerNow = at.Unix()
	return m
}

func (f *macOSPreflightFixture) dependencies(t *testing.T) macOSInventoryPreflightDependencies {
	t.Helper()
	return macOSInventoryPreflightDependencies{
		openEnrollment: func(path string) (*session, error) {
			if path != filepath.Join(f.s.opts.StateDirectory, "agent.json") {
				t.Fatal("changed original enrollment path")
			}
			f.events = append(f.events, "enrollment-open")
			return f.s, nil
		},
		openStorage: func(path string, enable []byte) (io.Closer, []byte, error) {
			if f.store.closed || path != filepath.Join(f.s.opts.StateDirectory, "telemetry") || !bytes.Equal(enable, f.enable) {
				t.Fatal("lost enrollment lock or original sender binding")
			}
			f.events = append(f.events, "storage-open")
			if f.onStorageOpen != nil {
				f.onStorageOpen()
			}
			if f.storageErr != nil {
				return nil, nil, f.storageErr
			}
			return macOSPreflightCloser(func() error {
				if f.store.closed {
					t.Fatal("sender storage outlived enrollment lock")
				}
				f.events = append(f.events, "storage-close")
				if f.onStorageClose != nil {
					f.onStorageClose()
				}
				return f.closeErr
			}), bytes.Clone(f.checkpoint), nil
		},
		now: func() time.Time { return f.now },
	}
}

func (f *macOSPreflightFixture) run(t *testing.T, ctx context.Context) error {
	t.Helper()
	e := validateMacOSInventoryServicePreflight(ctx, filepath.Join(f.s.opts.StateDirectory, "agent.json"), f.dependencies(t))
	if len(f.events) != 0 {
		if !f.store.closed || !bytes.Equal(f.s.key, make([]byte, len(f.s.key))) {
			t.Fatal("enrollment lock or in-memory key retained")
		}
	}
	return e
}

func TestMacOSInventoryServicePreflightRequiresLiveLocalAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renewable bool
		edit      func(*macOSPreflightFixture)
	}{
		{"nonrenewable-expired", false, func(f *macOSPreflightFixture) { f.now = time.Unix(f.s.l.Intent.NotAfter, 0).UTC() }},
		{"manifest-missing", true, func(f *macOSPreflightFixture) { delete(f.store.files, renewalidentity.ManifestName) }},
		{"manifest-malformed", true, func(f *macOSPreflightFixture) {
			f.store.files[renewalidentity.ManifestName] = []byte(`{"invalid":true}`)
		}},
		{"renewable-expired", true, func(f *macOSPreflightFixture) { f.now = time.Unix(f.s.l.Intent.NotAfter, 0).UTC() }},
		{"transaction-missing", true, func(f *macOSPreflightFixture) { delete(f.store.files, renewalidentity.LedgerName) }},
		{"transaction-malformed", true, func(f *macOSPreflightFixture) { f.store.files[renewalidentity.LedgerName] = []byte(`{"invalid":true}`) }},
		{"revoked", true, func(f *macOSPreflightFixture) { m, _ := f.s.initialRenewalManifest(); f.setCredential(t, m, "revoked") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMacOSPreflightFixture(t, tc.renewable)
			tc.edit(f)
			// Retained-state validation deliberately continues to accept original
			// history, while the new service preflight must reject live authority.
			if e := f.s.load(f.s.l.Bootstrap); e != nil || state.ValidateCheckpoint(f.checkpoint, f.enable) != nil {
				t.Fatal("retained-state semantics changed", e)
			}
			before := f.snapshot()
			if e := f.run(t, context.Background()); e == nil {
				t.Fatal("invalid current authority passed service preflight")
			}
			if !reflect.DeepEqual(before, f.store.files) || !reflect.DeepEqual(f.events, []string{"enrollment-open"}) {
				t.Fatal("rejected authority reached sender storage or changed state")
			}
		})
	}
}

func TestMacOSInventoryServicePreflightCurrentSuccessorKeepsOriginalState(t *testing.T) {
	for _, mode := range []string{"nonrenewable", "renewable", "successor", "future-renewal-blocked"} {
		t.Run(mode, func(t *testing.T) {
			f := newMacOSPreflightFixture(t, mode != "nonrenewable")
			if mode == "successor" {
				f.setCredential(t, f.successor(t), "healthy")
				f.now = time.Unix(f.s.l.Intent.NotAfter, 0).UTC().Add(time.Minute)
			} else if mode == "future-renewal-blocked" {
				m, _ := f.s.initialRenewalManifest()
				f.setCredential(t, m, "blocked")
			}
			before, checkpoint := f.snapshot(), bytes.Clone(f.checkpoint)
			if e := f.run(t, context.Background()); e != nil {
				t.Fatal("live original authority rejected", e)
			}
			if !reflect.DeepEqual(before, f.store.files) || !bytes.Equal(checkpoint, f.checkpoint) {
				t.Fatal("preflight changed original artifacts, renewal or sender state")
			}
			if !reflect.DeepEqual(f.events, []string{"enrollment-open", "storage-open", "storage-close"}) {
				t.Fatal("unexpected lock/storage lifetime")
			}
			for _, name := range []string{"ledger.json", "agent.json", "agent-cert.pem", "ready.json"} {
				if !bytes.Equal(f.before[name], f.store.files[name]) {
					t.Fatal("successor replaced original identity or configuration")
				}
			}
		})
	}
}

func TestMacOSInventoryServicePreflightStorageAndCloseFailures(t *testing.T) {
	for _, mode := range []string{"storage-open", "checkpoint", "storage-close", "enrollment-close"} {
		t.Run(mode, func(t *testing.T) {
			f := newMacOSPreflightFixture(t, false)
			switch mode {
			case "storage-open":
				f.storageErr = ErrState
			case "checkpoint":
				f.checkpoint = []byte(`{"invalid":true}`)
			case "storage-close":
				f.closeErr = errors.New("synthetic storage close failure")
			case "enrollment-close":
				f.store.closeErr = errors.New("synthetic enrollment close failure")
			}
			if e := f.run(t, context.Background()); !errors.Is(e, ErrState) {
				t.Fatal("storage or close failure did not block preflight", e)
			}
			if mode != "storage-open" && f.events[len(f.events)-1] != "storage-close" {
				t.Fatal("sender storage lock leaked on failure")
			}
		})
	}
}

func TestMacOSInventoryServicePreflightRejectsFutureSenderClock(t *testing.T) {
	f := newMacOSPreflightFixture(t, false)
	memory := &macOSInventoryMemory{}
	future := f.now.Add(2 * time.Minute)
	checkpoint, e := state.InitializeFresh(memory, f.enable, future)
	if e != nil {
		t.Fatal(e)
	}
	checkpoint.Close()
	f.checkpoint = bytes.Clone(memory.raw)
	if e := state.ValidateCheckpoint(f.checkpoint, f.enable); e != nil {
		t.Fatal("future checkpoint was not structurally valid", e)
	}
	if _, e := state.Restore(memory, f.enable, f.checkpoint, f.now); !errors.Is(e, state.ErrClock) {
		t.Fatal("fixture did not reproduce the sender's rollback rejection", e)
	}
	before := f.snapshot()
	if e := f.run(t, context.Background()); !errors.Is(e, ErrState) {
		t.Fatal("service preflight admitted a sender that cannot restore", e)
	}
	if !reflect.DeepEqual(before, f.store.files) || !reflect.DeepEqual(f.events, []string{"enrollment-open", "storage-open", "storage-close"}) {
		t.Fatal("rollback preflight modified state or skipped storage cleanup")
	}
}

func TestMacOSInventoryServicePreflightRechecksSenderClock(t *testing.T) {
	f := newMacOSPreflightFixture(t, false)
	f.onStorageClose = func() { f.now = f.now.Add(-time.Second) }
	before := f.snapshot()
	if e := f.run(t, context.Background()); !errors.Is(e, ErrState) {
		t.Fatal("sender clock rollback after initial inspection passed preflight", e)
	}
	if !reflect.DeepEqual(before, f.store.files) || !reflect.DeepEqual(f.events, []string{"enrollment-open", "storage-open", "storage-close"}) {
		t.Fatal("clock rollback changed state or bypassed final authority")
	}
}

func TestMacOSInventoryServicePreflightRechecksContextAndAuthority(t *testing.T) {
	for _, mode := range []string{"canceled-before-open", "canceled-during-read", "canceled-during-storage", "canceled-on-close", "ledger-changed", "config-changed", "manifest-lost", "revoked-during-storage", "expired-during-storage", "leaf-changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newMacOSPreflightFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "canceled-before-open":
				cancel()
			case "canceled-during-read":
				f.store.onRead = func(string) { cancel() }
			case "canceled-during-storage":
				f.onStorageClose = cancel
			case "canceled-on-close":
				f.store.onClose = func() error { cancel(); return nil }
			case "ledger-changed":
				f.onStorageClose = func() { f.store.files["ledger.json"] = []byte(`{"invalid":true}`) }
			case "config-changed":
				f.onStorageClose = func() { f.store.files["agent.json"] = []byte(`{"invalid":true}`) }
			case "manifest-lost":
				f.onStorageClose = func() { delete(f.store.files, renewalidentity.ManifestName) }
			case "revoked-during-storage":
				f.onStorageClose = func() { m, _ := f.s.initialRenewalManifest(); f.setCredential(t, m, "revoked") }
			case "expired-during-storage":
				f.onStorageClose = func() { f.now = time.Unix(f.s.l.Intent.NotAfter, 0).UTC() }
			case "leaf-changed":
				m := f.successor(t)
				f.now = time.Unix(m.Intent.NotBefore, 0).UTC().Add(time.Minute)
				f.onStorageClose = func() { f.setCredential(t, m, "healthy") }
			}
			if e := f.run(t, ctx); e == nil {
				t.Fatal("cancellation or changed final local authority passed")
			}
			if mode == "canceled-before-open" && len(f.events) != 0 {
				t.Fatal("canceled preflight opened enrollment")
			}
			if mode == "canceled-during-read" && !reflect.DeepEqual(f.events, []string{"enrollment-open"}) {
				t.Fatal("canceled authority check reached sender storage")
			}
		})
	}
	if e := ValidateMacOSInventoryServicePreflight(nil, "unused"); e == nil {
		t.Fatal("nil context reached native storage")
	}
}
