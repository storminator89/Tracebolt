//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/socketowner"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemstate"
	"localrmm/internal/systemwire"
	"strings"
	"testing"
	"time"
)

type socketSetupMemoryState struct {
	p                                         *socketSetupPending
	floor                                     uint64
	pendingErr, nextErr, discardErr, closeErr error
	discarded, closed                         int
	beforeDiscard                             func()
}

func (s *socketSetupMemoryState) pending() (*socketSetupPending, error) {
	if s.pendingErr != nil {
		return nil, s.pendingErr
	}
	if s.p == nil {
		return nil, nil
	}
	p := *s.p
	p.body = bytes.Clone(p.body)
	return &p, nil
}
func (s *socketSetupMemoryState) next() (uint64, error) { return s.floor + 1, s.nextErr }
func (s *socketSetupMemoryState) discard(d string) error {
	s.discarded++
	if s.beforeDiscard != nil {
		s.beforeDiscard()
	}
	if s.discardErr != nil {
		return s.discardErr
	}
	if s.p == nil || d != s.p.digest {
		return systemstate.ErrDigest
	}
	s.p = nil
	return nil
}
func (s *socketSetupMemoryState) Close() error { s.closed++; return s.closeErr }

type socketSetupMemoryLease struct {
	closed int
	err    error
}

func (l *socketSetupMemoryLease) Close() error { l.closed++; return l.err }

type socketSetupFixture struct {
	m                                      Material
	consent                                *SocketOwnerConsent
	policy                                 socketowner.Policy
	hooks                                  socketSetupHooks
	state                                  *socketSetupMemoryState
	lease                                  *socketSetupMemoryLease
	reads, writes, inspects, leases, opens int
	failReadAt                             int
}

func newSocketSetupMemoryFixture(t *testing.T, profile string) *socketSetupFixture {
	t.Helper()
	// Existing fixture constructs only invented credentials and temporary private
	// files with fake source/transport hooks. No Run, helper or native collector.
	source := newSocketFixtureProfile(t, profile)
	source.sender.Close()
	m := source.material
	m.configPath = SocketOwnerSetupConfigPath
	f := &socketSetupFixture{m: m, policy: source.local.Policy, state: &socketSetupMemoryState{floor: 7}, lease: &socketSetupMemoryLease{}}
	f.hooks = socketSetupHooks{
		material: func(path string) (Material, uint32, uint32, error) {
			f.reads++
			if path != SocketOwnerSetupConfigPath {
				t.Fatal("non-fixed path")
			}
			if f.failReadAt > 0 && f.reads >= f.failReadAt {
				return Material{}, 0, 0, ErrState
			}
			return f.m, 1234, 1234, nil
		},
		inspect: func(Material) (*SocketOwnerConsent, error) {
			f.inspects++
			if f.consent == nil {
				return nil, nil
			}
			c := *f.consent
			return &c, nil
		},
		lease: func(Material) (io.Closer, error) { f.leases++; return f.lease, nil },
		state: func(Material) (socketSetupState, error) { f.opens++; return f.state, nil },
		write: func(_ Material, old *SocketOwnerConsent, next SocketOwnerConsent, current func() error) error {
			f.writes++
			if current() != nil {
				return ErrState
			}
			f.consent = &next
			return nil
		},
	}
	return f
}
func (f *socketSetupFixture) enable() {
	f.consent = &SocketOwnerConsent{SocketOwnerConsentVersion, f.m.config.AgentID, "sha256:" + journalLeaf(f.m), f.policy}
}
func (f *socketSetupFixture) run(mode string) (SocketOwnerSetupResult, error) {
	var raw []byte
	ack := SocketOwnerSetupAcknowledgements{}
	if mode == "initialize" || mode == "disable" {
		p := f.policy
		p.Enabled = mode == "initialize"
		raw, _ = socketowner.EncodePolicy(p)
		if mode == "initialize" {
			ack = SocketOwnerSetupAcknowledgements{true, true, p.TransportProfile == "http-test"}
		}
	}
	return configureSocketOwners(context.Background(), mode, raw, ack, f.hooks)
}
func (f *socketSetupFixture) pending(t *testing.T, tagged bool) {
	t.Helper()
	id, _ := systemwire.GenerationID(f.m.config.AgentID, f.state.floor)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	snap := systeminventory.Empty(id, at, systeminventory.ReasonPermissionDenied)
	var raw []byte
	var err error
	if tagged {
		n := uint64(0)
		snap.Sockets.Meta = systeminventory.SectionMeta{GenerationID: id, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &n, CountExact: true}
		snap.Sockets.Items = []systeminventory.Socket{}
		provenance := systeminventory.SocketOwnerProvenance{SchemaVersion: systeminventory.SocketOwnerSourceVersion, Scope: systeminventory.SocketOwnerSourceScope, GrantEpoch: f.policy.Epoch, PolicyDigest: socketowner.PolicyDigest(f.policy), AuthorityRevision: strings.Repeat("b", 64), ContextID: strings.Repeat("c", 64), StartedAt: at, FinishedAt: at}
		raw, err = systemwire.EncodeSocketOwners(f.state.floor, snap, provenance, nil, nil)
	} else {
		raw, err = systemwire.Encode(f.state.floor, snap)
	}
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	f.state.p = &socketSetupPending{f.state.floor, hex.EncodeToString(sum[:]), raw}
}
func TestSocketSetupIdentityPreviewOfflineAndReadback(t *testing.T) {
	for _, mode := range []string{"identity", "preview"} {
		for _, profile := range []string{"tls", "http-test"} {
			for _, status := range []string{"absent", "enabled", "disabled"} {
				t.Run(mode+"/"+profile+"/"+status, func(t *testing.T) {
					f := newSocketSetupMemoryFixture(t, profile)
					if status != "absent" {
						f.enable()
						f.consent.Policy.Enabled = status == "enabled"
					}
					got, err := f.run(mode)
					if err != nil || got.State != status || got.SchemaVersion != SocketOwnerSetupResultVersion || got.Identity.SchemaVersion != SocketOwnerSetupIdentityVersion || got.Identity.TransportProfile != profile || got.TaggedPendingDiscarded || f.leases != 0 || f.opens != 0 || f.writes != 0 || f.reads < 2 || f.inspects < 2 {
						t.Fatal(got, err)
					}
					raw, _ := json.Marshal(got)
					for _, private := range []string{f.m.config.StateDirectory, f.m.config.PrivateKeyFile, "PRIVATE KEY", "sockets", "body"} {
						if bytes.Contains(raw, []byte(private)) {
							t.Fatal("private projection")
						}
					}
				})
			}
		}
	}
}
func TestSocketSetupInitializeExactAcksCreateOnly(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newSocketSetupMemoryFixture(t, profile)
			f.pending(t, false)
			before := bytes.Clone(f.state.p.body)
			got, err := f.run("initialize")
			if err != nil || got.State != "enabled" || got.Policy == nil || *got.Policy != f.policy || got.TaggedPendingDiscarded || f.state.floor != 7 || !bytes.Equal(before, f.state.p.body) || f.writes != 1 {
				t.Fatal(got, err)
			}
			if _, err = f.run("initialize"); err == nil || f.writes != 1 {
				t.Fatal("adopted enabled consent")
			}
			f.consent.Policy.Enabled = false
			if _, err = f.run("initialize"); err == nil || f.writes != 1 {
				t.Fatal("re-enabled tombstone")
			}
		})
	}
}
func TestSocketSetupDisableTaggedOnlyAndFloor(t *testing.T) {
	for _, kind := range []string{"absent_pending", "ordinary", "tagged", "exhausted"} {
		t.Run(kind, func(t *testing.T) {
			f := newSocketSetupMemoryFixture(t, "http-test")
			f.enable()
			if kind != "absent_pending" {
				f.pending(t, kind != "ordinary")
			}
			if kind == "exhausted" {
				f.state.nextErr = systemstate.ErrSequence
			}
			original, _ := f.state.pending()
			f.state.beforeDiscard = func() {
				if f.consent == nil || f.consent.Policy.Enabled {
					t.Fatal("discard before durable tombstone")
				}
			}
			got, err := f.run("disable")
			tagged := kind == "tagged" || kind == "exhausted"
			if err != nil || got.State != "disabled" || got.Policy == nil || got.Policy.Enabled || got.TaggedPendingDiscarded != tagged || f.state.floor != 7 || f.state.discarded != map[bool]int{false: 0, true: 1}[tagged] {
				t.Fatal(got, err)
			}
			after, _ := f.state.pending()
			if tagged && after != nil || !tagged && !socketSetupPendingEqual(original, after) {
				t.Fatal("wrong pending mutation")
			}
			if _, err = f.run("disable"); err == nil || f.writes != 1 {
				t.Fatal("adopted terminal tombstone")
			}
		})
	}
}
func TestSocketSetupMalformedPolicyAndAcknowledgementsBeforeIdentity(t *testing.T) {
	f := newSocketSetupMemoryFixture(t, "tls")
	raw, _ := socketowner.EncodePolicy(f.policy)
	cases := [][]byte{nil, []byte(`{}`), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":true,"enabled":true`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"Enabled":true`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"enabled":null`, 1)), bytes.Repeat([]byte(" "), 4097)}
	for _, body := range cases {
		if _, err := configureSocketOwners(context.Background(), "initialize", body, SocketOwnerSetupAcknowledgements{true, true, false}, f.hooks); err == nil {
			t.Fatal("malformed policy")
		}
	}
	for bits := 0; bits < 8; bits++ {
		ack := SocketOwnerSetupAcknowledgements{bits&1 != 0, bits&2 != 0, bits&4 != 0}
		if bits == 3 {
			continue
		}
		if _, err := configureSocketOwners(context.Background(), "initialize", raw, ack, f.hooks); err == nil {
			t.Fatal("acks", bits)
		}
	}
	if f.reads != 0 || f.writes != 0 {
		t.Fatal("invalid input read private material")
	}
}
func TestSocketSetupRejectsForeignConsentAndTarget(t *testing.T) {
	for _, kind := range []string{"absent", "disabled", "epoch", "helper", "identity", "origin", "collection", "transport", "ack", "version", "incarnation", "endpoint"} {
		t.Run(kind, func(t *testing.T) {
			f := newSocketSetupMemoryFixture(t, "http-test")
			f.enable()
			f.pending(t, true)
			switch kind {
			case "absent":
				f.consent = nil
			case "disabled":
				f.consent.Policy.Enabled = false
			case "epoch":
				f.policy.Epoch = strings.Repeat("f", 64)
			case "helper":
				f.policy.HelperUID++
			case "identity":
				f.policy.AgentGID++
			case "origin":
				f.policy.ManagerOrigin = "http://other.test"
			case "collection":
				f.policy.CollectionProfile = "managed-operations-v2"
			case "transport":
				f.policy.TransportProfile = "tls"
			case "ack":
				f.policy.MetadataAcknowledged = false
			case "version":
				f.consent.Version = "foreign"
			case "incarnation":
				f.consent.IncarnationDigest = "sha256:" + strings.Repeat("f", 64)
			case "endpoint":
				f.consent.EndpointID = "agent_" + strings.Repeat("f", 32)
			}
			if _, err := f.run("disable"); err == nil || f.writes != 0 || f.state.discarded != 0 || f.state.p == nil || f.state.floor != 7 {
				t.Fatal("accepted foreign or mutated state", kind, err)
			}
		})
	}
}
func TestSocketSetupRejectsCorruptPendingAndLocks(t *testing.T) {
	for _, kind := range []string{"lease", "state", "pending", "floor", "body", "generation", "tagged_without_consent"} {
		t.Run(kind, func(t *testing.T) {
			f := newSocketSetupMemoryFixture(t, "http-test")
			mode := "disable"
			f.enable()
			f.pending(t, true)
			switch kind {
			case "lease":
				f.hooks.lease = func(Material) (io.Closer, error) { return nil, systemstate.ErrLocked }
			case "state":
				f.hooks.state = func(Material) (socketSetupState, error) { return nil, systemstate.ErrLocked }
			case "pending":
				f.state.pendingErr = systemstate.ErrCorrupt
			case "floor":
				f.state.nextErr = systemstate.ErrIO
			case "body":
				f.state.p.body = []byte(`{"invalid":true}`)
			case "generation":
				f.state.p.sequence++
			case "tagged_without_consent":
				f.consent = nil
				mode = "initialize"
			}
			if _, err := f.run(mode); err == nil || f.writes != 0 || f.state.discarded != 0 || f.state.floor != 7 {
				t.Fatal("corrupt/locked state accepted", kind, err)
			}
		})
	}
}
func TestSocketSetupIdentityChangesAndPartialFailures(t *testing.T) {
	for _, mode := range []string{"initialize", "disable"} {
		for _, phase := range []string{"under_locks", "before_write", "writer_recheck", "after_commit", "readback", "discard", "after_discard", "state_close", "lease_close"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				if mode == "initialize" && (phase == "discard" || phase == "after_discard") {
					return
				}
				f := newSocketSetupMemoryFixture(t, "http-test")
				if mode == "disable" {
					f.enable()
					f.pending(t, true)
				}
				switch phase {
				case "under_locks":
					f.failReadAt = 2
				case "before_write":
					f.failReadAt = 3
				case "writer_recheck":
					f.failReadAt = 4
				case "after_commit":
					f.failReadAt = 5
				case "readback":
					base := f.hooks.write
					f.hooks.write = func(m Material, o *SocketOwnerConsent, n SocketOwnerConsent, c func() error) error {
						if err := base(m, o, n, c); err != nil {
							return err
						}
						f.consent.Policy.Epoch = strings.Repeat("f", 64)
						return nil
					}
				case "discard":
					f.state.discardErr = systemstate.ErrIO
				case "after_discard":
					f.state.beforeDiscard = func() { f.state.pendingErr = systemstate.ErrIO }
				case "state_close":
					f.state.closeErr = systemstate.ErrIO
				case "lease_close":
					f.lease.err = systemstate.ErrIO
				}
				got, err := f.run(mode)
				if err == nil || got != (SocketOwnerSetupResult{}) || f.state.floor != 7 {
					t.Fatal("uncertain operation claimed complete", phase, got, err)
				}
				if phase == "discard" && (f.consent == nil || f.consent.Policy.Enabled || f.state.p == nil) {
					t.Fatal("failure lost tombstone or pending")
				}
			})
		}
	}
}
func TestSocketSetupReadOnlyChangedConsentFails(t *testing.T) {
	f := newSocketSetupMemoryFixture(t, "http-test")
	f.hooks.inspect = func(Material) (*SocketOwnerConsent, error) {
		f.inspects++
		if f.inspects == 1 {
			return nil, nil
		}
		f.enable()
		return f.consent, nil
	}
	if _, err := f.run("preview"); err == nil || f.writes != 0 {
		t.Fatal("changed preview")
	}
	f = newSocketSetupMemoryFixture(t, "http-test")
	f.hooks.inspect = func(Material) (*SocketOwnerConsent, error) { return nil, errors.New("private state error") }
	if _, err := f.run("identity"); err == nil {
		t.Fatal("corrupt consent accepted")
	}
}
