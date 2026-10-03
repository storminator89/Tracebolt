package enrollmentstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

const testNow = int64(1800000000)

func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }
func hash(n int) string              { return fmt.Sprintf("%064x", n) }
func binding() Binding {
	return Binding{InstanceID: id("manager", 1), Origin: "https://manager.example", Profile: "tls", CollectionProfile: "basic-readonly-v1", IssuerFingerprint: hash(1)}
}
func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(DefaultConfig(binding()))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func createCommand(n int) CreateCommand {
	return CreateCommand{InvitationID: id("invite", n), RequestID: id("request", n*100), InvitationHash: hash(n), Platform: "linux", Now: testNow}
}
func create(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	s, err := e.CreateInvitation(context.Background(), createCommand(n))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func control(s Snapshot, n int) Control {
	return Control{InvitationID: s.InvitationID, RequestID: id("request", n), ExpectedRevision: s.Revision, Now: s.UpdatedAt + 1}
}
func unchanged(t *testing.T, e *Engine, before Snapshot) {
	t.Helper()
	after, err := e.Get(before.InvitationID)
	if err != nil || after != before {
		t.Fatalf("mutation on failure: %v\n%+v\n%+v", err, before, after)
	}
}

// Real claim proofs establish bindings; issued/activated fixtures below isolate
// terminal transitions. The end-to-end tests also verify real signing results.
func pending(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	f := newClaimFixture(t, n)
	s := f.create(t, e)
	out, err := e.Claim(context.Background(), f.command(s, testNow+1), f.proof(t, testNow+1))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func approved(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	s := pending(t, e, n)
	out, err := e.Approve(context.Background(), ApproveCommand{Control: control(s, n*100+2), DeviceID: id("agent", n), KeyFingerprint: s.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func intentCommand(s Snapshot, n int) IntentCommand {
	return IntentCommand{Control: control(s, n*100+3), IntentID: id("intent", n), SerialHex: fmt.Sprintf("%032x", n), TemplateVersion: TemplateVersion, NotBefore: s.UpdatedAt, NotAfter: s.UpdatedAt + MaxCertificateTTL}
}
func intended(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	s := approved(t, e, n)
	out, err := e.BeginIssuance(context.Background(), intentCommand(s, n))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func issued(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	s := intended(t, e, n)
	s.State = Issued
	s.Revision++
	s.UpdatedAt++
	s.Issuance = Issuance{RequestID: id("request", n*100+4), CertificateHash: hash(n + 400), At: s.UpdatedAt}
	if ValidateSnapshot(s) != nil {
		t.Fatal("invalid fixture")
	}
	r := e.records[s.InvitationID]
	r.snapshot = s
	e.records[s.InvitationID] = r
	return s
}
func activated(t *testing.T, e *Engine, n int) Snapshot {
	t.Helper()
	s := issued(t, e, n)
	s.State = Activated
	s.Revision++
	s.UpdatedAt++
	s.Activation = Activation{RequestID: id("request", n*100+5), At: s.UpdatedAt}
	if ValidateSnapshot(s) != nil {
		t.Fatal("invalid fixture")
	}
	r := e.records[s.InvitationID]
	r.snapshot = s
	e.records[s.InvitationID] = r
	return s
}

func TestConfigurationAndCanonicalBinding(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"zero": func(c *Config) { *c = Config{} }, "record overflow": func(c *Config) { c.RecordLimit = MaxRecords + 1 }, "invite overflow": func(c *Config) { c.InvitationLimit = MaxInvitations + 1 }, "pending overflow": func(c *Config) { c.PendingLimit = MaxPending + 1 }, "ttl overflow": func(c *Config) { c.InvitationTTL = MaxInvitationTTL + 1 }, "pending ttl overflow": func(c *Config) { c.PendingTTL = MaxPendingTTL + 1 }, "negative ttl": func(c *Config) { c.PendingTTL = -1 },
		"uppercase ID": func(c *Config) { c.Binding.InstanceID = "manager_" + strings.Repeat("A", 32) }, "zero ID": func(c *Config) { c.Binding.InstanceID = id("manager", 0) }, "unknown profile": func(c *Config) { c.Binding.Profile = "tls2" }, "unknown collection": func(c *Config) { c.Binding.CollectionProfile = "full-inventory" }, "wrong scheme": func(c *Config) { c.Binding.Origin = "http://manager.example" }, "uppercase host": func(c *Config) { c.Binding.Origin = "https://MANAGER.example" }, "default port": func(c *Config) { c.Binding.Origin = "https://manager.example:443" }, "path": func(c *Config) { c.Binding.Origin += "/" }, "query": func(c *Config) { c.Binding.Origin += "?" }, "fragment": func(c *Config) { c.Binding.Origin += "#x" }, "credentials": func(c *Config) { c.Binding.Origin = "https://user@manager.example" }, "zone": func(c *Config) { c.Binding.Origin = "https://[fe80::1%25eth0]" }, "bad issuer": func(c *Config) { c.Binding.IssuerFingerprint = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfig(binding())
			change(&c)
			if _, err := New(c); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
	for _, origin := range []string{"https://manager.example", "https://manager.example:8443", "https://127.0.0.1", "https://[::1]:8443"} {
		c := DefaultConfig(binding())
		c.Binding.Origin = origin
		if _, err := New(c); err != nil {
			t.Fatalf("valid origin %q: %v", origin, err)
		}
	}
	c := DefaultConfig(binding())
	c.Binding.Profile = "http-test"
	c.Binding.Origin = "http://127.0.0.1:8080"
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRetryImmutableSnapshotsAndNoVerifierDisclosure(t *testing.T) {
	e := engine(t)
	secret := "an-invitation-token-that-never-enters-the-state-API"
	h := sha256.Sum256([]byte(secret))
	c := createCommand(1)
	c.InvitationHash = hex.EncodeToString(h[:])
	s, err := e.CreateInvitation(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.Now++
	again, err := e.CreateInvitation(context.Background(), c)
	if err != nil || again != s {
		t.Fatalf("retry changed result: %v", err)
	}
	for _, v := range []any{e, s, e.Snapshots()} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{string(b), fmt.Sprintf("%v %+v %#v %x", v, v, v, v)} {
			if strings.Contains(text, secret) || strings.Contains(text, c.InvitationHash) {
				t.Fatal("disclosed verifier or secret")
			}
		}
	}
	copy := s
	copy.Claim.KeyFingerprint = hash(777)
	copy.Binding.Profile = "http-test"
	list := e.Snapshots()
	list[0] = copy
	unchanged(t, e, s)
	c.InvitationHash = hash(33)
	if _, err := e.CreateInvitation(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	c = createCommand(2)
	c.RequestID = s.CreateRequestID
	if _, err := e.CreateInvitation(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	c = createCommand(2)
	c.InvitationHash = hex.EncodeToString(h[:])
	if _, err := e.CreateInvitation(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal("reused invitation verifier", err)
	}
}

func TestApprovalCASAndExactRetry(t *testing.T) {
	e := engine(t)
	s := pending(t, e, 1)
	c := ApproveCommand{Control: control(s, 102), DeviceID: id("agent", 1), KeyFingerprint: hash(999)}
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	c.KeyFingerprint = s.Claim.KeyFingerprint
	c.Control.ExpectedRevision = 1
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	c.Control.ExpectedRevision = s.Revision
	out, err := e.Approve(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.Control.Now++
	retry, err := e.Approve(context.Background(), c)
	if err != nil || retry != out {
		t.Fatalf("retry %v", err)
	}
	c.DeviceID = id("agent", 2)
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, out)
	s2 := pending(t, e, 2)
	if _, err := e.Approve(context.Background(), ApproveCommand{Control: control(s2, 202), DeviceID: out.Approval.DeviceID, KeyFingerprint: s2.Claim.KeyFingerprint}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s2)
}

func TestIntentImmutableSerialUniquenessAndNoAdvanceRetry(t *testing.T) {
	e := engine(t)
	s := approved(t, e, 1)
	c := intentCommand(s, 1)
	out, err := e.BeginIssuance(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.Control.Now += 400
	retry, err := e.BeginIssuance(context.Background(), c)
	if err != nil || retry != out {
		t.Fatalf("retry: %v", err)
	}
	c.NotAfter--
	if _, err := e.BeginIssuance(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, out)
	i, err := e.SigningIntent(out.InvitationID, out.UpdatedAt)
	if err != nil || i.DeviceID != out.Approval.DeviceID || i.IssuerFingerprint != binding().IssuerFingerprint || i.KeyGeneration != 1 {
		t.Fatalf("intent: %+v %v", i, err)
	}
	i.DeviceID = id("agent", 999)
	i2, _ := e.SigningIntent(out.InvitationID, out.UpdatedAt)
	if i2.DeviceID == i.DeviceID {
		t.Fatal("mutable intent")
	}
	s2 := approved(t, e, 2)
	c2 := intentCommand(s2, 2)
	c2.SerialHex = out.Intent.SerialHex
	if _, err := e.BeginIssuance(context.Background(), c2); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s2)
	if _, err := e.Approve(context.Background(), ApproveCommand{Control: Control{InvitationID: out.InvitationID, RequestID: out.Approval.RequestID, ExpectedRevision: 2, Now: out.UpdatedAt}, DeviceID: out.Approval.DeviceID, KeyFingerprint: out.Approval.KeyFingerprint}); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}

func TestIntentExpiryUsesEarlierCertificateDeadline(t *testing.T) {
	e := engine(t)
	s := approved(t, e, 1)
	c := intentCommand(s, 1)
	c.NotAfter = c.Control.Now + 10
	out, err := e.BeginIssuance(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.Control.Now = c.NotAfter
	if _, err := e.BeginIssuance(context.Background(), c); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if _, err := e.SigningIntent(out.InvitationID, c.NotAfter); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	unchanged(t, e, out)
	tc := control(out, 190)
	tc.Now = c.NotAfter
	if _, err := e.Terminate(context.Background(), TerminalCommand{Control: tc, State: Expired}); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryAndTerminalTransitionMatrix(t *testing.T) {
	builders := []struct {
		name  string
		build func(*testing.T, *Engine, int) Snapshot
	}{{"created", create}, {"pending", pending}, {"approved", approved}, {"intent", intended}, {"issued", issued}, {"activated", activated}}
	for _, b := range builders {
		for _, target := range []State{Expired, Canceled, Rejected, Revoked} {
			t.Run(b.name+"/"+string(target), func(t *testing.T) {
				e := engine(t)
				s := b.build(t, e, 1)
				c := TerminalCommand{Control: control(s, 190), State: target}
				if target == Expired {
					c.Control.Now = deadline(s)
				}
				allowed := target == Expired || target == Canceled && s.State != Activated || target == Rejected && s.State == ClaimedPending || target == Revoked && stage(s.State) >= 3
				out, err := e.Terminate(context.Background(), c)
				if !allowed {
					if !errors.Is(err, ErrState) {
						t.Fatalf("got %v", err)
					}
					unchanged(t, e, s)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if out.State != target || out.Termination.From != s.State || out.Revision != s.Revision+1 {
					t.Fatal("bad terminal outcome")
				}
				c.Control.Now++
				retry, err := e.Terminate(context.Background(), c)
				if err != nil || retry != out {
					t.Fatalf("retry %v", err)
				}
				c.State = Canceled
				if target == Canceled {
					c.State = Revoked
				}
				if _, err := e.Terminate(context.Background(), c); !errors.Is(err, ErrState) {
					t.Fatal(err)
				}
				unchanged(t, e, out)
				if _, err := e.Claim(context.Background(), ClaimCommand{Control: Control{InvitationID: out.InvitationID, RequestID: id("request", 199), ExpectedRevision: out.Revision, Now: out.UpdatedAt}, ClaimID: id("claim", 99)}, enrollmentcrypto.VerifiedClaim{}); !errors.Is(err, ErrState) {
					t.Fatal(err)
				}
			})
		}
	}
	e := engine(t)
	s := pending(t, e, 1)
	c := ApproveCommand{Control: control(s, 102), DeviceID: id("agent", 1), KeyFingerprint: s.Claim.KeyFingerprint}
	c.Control.Now = s.DeadlineAt
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	if _, err := e.Terminate(context.Background(), TerminalCommand{Control: control(s, 190), State: Expired}); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
}

func TestQuotaTombstonesNeverEvicted(t *testing.T) {
	c := DefaultConfig(binding())
	c.RecordLimit = 2
	c.InvitationLimit = 1
	c.PendingLimit = 1
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	s := create(t, e, 1)
	if _, err := e.CreateInvitation(context.Background(), createCommand(2)); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if _, err := e.Terminate(context.Background(), TerminalCommand{Control: control(s, 190), State: Canceled}); err != nil {
		t.Fatal(err)
	}
	s = create(t, e, 2)
	if _, err := e.Terminate(context.Background(), TerminalCommand{Control: control(s, 290), State: Canceled}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CreateInvitation(context.Background(), createCommand(3)); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if len(e.Snapshots()) != 2 {
		t.Fatal("tombstones evicted")
	}
}

type cancelAtCommit struct{ calls atomic.Int32 }

func (*cancelAtCommit) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*cancelAtCommit) Done() <-chan struct{}       { return nil }
func (*cancelAtCommit) Value(any) any               { return nil }
func (c *cancelAtCommit) Err() error {
	if c.calls.Add(1) >= 3 {
		return context.Canceled
	}
	return nil
}

func TestCancellationClockAndRevisionExhaustionNoMutation(t *testing.T) {
	e := engine(t)
	s := pending(t, e, 1)
	c := ApproveCommand{Control: control(s, 102), DeviceID: id("agent", 1), KeyFingerprint: s.Claim.KeyFingerprint}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Approve(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	if _, err := e.Approve(&cancelAtCommit{}, c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	c.Control.Now = s.UpdatedAt - 1
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	c.Control.Now = s.UpdatedAt
	r := e.records[s.InvitationID]
	r.snapshot.Revision = MaxRevision
	e.records[s.InvitationID] = r
	s = r.snapshot
	c.Control.ExpectedRevision = MaxRevision
	if _, err := e.Approve(context.Background(), c); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	if _, err := e.Approve(nil, c); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestConcurrentCreateAndApprove(t *testing.T) {
	e := engine(t)
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := e.CreateInvitation(context.Background(), createCommand(1))
			if err != nil || s.Revision != 1 {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 || len(e.Snapshots()) != 1 {
		t.Fatal("create retry race")
	}
	e = engine(t)
	s := pending(t, e, 1)
	var winners atomic.Int32
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := e.Approve(context.Background(), ApproveCommand{Control: control(s, 1000+n), DeviceID: id("agent", 1000+n), KeyFingerprint: s.Claim.KeyFingerprint})
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				failures.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if winners.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("winners %d failures %d", winners.Load(), failures.Load())
	}
}

func TestZeroOpaqueProofsAndUnsupportedOperations(t *testing.T) {
	e := engine(t)
	s := create(t, e, 1)
	if _, err := e.Claim(context.Background(), ClaimCommand{Control: control(s, 101), ClaimID: id("claim", 1)}, enrollmentcrypto.VerifiedClaim{}); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	e = engine(t)
	s = intended(t, e, 1)
	if _, err := e.CommitIssued(context.Background(), control(s, 104), enrollmentcrypto.VerifiedCertificate{}); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	e = engine(t)
	s = issued(t, e, 1)
	if _, err := e.Activate(context.Background(), control(s, 105), enrollmentcrypto.VerifiedActivation{}); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, s)
	for _, err := range []error{e.Renew(context.Background()), e.Recover(context.Background()), e.Migrate(context.Background())} {
		if !errors.Is(err, ErrNotImplemented) {
			t.Fatal(err)
		}
	}
}
