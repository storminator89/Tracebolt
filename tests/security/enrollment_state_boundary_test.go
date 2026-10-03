package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

const independentEnrollmentNow = int64(1800000000)

func independentEnrollmentID(prefix string, n int) string {
	return fmt.Sprintf("%s_%032x", prefix, n)
}

func independentEnrollmentConfig() enrollmentstate.Config {
	return enrollmentstate.DefaultConfig(enrollmentstate.Binding{
		InstanceID: independentEnrollmentID("manager", 1), Origin: "https://manager.example",
		Profile: "tls", CollectionProfile: "basic-readonly-v1", IssuerFingerprint: strings.Repeat("a", 64),
	})
}

func independentEnrollmentCreate(n int) enrollmentstate.CreateCommand {
	return enrollmentstate.CreateCommand{InvitationID: independentEnrollmentID("invite", n),
		RequestID: independentEnrollmentID("request", n), InvitationHash: fmt.Sprintf("%064x", n),
		Platform: "linux", Now: independentEnrollmentNow}
}

func independentEnrollmentEngine(t *testing.T, cfg enrollmentstate.Config) *enrollmentstate.Engine {
	t.Helper()
	e, err := enrollmentstate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestIndependentEnrollmentStateCopiedHandleAndRedaction(t *testing.T) {
	e := independentEnrollmentEngine(t, independentEnrollmentConfig())
	c := independentEnrollmentCreate(1)
	c.InvitationHash = strings.Repeat("bd", 32)
	s, err := e.CreateInvitation(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := *e
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := copyHandle.CreateInvitation(context.Background(), independentEnrollmentCreate(n+10))
			if err != nil {
				t.Error(err)
			}
			for _, v := range []any{e, *e, &copyHandle, copyHandle} {
				for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
					text := fmt.Sprintf(f, v)
					if !strings.Contains(text, "redacted") || strings.Contains(text, c.InvitationHash) {
						t.Error("engine formatting did not preserve redaction")
					}
				}
				raw, err := json.Marshal(v)
				if err != nil || string(raw) != `{"contentsRedacted":true,"durable":false}` {
					t.Error("engine JSON did not preserve redaction")
				}
			}
		}(i)
	}
	wg.Wait()
	if len(e.Snapshots()) != 13 {
		t.Fatal("copying the handle forked mutable state")
	}
	list := copyHandle.Snapshots()
	list[0].State = enrollmentstate.Activated
	s.State = enrollmentstate.Activated
	got, err := e.Get(c.InvitationID)
	if err != nil || got.State != enrollmentstate.Created {
		t.Fatal("caller snapshot mutation affected engine")
	}
}

func TestIndependentEnrollmentStateRejectsEmptyProofsWithoutMutation(t *testing.T) {
	e := independentEnrollmentEngine(t, independentEnrollmentConfig())
	s, err := e.CreateInvitation(context.Background(), independentEnrollmentCreate(1))
	if err != nil {
		t.Fatal(err)
	}
	c := enrollmentstate.Control{InvitationID: s.InvitationID, RequestID: independentEnrollmentID("request", 100), ExpectedRevision: s.Revision, Now: s.UpdatedAt + 1}
	if _, err = e.Claim(context.Background(), enrollmentstate.ClaimCommand{Control: c, ClaimID: independentEnrollmentID("claim", 1)}, enrollmentcrypto.VerifiedClaim{}); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("empty claim proof was not rejected")
	}
	if _, err = e.CommitIssued(context.Background(), c, enrollmentcrypto.VerifiedCertificate{}); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("empty certificate proof was not rejected")
	}
	if _, err = e.Activate(context.Background(), c, enrollmentcrypto.VerifiedActivation{}); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("empty activation proof was not rejected")
	}
	if _, err = e.SigningIntent(s.InvitationID, c.Now); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("unapproved invitation exposed signing authority")
	}
	got, err := e.Get(s.InvitationID)
	if err != nil || got != s {
		t.Fatal("failed proof changed lifecycle state")
	}
	for _, err := range []error{e.Renew(context.Background()), e.Recover(context.Background()), e.Migrate(context.Background())} {
		if !errors.Is(err, enrollmentstate.ErrNotImplemented) {
			t.Fatal("unsupported lifecycle operation did not fail closed")
		}
	}
}

func TestIndependentEnrollmentStateTerminalRaceAndRetainedCapacity(t *testing.T) {
	cfg := independentEnrollmentConfig()
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 1, 1, 1
	e := independentEnrollmentEngine(t, cfg)
	create := independentEnrollmentCreate(1)
	s, err := e.CreateInvitation(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for n := 1; n <= 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: s.InvitationID, RequestID: independentEnrollmentID("request", 100+n), ExpectedRevision: s.Revision, Now: s.UpdatedAt + 1}, State: enrollmentstate.Canceled}
			_, err := e.Terminate(context.Background(), c)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, enrollmentstate.ErrState) && !errors.Is(err, enrollmentstate.ErrConflict) {
				t.Error("unexpected terminal race error")
			}
		}(n)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("CAS allowed more than one distinct terminal commit")
	}
	got, err := e.Get(s.InvitationID)
	if err != nil || got.State != enrollmentstate.Canceled || got.Revision != s.Revision+1 {
		t.Fatal("terminal state was not retained")
	}
	if _, err := e.CreateInvitation(context.Background(), create); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("old create retry revived a terminated invitation")
	}
	if _, err := e.CreateInvitation(context.Background(), independentEnrollmentCreate(2)); !errors.Is(err, enrollmentstate.ErrCapacity) {
		t.Fatal("terminal tombstone was evicted to admit another invitation")
	}
	reuse := independentEnrollmentCreate(3)
	reuse.InvitationHash = create.InvitationHash
	if _, err := e.CreateInvitation(context.Background(), reuse); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("invitation verifier was reusable across a tombstone")
	}
}

func TestIndependentEnrollmentStateCancellationAndExpiryAreNonmutating(t *testing.T) {
	e := independentEnrollmentEngine(t, independentEnrollmentConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.CreateInvitation(ctx, independentEnrollmentCreate(1)); !errors.Is(err, context.Canceled) || len(e.Snapshots()) != 0 {
		t.Fatal("canceled create changed engine state")
	}
	create := independentEnrollmentCreate(1)
	s, err := e.CreateInvitation(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	create.Now = s.DeadlineAt
	if _, err := e.CreateInvitation(context.Background(), create); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal("expired invitation returned successful retry")
	}
	c := enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: s.InvitationID, RequestID: independentEnrollmentID("request", 100), ExpectedRevision: s.Revision, Now: s.DeadlineAt}, State: enrollmentstate.Expired}
	if _, err := e.Terminate(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled terminal transition was accepted")
	}
	got, err := e.Get(s.InvitationID)
	if err != nil || got != s {
		t.Fatal("failed expiry operation silently mutated state")
	}
	if _, err := e.Terminate(context.Background(), c); err != nil {
		t.Fatal("explicit expiry failed")
	}
}

func TestIndependentEnrollmentStateStrictInspectionJSON(t *testing.T) {
	e := independentEnrollmentEngine(t, independentEnrollmentConfig())
	s, err := e.CreateInvitation(context.Background(), independentEnrollmentCreate(1))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enrollmentstate.EncodeSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := enrollmentstate.DecodeSnapshot(raw); err != nil || got != s {
		t.Fatal("valid snapshot roundtrip failed")
	}
	text := string(raw)
	for name, candidate := range map[string]string{
		"duplicate":   strings.Replace(text, `"revision":1`, `"revision":1,"revision":1`, 1),
		"case alias":  strings.Replace(text, `"revision":1`, `"Revision":1`, 1),
		"null":        strings.Replace(text, `"revision":1`, `"revision":null`, 1),
		"fraction":    strings.Replace(text, `"revision":1`, `"revision":1.5`, 1),
		"missing":     strings.Replace(text, `"revision":1,`, ``, 1),
		"extra":       strings.Replace(text, `"revision":1`, `"revision":1,"authority":true`, 1),
		"trailing":    text + `{}`,
		"oversized":   strings.Repeat(" ", enrollmentstate.MaxJSONBytes) + text,
		"wrong state": strings.Replace(text, `"state":"created"`, `"state":"activated"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := enrollmentstate.DecodeSnapshot([]byte(candidate)); !errors.Is(err, enrollmentstate.ErrInvalid) {
				t.Fatal("invalid inspection contract accepted")
			}
		})
	}
}
