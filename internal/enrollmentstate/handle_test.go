package enrollmentstate

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
)

func TestEnginePointerAndValueRedactDiagnostics(t *testing.T) {
	e := engine(t)
	s := pending(t, e, 1)
	for _, value := range []any{e, *e} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x"} {
			out := fmt.Sprintf(format, value)
			if out != "enrollment state (contents redacted; non-durable)" || strings.Contains(out, s.InvitationID) || strings.Contains(out, s.Claim.KeyFingerprint) {
				t.Fatalf("unredacted %T with %s: %q", value, format, out)
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"contentsRedacted":true,"durable":false}` {
			t.Fatalf("unredacted JSON for %T: %s %v", value, raw, err)
		}
	}
	if (*e).GoString() != "enrollmentstate.Engine{contents:redacted}" {
		t.Fatal("GoString must redact the handle value")
	}
}

func TestCopiedEngineSharesStateAndMutex(t *testing.T) {
	e := engine(t)
	copy := *e
	var wg sync.WaitGroup
	var bad atomic.Int32
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			handle := e
			if n%2 == 1 {
				handle = &copy
			}
			s, err := handle.CreateInvitation(context.Background(), createCommand(1))
			if err != nil || s.Revision != 1 {
				bad.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if bad.Load() != 0 || len(e.Snapshots()) != 1 || len(copy.Snapshots()) != 1 {
		t.Fatal("copied handle does not share synchronized state")
	}
	s, err := copy.Get(id("invite", 1))
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.Terminate(context.Background(), TerminalCommand{Control: control(s, 190), State: Canceled})
	if err != nil {
		t.Fatal(err)
	}
	got, err := copy.Get(s.InvitationID)
	if err != nil || got != out {
		t.Fatal("copied handle saw different state")
	}
}

func TestZeroAndNilEnginesFailClosed(t *testing.T) {
	var zero Engine
	var nilEngine *Engine
	c := Control{InvitationID: id("invite", 1), RequestID: id("request", 1), ExpectedRevision: 1, Now: testNow}
	for _, e := range []*Engine{&zero, nilEngine} {
		assertInvalid := func(err error) {
			t.Helper()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("uninitialized engine returned %v", err)
			}
		}
		_, err := e.Get(c.InvitationID)
		assertInvalid(err)
		_, err = e.CreateInvitation(context.Background(), createCommand(1))
		assertInvalid(err)
		_, err = e.Claim(context.Background(), ClaimCommand{Control: c, ClaimID: id("claim", 1)}, enrollmentcrypto.VerifiedClaim{})
		assertInvalid(err)
		_, err = e.Approve(context.Background(), ApproveCommand{Control: c, DeviceID: id("agent", 1), KeyFingerprint: hash(1)})
		assertInvalid(err)
		_, err = e.BeginIssuance(context.Background(), IntentCommand{Control: c, IntentID: id("intent", 1), SerialHex: strings.Repeat("1", 32), TemplateVersion: TemplateVersion, NotBefore: testNow, NotAfter: testNow + 60})
		assertInvalid(err)
		_, err = e.SigningIntent(c.InvitationID, testNow)
		assertInvalid(err)
		_, err = e.CommitIssued(context.Background(), c, enrollmentcrypto.VerifiedCertificate{})
		assertInvalid(err)
		_, err = e.Activate(context.Background(), c, enrollmentcrypto.VerifiedActivation{})
		assertInvalid(err)
		_, err = e.Terminate(context.Background(), TerminalCommand{Control: c, State: Canceled})
		assertInvalid(err)
		if len(e.Snapshots()) != 0 {
			t.Fatal("uninitialized engine exported records")
		}
		for _, err := range []error{e.Renew(context.Background()), e.Recover(context.Background()), e.Migrate(context.Background())} {
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatal(err)
			}
		}
	}
	for _, value := range []any{zero, &zero} {
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("zero handle was not redacted")
		}
		if _, err := json.Marshal(value); err != nil {
			t.Fatal(err)
		}
	}
}
