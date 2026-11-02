package alarmdelivery

import (
	"context"
	"errors"
	"localrmm/internal/operatorauth"
	"strings"
	"sync"
	"testing"
	"time"
)

type authorityQueueFixture struct {
	attempt *Attempt
	results []Result
}

func (q *authorityQueueFixture) ClaimAlarm(context.Context, Binding, time.Time) (*Attempt, error) {
	return q.attempt, nil
}
func (q *authorityQueueFixture) CompleteAlarm(_ context.Context, _ Binding, _ Attempt, r Result, _ time.Time) error {
	q.results = append(q.results, r)
	return nil
}

type authorityTransport func(context.Context, Payload) Result

func (f authorityTransport) Send(ctx context.Context, p Payload) Result { return f(ctx, p) }
func testAuthorityWorker(t *testing.T, transport Transport) (*Worker, *authorityQueueFixture) {
	t.Helper()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	q := &authorityQueueFixture{attempt: &Attempt{Payload: NewTestPayload(strings.Repeat("a", 64), at), Number: 1, TestActor: "operator_00000000000000000000000000000001", AuthorityEpoch: 1}}
	b := Binding{ManagerInstanceID: "manager-fixture", Profile: "tls", DestinationID: "recipient", Generation: "generation", Fingerprint: strings.Repeat("a", 64)}
	w, e := NewWorker(q, b, transport, func() time.Time { return at })
	if e != nil {
		t.Fatal(e)
	}
	return w, q
}
func TestQueuedTestAlarmRevocationAndRegrantNeverSend(t *testing.T) {
	for _, epoch := range []uint64{0, 2, 3} {
		t.Run(strings.Repeat("x", int(epoch)+1), func(t *testing.T) {
			sends := 0
			w, q := testAuthorityWorker(t, authorityTransport(func(context.Context, Payload) Result { sends++; return Result{Outcome: Accepted} }))
			if e := w.ConfigureAccountAuthority(func(ctx context.Context, actor string, receipt uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
				if actor != q.attempt.TestActor || receipt != epoch || epoch == 0 || len(caps) != 1 || caps[0] != operatorauth.ManageAlarms {
					return ctx, nil, operatorauth.ErrForbidden
				}
				return ctx, func() {}, nil
			}); e != nil {
				t.Fatal(e)
			}
			if e := w.Step(context.Background()); e != nil {
				t.Fatal(e)
			}
			if sends != 0 || len(q.results) != 1 || q.results[0].Outcome != Failed || q.results[0].Code != "operator_authority_revoked" {
				t.Fatal("revoked queued test sent or remained retryable")
			}
		})
	}
}
func TestTestAlarmLeaseCoversProviderSend(t *testing.T) {
	var gate sync.RWMutex
	entered, finish := make(chan struct{}), make(chan struct{})
	w, q := testAuthorityWorker(t, authorityTransport(func(ctx context.Context, _ Payload) Result {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("provider send has no deadline")
		}
		close(entered)
		<-finish
		return Result{Outcome: Accepted}
	}))
	released := make(chan struct{})
	if e := w.ConfigureAccountAuthority(func(ctx context.Context, _ string, _ uint64, _ ...operatorauth.Capability) (context.Context, func(), error) {
		gate.RLock()
		return ctx, func() { gate.RUnlock(); close(released) }, nil
	}); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- w.Step(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("send not reached")
	}
	if gate.TryLock() {
		gate.Unlock()
		t.Fatal("send escaped its authority lease")
	}
	close(finish)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish")
	}
	select {
	case <-released:
	default:
		t.Fatal("lease not released")
	}
	if len(q.results) != 1 || q.results[0].Outcome != Accepted {
		t.Fatal("provider outcome lost")
	}
}
func TestOperationalAlarmDoesNotInheritAccountRevocation(t *testing.T) {
	sends, calls := 0, 0
	w, q := testAuthorityWorker(t, authorityTransport(func(context.Context, Payload) Result { sends++; return Result{Outcome: Accepted} }))
	q.attempt.Payload.SchemaVersion = "tracebolt.alarm.v1"
	q.attempt.Payload.Rule = "root-filesystem"
	q.attempt.Payload.Transition = "opened"
	if e := w.ConfigureAccountAuthority(func(ctx context.Context, _ string, _ uint64, _ ...operatorauth.Capability) (context.Context, func(), error) {
		calls++
		return ctx, nil, errors.New("revoked")
	}); e != nil {
		t.Fatal(e)
	}
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if calls != 0 || sends != 1 {
		t.Fatal("committed operational monitoring tied to historical actor")
	}
}
func TestUnboundAndDowngradedTestReceiptsFailClosed(t *testing.T) {
	sends := 0
	w, q := testAuthorityWorker(t, authorityTransport(func(context.Context, Payload) Result { sends++; return Result{Outcome: Accepted} }))
	// No live callback must not let an existing live receipt run as a static test.
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if sends != 0 {
		t.Fatal("live receipt dispatched without authority policy")
	}
	q.attempt.AuthorityEpoch = 0
	q.attempt.TestActor = ""
	if e := w.ConfigureAccountAuthority(func(ctx context.Context, actor string, epoch uint64, _ ...operatorauth.Capability) (context.Context, func(), error) {
		if actor == "" || epoch == 0 {
			return ctx, nil, operatorauth.ErrForbidden
		}
		return ctx, func() {}, nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if sends != 0 {
		t.Fatal("legacy test silently promoted into live authority")
	}
}
func TestRetryableTestAlarmRechecksOriginalEpoch(t *testing.T) {
	sends := 0
	allowed := true
	w, q := testAuthorityWorker(t, authorityTransport(func(context.Context, Payload) Result { sends++; return Result{Outcome: Retryable} }))
	if e := w.ConfigureAccountAuthority(func(ctx context.Context, _ string, epoch uint64, _ ...operatorauth.Capability) (context.Context, func(), error) {
		if !allowed || epoch != 1 {
			return ctx, nil, operatorauth.ErrForbidden
		}
		return ctx, func() {}, nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	allowed = false
	q.attempt.Number = 2
	if e := w.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	if sends != 1 || len(q.results) != 2 || q.results[1].Outcome != Failed {
		t.Fatal("retry renewed operator authority")
	}
}
