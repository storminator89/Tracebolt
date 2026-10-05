package actionclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

func fixturePermit(t *testing.T) []byte {
	t.Helper()
	d := actionpermit.Digest([]byte("fixture"))
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: "fixture.service", UnitPolicyDigest: d}
	pd, _ := actionpermit.PlanDigest(plan)
	p := actionpermit.Permit{Version: actionpermit.Version, ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: d, EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d, JobID: "action_" + strings.Repeat("3", 32), Sequence: 1, Plan: plan, PlanDigest: pd, OperatorID: "operator_" + strings.Repeat("4", 32), ApprovalDigest: d, RootPolicyDigest: d, IssuedAt: 1700000000, NotBefore: 1700000000, StartDeadline: 1700000060}
	raw, err := actionpermit.Encode(p, make([]byte, ed25519.SignatureSize))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func fixtureResult(t *testing.T, raw []byte) *actionhelper.Result {
	t.Helper()
	p, err := actionpermit.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &actionhelper.Result{JobID: p.JobID, Sequence: p.Sequence, EnvelopeDigest: actionpermit.Digest(raw), Phase: actionstate.OperationCompleted, ConsumedAt: 1700000000000000, DispatchAt: 1700000000000001, TransitionAt: 1700000000000002, Outcome: actionstate.OutcomeCompleted, ObservedState: actionstate.ObservedActive}
}
func fixtureCapabilities() actionhelper.Capabilities {
	d := actionpermit.Digest([]byte("fixture"))
	return actionhelper.Capabilities{Version: actionhelper.CapabilitiesVersion, Enabled: false, ManagerID: "manager_" + strings.Repeat("1", 32), KeyID: d, EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: d, RootPolicyDigest: d, TransportProfile: actionhelper.ProductionTLS, CapturedAt: 1700000000, MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: d}}}
}
func responseFrame(t *testing.T, r actionhelper.Response) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return rawFrame(b)
}
func rawFrame(b []byte) []byte {
	h := make([]byte, 8)
	copy(h, "TBA1")
	binary.BigEndian.PutUint32(h[4:], uint32(len(b)))
	return append(h, b...)
}

func fixtureClient(t *testing.T, request actionhelper.Request, reply []byte) (Client, *atomic.Int32) {
	t.Helper()
	wire, err := actionhelper.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	c := Client{now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
	c.connect = func(ctx context.Context) (connection, error) {
		calls.Add(1)
		server, client := net.Pipe()
		wg.Go(func() {
			defer server.Close()
			received := make([]byte, len(wire))
			if _, err := io.ReadFull(server, received); err != nil {
				return
			}
			if !bytes.Equal(received, wire) {
				t.Error("request bytes changed")
			}
			if len(reply) > 0 {
				_, _ = server.Write(reply)
			}
		})
		return connection{Conn: client, reader: client, recheck: func() error { return nil }, close: func() {}}, nil
	}
	return c, &calls
}

func TestClientCapabilitiesPreserveDefaultOffAndOriginalTime(t *testing.T) {
	caps := fixtureCapabilities()
	reply := responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Capabilities: &caps})
	c, calls := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation}, reply)
	var times atomic.Int32
	c.now = func() time.Time {
		if times.Add(1) == 1 {
			return time.Unix(caps.CapturedAt, 0).UTC()
		}
		return time.Unix(caps.CapturedAt+3, 0).UTC()
	}
	got, err := c.Capabilities(context.Background())
	if err != nil || got.Enabled || got.CapturedAt != caps.CapturedAt || calls.Load() != 1 {
		t.Fatal(got, err, calls.Load())
	}
}
func TestClientCapabilitiesRejectOldFutureOrReversedClock(t *testing.T) {
	for _, kind := range []string{"stale", "future", "reversed"} {
		t.Run(kind, func(t *testing.T) {
			caps := fixtureCapabilities()
			original := caps.CapturedAt
			if kind == "stale" {
				caps.CapturedAt--
			}
			if kind == "future" {
				caps.CapturedAt++
			}
			c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Capabilities: &caps}))
			var calls int
			c.now = func() time.Time {
				calls++
				if kind == "reversed" && calls == 2 {
					return time.Unix(original-1, 0).UTC()
				}
				return time.Unix(original, 0).UTC()
			}
			if _, err := c.Capabilities(context.Background()); err == nil {
				t.Fatal("capture age refreshed or invalid clock accepted")
			}
		})
	}
}
func TestClientSubmitAndStatusBindExactImmutableEnvelope(t *testing.T) {
	raw := fixturePermit(t)
	result := fixtureResult(t, raw)
	for _, operation := range []string{actionhelper.SubmitOperation, actionhelper.StatusOperation} {
		t.Run(operation, func(t *testing.T) {
			request := actionhelper.Request{Version: actionhelper.RequestVersion, Operation: operation}
			if operation == actionhelper.SubmitOperation {
				request.Envelope = raw
			} else {
				request.JobID = result.JobID
			}
			c, calls := fixtureClient(t, request, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: result}))
			var got actionhelper.Response
			var err error
			if operation == actionhelper.SubmitOperation {
				got, err = c.Submit(context.Background(), raw)
			} else {
				got, err = c.Status(context.Background(), result.JobID, result.EnvelopeDigest)
			}
			if err != nil || got.Result == nil || *got.Result != *result || calls.Load() != 1 {
				t.Fatal(got, err)
			}
		})
	}
	for _, kind := range []string{"job", "digest", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			bad := *result
			switch kind {
			case "job":
				bad.JobID = "action_" + strings.Repeat("a", 32)
			case "digest":
				bad.EnvelopeDigest = actionpermit.Digest([]byte("other"))
			case "sequence":
				bad.Sequence++
			}
			c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: &bad}))
			if _, err := c.Submit(context.Background(), raw); !errors.Is(err, ErrUncertain) {
				t.Fatal("mismatched result trusted", err)
			}
		})
	}
	bad := *result
	bad.EnvelopeDigest = actionpermit.Digest([]byte("other"))
	c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.StatusOperation, JobID: result.JobID}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: &bad}))
	if _, err := c.Status(context.Background(), result.JobID, result.EnvelopeDigest); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
}
func TestClientLostOrMalformedSubmitResponseNeverRetries(t *testing.T) {
	raw := fixturePermit(t)
	result := fixtureResult(t, raw)
	good := responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: result})
	huge := append([]byte(nil), good[:8]...)
	binary.BigEndian.PutUint32(huge[4:], actionhelper.MaxResponseBytes+1)
	duplicate := bytes.Replace(good[8:], []byte(`"phase":`), []byte(`"arbitrary":true,"phase":`), 1)
	for name, reply := range map[string][]byte{"lost": nil, "partial": good[:len(good)-1], "trailing": append(bytes.Clone(good), 'x'), "second_frame": append(bytes.Clone(good), good...), "oversize": huge, "unknown_field": rawFrame(duplicate)} {
		t.Run(name, func(t *testing.T) {
			c, calls := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw}, reply)
			if _, err := c.Submit(context.Background(), raw); !errors.Is(err, ErrUncertain) || calls.Load() != 1 {
				t.Fatal("lost response retried or certain", err, calls.Load())
			}
		})
	}
}
func TestClientStructuredDenialAndOperationConfusion(t *testing.T) {
	raw := fixturePermit(t)
	for _, reason := range []string{"denied", "busy", "expired", "conflict", "unavailable"} {
		t.Run(reason, func(t *testing.T) {
			c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Error: reason}))
			r, err := c.Submit(context.Background(), raw)
			if err != nil || r.Error != reason || r.Result != nil {
				t.Fatal(r, err)
			}
		})
	}
	caps := fixtureCapabilities()
	c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Capabilities: &caps}))
	if _, err := c.Submit(context.Background(), raw); !errors.Is(err, ErrUncertain) {
		t.Fatal("unexpected capabilities accepted", err)
	}
	c, _ = fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: fixtureResult(t, raw)}))
	if _, err := c.Capabilities(context.Background()); err == nil {
		t.Fatal("unexpected result accepted")
	}
}
func TestClientRechecksProtectedConnectionAfterResponse(t *testing.T) {
	raw := fixturePermit(t)
	c, _ := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: fixtureResult(t, raw)}))
	connect := c.connect
	c.connect = func(ctx context.Context) (connection, error) {
		conn, err := connect(ctx)
		checks := 0
		conn.recheck = func() error {
			checks++
			if checks == 2 {
				return ErrRejected
			}
			return nil
		}
		return conn, err
	}
	if _, err := c.Submit(context.Background(), raw); !errors.Is(err, ErrUncertain) {
		t.Fatal("changed socket trusted", err)
	}
}
func TestClientCallerDeadlineAndCancellationBoundStalledResponse(t *testing.T) {
	for _, kind := range []string{"deadline", "cancel", "no_eof"} {
		t.Run(kind, func(t *testing.T) {
			raw := fixturePermit(t)
			wire, _ := actionhelper.EncodeRequest(actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: raw})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			var wg sync.WaitGroup
			defer wg.Wait()
			var calls atomic.Int32
			c := Client{connect: func(context.Context) (connection, error) {
				calls.Add(1)
				a, b := net.Pipe()
				wg.Go(func() {
					defer a.Close()
					buf := make([]byte, len(wire))
					if _, err := io.ReadFull(a, buf); err != nil {
						return
					}
					if kind == "cancel" {
						cancel()
					}
					if kind == "no_eof" {
						_, _ = a.Write(responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Result: fixtureResult(t, raw)}))
					}
					<-ctx.Done()
				})
				return connection{Conn: b, reader: b, recheck: func() error { return nil }, close: func() {}}, nil
			}}
			start := time.Now()
			if _, err := c.Submit(ctx, raw); !errors.Is(err, ErrUncertain) || calls.Load() != 1 {
				t.Fatal(err, calls.Load())
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("caller deadline ignored")
			}
		})
	}
}
func TestClientRejectsInvalidInputBeforeConnecting(t *testing.T) {
	c := Client{connect: func(context.Context) (connection, error) {
		t.Fatal("invalid input connected")
		return connection{}, ErrRejected
	}}
	if _, err := c.Submit(context.Background(), []byte("arbitrary")); err == nil {
		t.Fatal("bad permit accepted")
	}
	if _, err := c.Status(context.Background(), "invalid", actionpermit.Digest(nil)); err == nil {
		t.Fatal("bad job accepted")
	}
	if _, err := c.Status(context.Background(), "action_"+strings.Repeat("1", 32), "invalid"); err == nil {
		t.Fatal("bad digest accepted")
	}
	if _, err := c.Capabilities(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Capabilities(ctx); err == nil {
		t.Fatal("canceled context accepted")
	}
}
func TestClientConcurrentReadOnlyCalls(t *testing.T) {
	caps := fixtureCapabilities()
	c, calls := fixtureClient(t, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation}, responseFrame(t, actionhelper.Response{Version: actionhelper.ResponseVersion, Capabilities: &caps}))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			if _, err := c.Capabilities(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 16 {
		t.Fatal(calls.Load())
	}
}
