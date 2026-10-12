package windowsmutationfence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
)

func reusableWUAFence(t *testing.T) (*memoryFence, Roster, *atomic.Int64) {
	t.Helper()
	f := &memoryFence{}
	now := &atomic.Int64{}
	now.Store(1800000000)
	p := testPlan()
	p.Version = ReusableWUAPlanVersion
	id, err := beginSetup(context.Background(), p, now.Load(), f.open)
	if err != nil {
		t.Fatal(err)
	}
	r := testRoster(p, id)
	r.Version = ReusableWUARosterVersion
	if err = setupChange(context.Background(), r, nil, now.Load(), f.open); err != nil {
		t.Fatal(err)
	}
	a := testActivation()
	a.Version = ReusableWUAActivationVersion
	if err = setupChange(context.Background(), r, &a, now.Load(), f.open); err != nil {
		t.Fatal(err)
	}
	return f, r, now
}
func successfulReceipt(t *testing.T, c *Capability, now int64) Receipt {
	t.Helper()
	r, e := c.Completion(testDigest(c.owner.JobID+"-result"), "succeeded", now)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestReusableWUAFenceRetirementBeyondLifetimeAndRestart(t *testing.T) {
	f, r, now := reusableWUAFence(t)
	ctx := context.Background()
	s := testSession(t, f, r, CachedWUA, now)
	var first Receipt
	var priorChain string
	for n := uint64(1); n <= 65; n++ {
		c := mustReserve(t, s, testOwner(CachedWUA, n))
		start(t, s, c)
		receipt := successfulReceipt(t, c, now.Load())
		if n == 1 {
			first = receipt
		}
		if e := s.Complete(ctx, c, receipt, exact(receipt)); e != nil {
			t.Fatal(e)
		}
		if e := s.RetireWUA(ctx, receipt, exact(receipt)); e != nil {
			t.Fatal(e)
		}
		state, e := decode(f.raw)
		if e != nil || state.RetiredWUASequence != n || state.RetiredWUADigest == priorChain || state.RetiredWUAReceiptDigest != digest(receipt) || len(state.Entries) != 0 {
			t.Fatal("floor/chain not retained", e)
		}
		priorChain = state.RetiredWUADigest
		before := bytes.Clone(f.raw)
		s.Close()
		s = testSession(t, f, r, CachedWUA, now)
		if e := s.RetireWUA(ctx, receipt, exact(receipt)); e != nil || !bytes.Equal(before, f.raw) {
			t.Fatal("exact latest retirement was not idempotent", e)
		}
		if _, e := s.Reserve(ctx, testOwner(CachedWUA, n)); !errors.Is(e, ErrConsumed) {
			t.Fatal("retired sequence replayed", e)
		}
		if n > 1 {
			if e := s.RetireWUA(ctx, first, exact(first)); !errors.Is(e, ErrConsumed) {
				t.Fatal("older retirement accepted", e)
			}
		}
		now.Add(1)
	}
	// The same v4 roster retains the existing reusable MSI operation.
	m := testSession(t, f, r, ManagedMSI, now)
	c := mustReserve(t, m, testOwner(ManagedMSI, 1))
	start(t, m, c)
	mr := terminal(t, c, now.Load())
	if e := m.Complete(ctx, c, mr, exact(mr)); e != nil {
		t.Fatal(e)
	}
	if e := m.RetireMSI(ctx, mr, exact(mr)); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Reserve(ctx, testOwner(ManagedMSI, 2)); e != nil {
		t.Fatal("MSI reuse lost", e)
	}
}
func TestReusableWUAFenceRequiresSuccessfulExactReleasedReceipt(t *testing.T) {
	for _, kind := range []string{"unreleased", "failure", "wrong-result", "wrong-domain", "verifier", "same-floor-different-receipt"} {
		t.Run(kind, func(t *testing.T) {
			f, r, now := reusableWUAFence(t)
			s := testSession(t, f, r, CachedWUA, now)
			ctx := context.Background()
			c := mustReserve(t, s, testOwner(CachedWUA, 1))
			start(t, s, c)
			receipt := successfulReceipt(t, c, now.Load())
			if kind == "failure" {
				c.receipt = nil
				receipt = terminal(t, c, now.Load())
			}
			if kind != "unreleased" {
				if e := s.Complete(ctx, c, receipt, exact(receipt)); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "same-floor-different-receipt" {
				if e := s.RetireWUA(ctx, receipt, exact(receipt)); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "wrong-result" || kind == "same-floor-different-receipt" {
				receipt.ResultDigest = testDigest("different result")
			}
			if kind == "wrong-domain" {
				receipt.Owner = testOwner(ManagedMSI, 1)
			}
			verify := exact(receipt)
			if kind == "verifier" {
				verify = func(Receipt) error { return ErrIntegrity }
			}
			before := bytes.Clone(f.raw)
			if e := s.RetireWUA(ctx, receipt, verify); e == nil || !bytes.Equal(before, f.raw) {
				t.Fatal("unsafe retirement changed durable evidence", e)
			}
		})
	}
}
func TestReusableWUAFenceCompactionWriteAndCloseUncertainty(t *testing.T) {
	for _, kind := range []string{"write-before-commit", "write-after-commit", "close"} {
		t.Run(kind, func(t *testing.T) {
			f, r, now := reusableWUAFence(t)
			s := testSession(t, f, r, CachedWUA, now)
			ctx := context.Background()
			c := mustReserve(t, s, testOwner(CachedWUA, 1))
			start(t, s, c)
			receipt := successfulReceipt(t, c, now.Load())
			if e := s.Complete(ctx, c, receipt, exact(receipt)); e != nil {
				t.Fatal(e)
			}
			if kind == "close" {
				f.failClose = f.closes + 1
			} else {
				f.failWrite = f.writes + 1
				f.commitFailedWrite = kind == "write-after-commit"
			}
			if e := s.RetireWUA(ctx, receipt, exact(receipt)); e == nil {
				t.Fatal("uncertainty hidden")
			}
			if kind == "write-before-commit" {
				if _, e := s.Reserve(ctx, testOwner(CachedWUA, 2)); e == nil {
					t.Fatal("uncertain store admitted new owner")
				}
			} else {
				s.Close()
				s = testSession(t, f, r, CachedWUA, now)
				if e := s.RetireWUA(ctx, receipt, exact(receipt)); e != nil {
					t.Fatal("exact saved retirement cannot reconcile", e)
				}
			}
		})
	}
}
func TestReusableWUAFenceVersionsAndOldByteShapes(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	if bytes.Contains(f.raw, []byte("retiredWUA")) {
		t.Fatal("old record shape changed")
	}
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	start(t, s, c)
	if _, e := c.Completion(testDigest("result"), "succeeded", now.Load()); e == nil {
		t.Fatal("old version gained new receipt outcome")
	}
	receipt := terminal(t, c, now.Load())
	if e := s.RetireWUA(context.Background(), receipt, exact(receipt)); e == nil {
		t.Fatal("old roster gained retirement")
	}
	f, r, _ = reusableWUAFence(t)
	r.Version = BackgroundRosterVersion
	if r.Validate() == nil {
		t.Fatal("mixed plan/roster accepted")
	}
	state, e := decode(f.raw)
	if e != nil {
		t.Fatal(e)
	}
	state.Version = BackgroundVersion
	state.Plan.Version = BackgroundPlanVersion
	state.Roster.Version = BackgroundRosterVersion
	state.Roster.Plan = state.Plan
	state.Activation.Version = BackgroundActivationVersion
	state.RetiredWUASequence = 1
	state.RetiredWUADigest = testDigest("chain")
	state.RetiredWUAReceiptDigest = testDigest("receipt")
	raw, _ := json.Marshal(state)
	if _, e = decode(raw); e == nil {
		t.Fatal("old state gained new floors")
	}
}

func TestReusableWUARetirementWaitsForOtherOwner(t *testing.T) {
	f, r, now := reusableWUAFence(t)
	ctx := context.Background()
	s := testSession(t, f, r, CachedWUA, now)
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	start(t, s, c)
	receipt := successfulReceipt(t, c, now.Load())
	if e := s.Complete(ctx, c, receipt, exact(receipt)); e != nil {
		t.Fatal(e)
	}
	m := testSession(t, f, r, ManagedMSI, now)
	mc := mustReserve(t, m, testOwner(ManagedMSI, 1))
	before := bytes.Clone(f.raw)
	if e := s.RetireWUA(ctx, receipt, exact(receipt)); !errors.Is(e, ErrBusy) || !bytes.Equal(before, f.raw) {
		t.Fatal("retired while MSI owned fence", e)
	}
	start(t, m, mc)
	mr := terminal(t, mc, now.Load())
	if e := m.Complete(ctx, mc, mr, exact(mr)); e != nil {
		t.Fatal(e)
	}
	if e := s.RetireWUA(ctx, receipt, exact(receipt)); e != nil {
		t.Fatal(e)
	}
	if e := m.RetireMSI(ctx, mr, exact(mr)); e != nil {
		t.Fatal(e)
	}
	mustReserve(t, m, testOwner(ManagedMSI, 2))
	if e := s.RetireWUA(ctx, receipt, exact(receipt)); !errors.Is(e, ErrBusy) {
		t.Fatal("idempotent ack bypassed active owner", e)
	}
}
