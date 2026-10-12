package windowssoftwarejob

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestInstallStartFenceIsRequiredOriginalAndIndependentOfDuration(t *testing.T) {
	ctx := withInstallStartFence(context.Background(), 1700000000, 1700000060, 1700000070, 1700000080)
	for _, n := range []int64{1699999999, 1700000060, 1700000061} {
		if !errors.Is(CheckInstallStart(ctx, time.Unix(n, 0)), ErrExpired) {
			t.Fatal(n)
		}
	}
	if CheckInstallStart(ctx, time.Unix(1700000059, 0)) != nil {
		t.Fatal("valid start")
	}
	if !errors.Is(CheckInstallStart(context.Background(), time.Unix(1700000000, 0)), ErrAuthority) {
		t.Fatal("missing fence")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(CheckInstallStart(canceled, time.Unix(1700000001, 0)), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("start fence became operation-duration deadline")
	}
}

type startFenceFixture struct {
	nativeFixture
	seen context.Context
}

func (n *startFenceFixture) PrepareExact(context.Context, Selection) (PreparedPackage, error) {
	return n, nil
}
func (n *startFenceFixture) InstallOnce(ctx context.Context) (NativeResult, error) {
	n.seen = ctx
	return n.result, nil
}
func TestExecutorCarriesExactOriginalStartFence(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	permit, e := Verify(raw, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	n := &startFenceFixture{nativeFixture: nativeFixture{readiness: f.source.value, result: NativeResult{ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: Yes}}}
	x, _ := executorFixture(t, f, n)
	if _, e = x.Execute(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
	fence, ok := n.seen.Value(installStartKey{}).(installStartFence)
	if !ok || fence.before != permit.Preview.ExpiresAt || fence.floor != f.at.Unix() || fence.consentBefore != f.consent.ExpiresAt || fence.leafBefore != f.guard.current.LeafNotAfter {
		t.Fatal("kernel replaced original start fence", fence)
	}
}

func TestShorterConsentOrCurrentLeafCannotExtendNativeStart(t *testing.T) {
	for _, bounds := range [][2]int64{{1700000005, 1700000080}, {1700000080, 1700000005}} {
		ctx := withInstallStartFence(context.Background(), 1700000000, 1700000060, bounds[0], bounds[1])
		if CheckInstallStart(ctx, time.Unix(1700000004, 0)) != nil {
			t.Fatal("valid shorter bound")
		}
		if !errors.Is(CheckInstallStart(ctx, time.Unix(1700000005, 0)), ErrExpired) {
			t.Fatal("short current authority extended")
		}
	}
}

func TestStartCurrentnessIsRecheckedAndTimeResampled(t *testing.T) {
	at := time.Unix(1700000000, 0)
	called := 0
	ctx := withInstallStartFence(context.Background(), at.Unix(), at.Unix()+60, at.Unix()+80, at.Unix()+90)
	ctx = withInstallStartCurrent(ctx, func() time.Time { return at }, func(context.Context) (installStartBounds, error) {
		called++
		at = at.Add(time.Minute)
		return installStartBounds{1700000000, 1700000080, 1700000090}, nil
	})
	if err := CheckInstallStart(ctx, at); !errors.Is(err, ErrExpired) || called != 1 {
		t.Fatal("blocking currentness check extended start", err, called)
	}
	denied := withInstallStartCurrent(withInstallStartFence(context.Background(), 1700000000, 1700000060, 1700000080, 1700000090), func() time.Time { return time.Unix(1700000001, 0) }, func(context.Context) (installStartBounds, error) { return installStartBounds{}, ErrAuthority })
	if err := CheckInstallStart(denied, time.Unix(1700000001, 0)); !errors.Is(err, ErrAuthority) {
		t.Fatal("authority revocation ignored", err)
	}
}

func TestFreshStartBoundsCannotBeExtendedByOriginalLeafOrClock(t *testing.T) {
	for _, kind := range []string{"shorter_leaf", "advanced_floor"} {
		t.Run(kind, func(t *testing.T) {
			at := time.Unix(1700000000, 0)
			ctx := withInstallStartFence(context.Background(), at.Unix(), at.Unix()+60, at.Unix()+80, at.Unix()+90)
			ctx = withInstallStartCurrent(ctx, func() time.Time { return at }, func(context.Context) (installStartBounds, error) {
				if kind == "shorter_leaf" {
					at = at.Add(10 * time.Second)
					return installStartBounds{1700000000, 1700000080, 1700000005}, nil
				}
				at = at.Add(2 * time.Second)
				return installStartBounds{1700000003, 1700000080, 1700000090}, nil
			})
			if e := CheckInstallStart(ctx, time.Unix(1700000000, 0)); !errors.Is(e, ErrExpired) {
				t.Fatal("fresh authority extended", e)
			}
		})
	}
}
