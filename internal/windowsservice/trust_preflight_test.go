package windowsservice

import (
	"context"
	"errors"
	"testing"
)

type unreadableRuntimeBackend struct{ *fakeBackend }

func (b unreadableRuntimeBackend) VerifyExecutable(Layout) (string, error) {
	b.verified++
	return "", ErrRuntimeReadAccess
}

func TestRuntimeReadPreflightRefusesPlanAndInstallBeforeMutation(t *testing.T) {
	ctx := context.Background()
	b := fixtureBackend(t)
	if _, err := plan(ctx, unreadableRuntimeBackend{b}); !errors.Is(err, ErrRuntimeReadAccess) || b.created != 0 || len(b.opened) != 0 {
		t.Fatal("runtime read refusal did not stop planning before SCM access", err)
	}
	p, err := plan(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate loss of the runtime grant after an otherwise valid read-only
	// plan. Apply must recheck and stop before creating a service or receipt.
	r, err := install(ctx, unreadableRuntimeBackend{b}, p)
	if !errors.Is(err, ErrRuntimeReadAccess) || r != (Receipt{}) || b.created != 0 {
		t.Fatal("runtime read refusal did not stop installation", r, err)
	}
}

func TestRuntimeReadPreflightRefusesOwnedInspectionAndStart(t *testing.T) {
	ctx := context.Background()
	b, receipt := installedFixture(t)
	blocked := unreadableRuntimeBackend{b}
	before := b.s.closes
	if _, err := inspectOwned(ctx, blocked, receipt); !errors.Is(err, ErrRuntimeReadAccess) {
		t.Fatal("owned inspection accepted an unreadable runtime path", err)
	}
	if b.s.closes != before+1 {
		t.Fatal("owned inspection leaked its read-only service handle")
	}
	result, err := apply(ctx, blocked, receipt, startAccess)
	if !errors.Is(err, ErrRuntimeReadAccess) || result.Requested || b.s.starts != 0 || b.s.stops != 0 || b.s.deletes != 0 {
		t.Fatal("runtime read refusal did not stop service start", result, err)
	}
}
