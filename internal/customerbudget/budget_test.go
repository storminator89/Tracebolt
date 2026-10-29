package customerbudget

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestBoundAndCancellation(t *testing.T) {
	if _, err := (*Budget)(nil).Acquire(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil budget accepted")
	}
	if _, err := (&Budget{}).Acquire(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero budget accepted")
	}
	if _, err := New().Acquire(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	b := New()
	if _, err := b.Acquire(cancelled); !errors.Is(err, context.Canceled) || b.InUse() != 0 {
		t.Fatal("cancelled operation reserved capacity")
	}
	a, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("limit not enforced")
	}
	a.Release()
	c.Release()
	if b.InUse() != 0 {
		t.Fatal("capacity not released")
	}
}

func TestCopiedLeaseIsReleasedExactlyOnce(t *testing.T) {
	b := New()
	lease, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	copyOfLease := *lease
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); lease.Release() }()
	go func() { defer wg.Done(); copyOfLease.Release() }()
	wg.Wait()
	if b.InUse() != 0 {
		t.Fatal("lease not released exactly once")
	}
	var zero Lease
	zero.Release()
	var nilLease *Lease
	nilLease.Release()
}
