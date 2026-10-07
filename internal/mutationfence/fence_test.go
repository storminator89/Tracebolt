//go:build linux

package mutationfence

import (
	"context"
	"errors"
	"localrmm/internal/actionpermit"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) (*Fence, string, Binding) {
	t.Helper()
	d := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(d, 0700); e != nil {
		t.Fatal(e)
	}
	b := Binding{"manager_11111111111111111111111111111111", "agent_11111111111111111111111111111111", actionpermit.Digest([]byte("incarnation"))}
	f, e := Create(context.Background(), d, b, 100)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, d, b
}
func owner(action, id string, seq uint64) Owner {
	return Owner{action, id, seq, actionpermit.Digest([]byte(action + id))}
}
func TestCrossActionFencePersistsUnknownAndNeverReplays(t *testing.T) {
	ctx := context.Background()
	f, d, b := fixture(t)
	p := owner(Package, "update_11111111111111111111111111111111", 1)
	s := owner(Service, "action_11111111111111111111111111111111", 1)
	e, fresh, err := f.Acquire(ctx, p, 101)
	if err != nil || !fresh || e.CompletedAt != 0 {
		t.Fatal(err)
	}
	if _, _, err = f.Acquire(ctx, s, 102); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	_ = f.Close()
	g, err := Open(ctx, d, b)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if _, fresh, err = g.Acquire(ctx, p, 103); err != nil || fresh {
		t.Fatal("replayed root mutation", err)
	}
	if _, _, err = g.Acquire(ctx, s, 103); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err = g.Complete(ctx, p, "completed", 104); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err = g.Acquire(ctx, s, 105); err != nil || !fresh {
		t.Fatal(err)
	}
}
func TestSameIDChangedBytesAndClockRollbackFail(t *testing.T) {
	ctx := context.Background()
	f, _, _ := fixture(t)
	p := owner(Prepare, "update_11111111111111111111111111111111", 1)
	_, _, e := f.Acquire(ctx, p, 101)
	if e != nil {
		t.Fatal(e)
	}
	changed := p
	changed.EnvelopeDigest = actionpermit.Digest([]byte("changed"))
	if _, _, e = f.Acquire(ctx, changed, 102); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = f.Complete(ctx, p, "not_started", 100); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestUncertainIntentAndMissingStateNeverReset(t *testing.T) {
	ctx := context.Background()
	f, d, b := fixture(t)
	_ = f.Close()
	if e := os.WriteFile(filepath.Join(d, "intent"), []byte("uncertain"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(ctx, d, b); !errors.Is(e, ErrUncertain) {
		t.Fatal(e)
	}
	if _, e := Create(ctx, d, b, 101); e == nil {
		t.Fatal("reinitialized used scope")
	}
}

func TestIndependentHandlesSerializeOneAdmission(t *testing.T) {
	ctx := context.Background()
	f, d, b := fixture(t)
	g, e := Open(ctx, d, b)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	owners := []Owner{owner(Prepare, "update_11111111111111111111111111111111", 1), owner(Service, "action_11111111111111111111111111111111", 1)}
	start := make(chan struct{})
	results := make(chan bool, 2)
	for i, h := range []*Fence{f, g} {
		go func(i int, h *Fence) {
			<-start
			_, fresh, e := h.Acquire(ctx, owners[i], 101)
			if e != nil && !errors.Is(e, ErrBusy) {
				t.Errorf("unexpected admission error %v", e)
			}
			results <- fresh
		}(i, h)
	}
	close(start)
	count := 0
	for i := 0; i < 2; i++ {
		if <-results {
			count++
		}
	}
	if count != 1 {
		t.Fatal("concurrent admissions", count)
	}
}
func TestUnsafeFilesAndInterruptedWritePoisonAdmission(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "permissions", "pending-write"} {
		t.Run(kind, func(t *testing.T) {
			f, d, b := fixture(t)
			ctx := context.Background()
			p := owner(Prepare, "update_11111111111111111111111111111111", 1)
			switch kind {
			case "symlink":
				if e := os.Rename(filepath.Join(d, "state.json"), filepath.Join(d, "original")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("original", filepath.Join(d, "state.json")); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(filepath.Join(d, "state.json"), filepath.Join(d, "linked")); e != nil {
					t.Fatal(e)
				}
			case "permissions":
				if e := os.Chmod(filepath.Join(d, "state.json"), 0644); e != nil {
					t.Fatal(e)
				}
			case "pending-write":
				if e := os.WriteFile(filepath.Join(d, "state.next"), []byte("partial"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, fresh, e := f.Acquire(ctx, p, 101); e == nil || fresh {
				t.Fatal("unsafe mutation admitted", e)
			}
			if _, fresh, e := f.Acquire(ctx, p, 102); e == nil || fresh {
				t.Fatal("poison retried", e)
			}
			_ = f.Close()
			if _, e := Open(ctx, d, b); e == nil {
				t.Fatal("unsafe state reopened")
			}
		})
	}
}
