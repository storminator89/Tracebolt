package native

import (
	"errors"
	"reflect"
	"testing"
)

func TestCleanupFreezeReusesDeleteParentsWithoutReopeningAncestors(t *testing.T) {
	objects := []ownedObject{{path: `C:\ProgramData\Tracebolt\state\entry`}, {path: `C:\ProgramData\Tracebolt`, directory: true}, {path: `C:\ProgramData\Tracebolt\state`, directory: true}, {path: `C:\Program Files\Tracebolt\agent.exe`}, {path: `C:\Program Files\Tracebolt`, directory: true}}
	anchors := map[string]uintptr{`C:\ProgramData`: 1, `C:\Program Files`: 2}
	handles := map[string]uintptr{`C:\ProgramData`: 1, `C:\Program Files`: 2}
	deletePinned := map[string]bool{}
	var opened []string
	var closed []uintptr
	pins, err := freezeTree(objects, anchors, func(parent uintptr, o ownedObject) (uintptr, error) {
		// Model Windows two-way sharing: every acquired directory has DELETE and
		// denies delete sharing, so any attempt to reopen it would be refused.
		if deletePinned[o.path] {
			return 0, errors.New("sharing violation")
		}
		direct := o.path[:len(o.path)-len(baseComponent(o.path))-1]
		if handles[direct] != parent {
			t.Fatal("child did not use its frozen direct parent")
		}
		h := uintptr(len(opened) + 10)
		handles[o.path] = h
		if o.directory {
			deletePinned[o.path] = true
		}
		opened = append(opened, o.path)
		return h, nil
	}, func(h uintptr) { closed = append(closed, h) })
	if err != nil || len(pins) != len(objects) || len(closed) != 0 {
		t.Fatal("cleanup collided with its own parent pin")
	}
	if len(opened) != len(objects) {
		t.Fatal("an ancestor was reopened")
	}
	// Frozen parents remain live until the caller's bottom-up disposition stage.
	for _, p := range pins {
		if p.handle == 0 {
			t.Fatal("missing retained cleanup handle")
		}
	}
}
func baseComponent(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}

func TestCleanupFreezeFailureClosesOnlyAcquiredHandlesInReverse(t *testing.T) {
	objects := []ownedObject{{path: `C:\ProgramData\Tracebolt`, directory: true}, {path: `C:\ProgramData\Tracebolt\state`, directory: true}, {path: `C:\ProgramData\Tracebolt\state\entry`}}
	for failAt := 0; failAt < len(objects); failAt++ {
		calls := 0
		var closed []uintptr
		_, err := freezeTree(objects, map[string]uintptr{`C:\ProgramData`: 1}, func(parent uintptr, o ownedObject) (uintptr, error) {
			index := calls
			calls++
			if index == failAt {
				return 0, ErrAcceptance
			}
			return uintptr(index + 10), nil
		}, func(h uintptr) { closed = append(closed, h) })
		want := []uintptr(nil)
		for i := failAt - 1; i >= 0; i-- {
			want = append(want, uintptr(i+10))
		}
		if err == nil || !reflect.DeepEqual(closed, want) || calls != failAt+1 {
			t.Fatal("failed cleanup leaked handles or retried")
		}
	}
}
func TestCleanupFreezeRejectsMissingParentWithoutPathFallback(t *testing.T) {
	calls := 0
	_, err := freezeTree([]ownedObject{{path: `C:\ProgramData\Tracebolt\unknown\entry`}}, map[string]uintptr{`C:\ProgramData`: 1}, func(uintptr, ownedObject) (uintptr, error) { calls++; return 2, nil }, func(uintptr) { t.Fatal("closed an unowned anchor") })
	if err == nil || calls != 0 {
		t.Fatal("missing parent triggered an absolute fallback")
	}
}
