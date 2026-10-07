package native

import (
	"slices"
	"strings"
)

type objectID struct{ Volume, High, Low uint32 }
type ownedObject struct {
	path      string
	id        objectID
	hash      string
	directory bool
}
type treePin struct {
	object ownedObject
	handle uintptr
}

// freezeTree opens every child through its already-held direct parent. Reopening
// a parent's path would conflict with its existing no-delete-sharing DELETE
// handle. The callbacks allow this lifetime/sharing rule to be tested without OS
// operations. On failure every newly acquired handle is released, never anchors.
func freezeTree(objects []ownedObject, anchors map[string]uintptr, open func(uintptr, ownedObject) (uintptr, error), close func(uintptr)) ([]treePin, error) {
	objects = slices.Clone(objects)
	slices.SortFunc(objects, func(a, b ownedObject) int { return strings.Compare(a.path, b.path) })
	parents := make(map[string]uintptr, len(anchors)+len(objects))
	for name, handle := range anchors {
		parents[name] = handle
	}
	seen := make(map[string]bool, len(objects))
	var held []treePin
	fail := func() ([]treePin, error) {
		for i := len(held) - 1; i >= 0; i-- {
			close(held[i].handle)
		}
		return nil, ErrAcceptance
	}
	for _, object := range objects {
		split := strings.LastIndex(object.path, `\`)
		if split < 3 || split == len(object.path)-1 || parents[object.path] != 0 || seen[object.path] {
			return fail()
		}
		seen[object.path] = true
		parent := parents[object.path[:split]]
		if parent == 0 {
			return fail()
		}
		handle, err := open(parent, object)
		if err != nil {
			return fail()
		}
		if handle == 0 {
			return fail()
		}
		held = append(held, treePin{object, handle})
		if object.directory {
			parents[object.path] = handle
		}
	}
	return held, nil
}
