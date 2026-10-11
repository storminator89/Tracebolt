package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFleetGroupsBoundedCASAndPrivateIdentity(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	manager := strings.Repeat("a", 64)
	id := "group_" + strings.Repeat("1", 32)
	members := []FleetGroupMember{{DeviceID: "agent_" + strings.Repeat("2", 32), Identity: strings.Repeat("b", 64)}}
	guard := func() error { return nil }
	before, err := s.FleetGroups(ctx, manager)
	if err != nil || len(before) != 0 {
		t.Fatal("new store is not empty")
	}
	created, err := s.SaveFleetGroup(ctx, manager, id, "Office", members, 0, false, guard)
	if err != nil || created.Revision != 1 {
		t.Fatal(err)
	}
	if _, err = s.SaveFleetGroup(ctx, manager, id, "Old tab", members, 0, false, guard); !errors.Is(err, ErrFleetGroupConflict) {
		t.Fatal("stale revision accepted")
	}
	if _, err = s.SaveFleetGroup(ctx, strings.Repeat("c", 64), id, "Other manager", members, 1, false, guard); !errors.Is(err, ErrFleetGroupConflict) {
		t.Fatal("manager changed")
	}
	if _, err = s.SaveFleetGroup(ctx, manager, id, "Duplicates", append(members, members...), 1, false, guard); !errors.Is(err, ErrFleetGroupInvalid) {
		t.Fatal("duplicate member accepted")
	}
	calls := 0
	denyCommit := func() error {
		calls++
		if calls == 2 {
			return ErrFleetGroupConflict
		}
		return nil
	}
	if _, err = s.SaveFleetGroup(ctx, manager, id, "Expired", nil, 1, false, denyCommit); !errors.Is(err, ErrFleetGroupConflict) {
		t.Fatal("final guard ignored")
	}
	read, err := s.FleetGroups(ctx, manager)
	if err != nil || !reflect.DeepEqual(read, []FleetGroup{created}) {
		t.Fatal("failed write changed membership")
	}
	other, err := s.FleetGroups(ctx, strings.Repeat("c", 64))
	if err != nil || len(other) != 0 {
		t.Fatal("cross-manager projection")
	}
	updated, err := s.SaveFleetGroup(ctx, manager, id, "Empty", []FleetGroupMember{}, 1, false, guard)
	if err != nil || updated.Revision != 2 || len(updated.Members) != 0 {
		t.Fatal("membership not replaced", err)
	}
	if _, err = s.SaveFleetGroup(ctx, manager, id, "Empty", nil, 1, true, guard); !errors.Is(err, ErrFleetGroupConflict) {
		t.Fatal("stale deletion accepted")
	}
	if _, err = s.SaveFleetGroup(ctx, manager, id, "Empty", nil, 2, true, guard); err != nil {
		t.Fatal(err)
	}
}
func TestFleetGroupsCanonicalCorruptionAndBounds(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	manager := strings.Repeat("a", 64)
	guard := func() error { return nil }
	for _, name := range []string{"", " Leading", "Trailing ", "\nline", "\u202ehidden", strings.Repeat("x", 81)} {
		if ValidFleetGroupName(name) {
			t.Fatal("invalid name accepted")
		}
	}
	for i := 1; i <= MaxFleetGroups; i++ {
		id := "group_" + strings.Repeat("0", 30) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
		if _, err = s.SaveFleetGroup(ctx, manager, id, "Group", nil, 0, false, guard); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.SaveFleetGroup(ctx, manager, "group_"+strings.Repeat("f", 32), "Overflow", nil, 0, false, guard); !errors.Is(err, ErrLimit) {
		t.Fatal("group bound ignored")
	}
	if _, err = s.db.Exec("UPDATE fleet_groups SET body=body || ' '"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.FleetGroups(ctx, manager); !errors.Is(err, ErrFleetGroupInvalid) {
		t.Fatal("noncanonical data accepted")
	}
}
