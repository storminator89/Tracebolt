package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomerWindowsAssignmentLegacyCustomerJSON(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	manager := strings.Repeat("a", 64)
	id := "customer_" + strings.Repeat("1", 32)
	for _, row := range []struct {
		name     string
		expected uint64
	}{{"Customer", 0}, {"Renamed", 1}} {
		if _, err = s.SaveCustomer(ctx, manager, id, row.name, row.expected, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err = s.db.QueryRowContext(ctx, "SELECT body FROM customers WHERE id=?", id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf(`{"version":"tracebolt.customer.v1","id":"%s","manager":"%s","name":"%s","revision":%d}`, id, manager, row.name, row.expected+1)
		if string(raw) != want {
			t.Fatalf("legacy customer bytes changed: got %s, want %s", raw, want)
		}
		if _, err = decodeCustomer(id, []byte(want)); err != nil {
			t.Fatalf("legacy customer bytes rejected: %v", err)
		}
	}
}

func TestCustomerWindowsAssignmentCreateOnlyAndGuards(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "assignment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	manager := strings.Repeat("a", 64)
	customer := "customer_" + strings.Repeat("1", 32)
	_, err = s.SaveCustomer(ctx, manager, customer, "Customer", 0, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	a := CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: "agent_" + strings.Repeat("2", 32), Identity: strings.Repeat("b", 64)}
	calls := 0
	err = s.CreateCustomerWindowsAssignment(ctx, a, func() error {
		calls++
		if calls == 2 {
			return ErrCustomerAssignmentConflict
		}
		return nil
	})
	if !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("guard failure accepted", err)
	}
	rows, err := s.CustomerWindowsAssignments(ctx, manager)
	if err != nil || len(rows) != 0 {
		t.Fatal("guard failed to roll back", rows, err)
	}
	stale := a
	stale.CustomerRevision = 2
	if err = s.CreateCustomerWindowsAssignment(ctx, stale, func() error { return nil }); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("stale customer revision accepted", err)
	}
	if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("repeat accepted", err)
	}
	rows, err = s.CustomerWindowsAssignments(ctx, manager)
	if err != nil || len(rows) != 1 || rows[0] != a {
		t.Fatal(rows, err)
	}
	if _, err = s.SaveCustomer(ctx, manager, customer, "Renamed", 1, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	second := a
	second.DeviceID = "agent_" + strings.Repeat("3", 32)
	second.Identity = strings.Repeat("c", 64)
	if err = s.CreateCustomerWindowsAssignment(ctx, second, func() error { return nil }); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("old customer revision accepted after rename", err)
	}
	second.CustomerRevision = 2
	if err = s.CreateCustomerWindowsAssignment(ctx, second, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE customer_windows_assignments SET body=body || ' '"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CustomerWindowsAssignments(ctx, manager); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("corrupt record accepted", err)
	}
}

func TestCustomerWindowsAssignmentRejectsFutureCustomerRevision(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "future.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	manager := strings.Repeat("a", 64)
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = s.SaveCustomer(ctx, manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	a := CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: "agent_" + strings.Repeat("2", 32), Identity: strings.Repeat("b", 64)}
	if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	a.CustomerRevision = 2
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE customer_windows_assignments SET body=? WHERE identity=?", raw, a.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CustomerWindowsAssignments(ctx, manager); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("future revision accepted", err)
	}
}

func TestCustomerWindowsAssignmentsBoundedHistoryAndRename(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	manager := strings.Repeat("a", 64)
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = s.SaveCustomer(ctx, manager, customer, "Old", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= MaxCustomerWindowsAssignments; i++ {
		a := CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: fmt.Sprintf("agent_%032x", i), Identity: fmt.Sprintf("%064x", i)}
		if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	rows, err := s.CustomerWindowsAssignments(ctx, manager)
	if err != nil || len(rows) != 100 {
		t.Fatal("history truncated", len(rows), err)
	}
	if _, err = s.SaveCustomer(ctx, manager, customer, "New", 1, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	rows, err = s.CustomerWindowsAssignments(ctx, manager)
	if err != nil || len(rows) != 100 || rows[0].CustomerRevision != 1 {
		t.Fatal("rename rewrote historical binding", rows, err)
	}
	extra := CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 2, DeviceID: fmt.Sprintf("agent_%032x", 101), Identity: fmt.Sprintf("%064x", 101)}
	if err = s.CreateCustomerWindowsAssignment(ctx, extra, func() error { return nil }); !errors.Is(err, ErrCustomerAssignmentConflict) {
		t.Fatal("history bound exceeded", err)
	}
}

func TestCustomerWindowsAssignmentUsedFloorBlocksLostRowOrTable(t *testing.T) {
	for _, lost := range []string{"row", "table"} {
		t.Run(lost, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "floor.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			manager := strings.Repeat("a", 64)
			customer := "customer_" + strings.Repeat("1", 32)
			if _, err = s.SaveCustomer(ctx, manager, customer, "Customer", 0, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			a := CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: "agent_" + strings.Repeat("2", 32), Identity: strings.Repeat("b", 64)}
			if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			query := "DELETE FROM customer_windows_assignments"
			if lost == "table" {
				query = "DROP TABLE customer_windows_assignments"
			}
			if _, err = s.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.CustomerWindowsAssignments(ctx, manager); !errors.Is(err, ErrCustomerAssignmentConflict) {
				t.Fatal("lost used state accepted", err)
			}
			if err = s.CreateCustomerWindowsAssignment(ctx, a, func() error { return nil }); !errors.Is(err, ErrCustomerAssignmentConflict) {
				t.Fatal("lost used state recreated", err)
			}
			c, err := s.SaveCustomer(ctx, manager, customer, "Renamed", 1, func() error { return nil })
			if err != nil || c.AssignmentCount != 1 {
				t.Fatal("rename lost used floor", c, err)
			}
		})
	}
}
