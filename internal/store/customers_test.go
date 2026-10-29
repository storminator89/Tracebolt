package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomersBoundedCASAndSessionGuard(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "customers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	manager := strings.Repeat("a", 64)
	id := "customer_" + strings.Repeat("1", 32)
	guard := func() error { return nil }
	c, err := s.SaveCustomer(ctx, manager, id, "First", 0, guard)
	if err != nil || c.Revision != 1 {
		t.Fatal(c, err)
	}
	if _, err = s.SaveCustomer(ctx, manager, id, "Stale", 0, guard); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("stale create accepted", err)
	}
	if _, err = s.SaveCustomer(ctx, strings.Repeat("b", 64), id, "Other", 1, guard); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("manager reassignment accepted", err)
	}
	calls := 0
	if _, err = s.SaveCustomer(ctx, manager, id, "Rejected", 1, func() error {
		calls++
		if calls == 2 {
			return ErrCustomerConflict
		}
		return nil
	}); !errors.Is(err, ErrCustomerConflict) {
		t.Fatal("final guard failed", err)
	}
	items, err := s.Customers(ctx, manager)
	if err != nil || len(items) != 1 || items[0] != c {
		t.Fatal("failed write changed catalog", items, err)
	}
	items, err = s.Customers(ctx, strings.Repeat("b", 64))
	if err != nil || len(items) != 0 {
		t.Fatal("cross-manager leak", items, err)
	}
	c, err = s.SaveCustomer(ctx, manager, id, "Updated", 1, guard)
	if err != nil || c.Revision != 2 {
		t.Fatal("rename failed", err)
	}
	for i := 2; i <= MaxCustomers; i++ {
		id := fmt.Sprintf("customer_%032x", i)
		if _, err = s.SaveCustomer(ctx, manager, id, "Name", 0, guard); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.SaveCustomer(ctx, manager, "customer_"+strings.Repeat("f", 32), "Overflow", 0, guard); !errors.Is(err, ErrLimit) {
		t.Fatal("limit ignored", err)
	}
	if _, err = s.db.Exec("UPDATE customers SET body=body || ' '"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Customers(ctx, manager); !errors.Is(err, ErrCustomerInvalid) {
		t.Fatal("noncanonical data accepted", err)
	}
	if _, err = s.SaveCustomer(ctx, manager, id, "Must not overwrite", 2, guard); !errors.Is(err, ErrCustomerInvalid) {
		t.Fatal("corrupt catalog was modified", err)
	}
}
