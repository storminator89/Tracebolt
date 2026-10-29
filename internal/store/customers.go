package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"localrmm/internal/enrollmentcrypto"
)

// Customers are organizational records only: no device membership, tenancy,
// collection permission or enrollment authority follows from this table.
const customersSchema = `CREATE TABLE IF NOT EXISTS customers(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024 AND json_valid(body)))`
const MaxCustomers = 25

var ErrCustomerInvalid = errors.New("invalid customer")
var ErrCustomerConflict = errors.New("customer revision or manager changed")

type Customer struct {
	Version  string `json:"version"`
	ID       string `json:"id"`
	Manager  string `json:"manager"`
	Name     string `json:"name"`
	Revision uint64 `json:"revision"`
	// A retained floor for create-only Windows assignments. Omitted at zero so
	// historical customer JSON remains byte-identical until this domain is used.
	AssignmentCount uint64 `json:"assignmentCount,omitempty"`
}

func validCustomer(c Customer) bool {
	return c.Version == "tracebolt.customer.v1" && enrollmentcrypto.ValidID(c.ID, "customer_") && enrollmentcrypto.ValidHash(c.Manager) && ValidFleetGroupName(c.Name) && c.Revision > 0 && c.Revision <= MaxFleetGroupRevision && c.AssignmentCount <= MaxCustomerWindowsAssignments
}

func decodeCustomer(id string, raw []byte) (Customer, error) {
	var c Customer
	if len(raw) > 1024 || json.Unmarshal(raw, &c) != nil || c.ID != id || !validCustomer(c) {
		return Customer{}, ErrCustomerInvalid
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Customer{}, ErrCustomerInvalid
	}
	return c, nil
}

func (s *Store) Customers(ctx context.Context, manager string) ([]Customer, error) {
	if !enrollmentcrypto.ValidHash(manager) {
		return nil, ErrCustomerInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,body FROM customers ORDER BY id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Customer{}
	count := 0
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		count++
		if count > MaxCustomers {
			return nil, ErrCustomerInvalid
		}
		c, err := decodeCustomer(id, raw)
		if err != nil {
			return nil, err
		}
		if c.Manager == manager {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// SaveCustomer never deletes or reuses an ID. A caller must hold a live session
// lease and supply a guard; it is rechecked immediately before commit.
func (s *Store) SaveCustomer(ctx context.Context, manager, id, name string, expected uint64, guard func() error) (Customer, error) {
	if expected >= MaxFleetGroupRevision || guard == nil {
		return Customer{}, ErrCustomerInvalid
	}
	next := Customer{Version: "tracebolt.customer.v1", ID: id, Manager: manager, Name: name, Revision: expected + 1}
	if !validCustomer(next) {
		return Customer{}, ErrCustomerInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Customer{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,body FROM customers LIMIT 26")
	if err != nil {
		return Customer{}, err
	}
	count := 0
	for rows.Next() {
		var existingID string
		var existingRaw []byte
		if err = rows.Scan(&existingID, &existingRaw); err != nil {
			rows.Close()
			return Customer{}, err
		}
		count++
		if count > MaxCustomers {
			rows.Close()
			return Customer{}, ErrCustomerInvalid
		}
		if _, err = decodeCustomer(existingID, existingRaw); err != nil {
			rows.Close()
			return Customer{}, err
		}
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return Customer{}, err
	}
	if closeErr != nil {
		return Customer{}, closeErr
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM customers WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 {
			return Customer{}, ErrCustomerConflict
		}
		if count >= MaxCustomers {
			return Customer{}, ErrLimit
		}
	} else if err != nil {
		return Customer{}, err
	} else {
		old, e := decodeCustomer(id, raw)
		if e != nil {
			return Customer{}, e
		}
		if old.Manager != manager || old.Revision != expected {
			return Customer{}, ErrCustomerConflict
		}
		next.AssignmentCount = old.AssignmentCount
	}
	if err = guard(); err != nil {
		return Customer{}, err
	}
	raw, err = json.Marshal(next)
	if err != nil {
		return Customer{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO customers(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, raw); err != nil {
		return Customer{}, err
	}
	if err = guard(); err != nil {
		return Customer{}, err
	}
	if err = ctx.Err(); err != nil {
		return Customer{}, err
	}
	if err = tx.Commit(); err != nil {
		return Customer{}, err
	}
	return next, nil
}
