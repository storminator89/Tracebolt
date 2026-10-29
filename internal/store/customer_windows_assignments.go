package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
)

// Organizational metadata bound to the original enrollment identity. No grant,
// tenant access or action authority follows from this record.
const customerWindowsAssignmentsSchema = `CREATE TABLE IF NOT EXISTS customer_windows_assignments(identity TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024 AND json_valid(body)))`
const MaxCustomerWindowsAssignments = 100

var ErrCustomerAssignmentConflict = errors.New("customer assignment changed or unavailable")

type CustomerWindowsAssignment struct {
	Version          string `json:"version"`
	Manager          string `json:"manager"`
	CustomerID       string `json:"customerId"`
	CustomerRevision uint64 `json:"customerRevision"`
	DeviceID         string `json:"deviceId"`
	Identity         string `json:"identity"`
}

func validCustomerWindowsAssignment(a CustomerWindowsAssignment) bool {
	return a.Version == "tracebolt.customer-windows-assignment.v1" && enrollmentcrypto.ValidHash(a.Manager) && enrollmentcrypto.ValidID(a.CustomerID, "customer_") && a.CustomerRevision > 0 && a.CustomerRevision <= MaxFleetGroupRevision && enrollmentcrypto.ValidID(a.DeviceID, "agent_") && enrollmentcrypto.ValidHash(a.Identity)
}

func decodeCustomerWindowsAssignment(id string, raw []byte) (CustomerWindowsAssignment, error) {
	var a CustomerWindowsAssignment
	if len(raw) > 1024 || json.Unmarshal(raw, &a) != nil || a.Identity != id || !validCustomerWindowsAssignment(a) {
		return a, ErrCustomerAssignmentConflict
	}
	canonical, e := json.Marshal(a)
	if e != nil || !bytes.Equal(canonical, raw) {
		return CustomerWindowsAssignment{}, ErrCustomerAssignmentConflict
	}
	return a, nil
}

func readCustomerWindowsAssignments(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, manager string) ([]CustomerWindowsAssignment, error) {
	if !enrollmentcrypto.ValidHash(manager) {
		return nil, ErrCustomerAssignmentConflict
	}
	rows, e := q.QueryContext(ctx, "SELECT identity,body FROM customer_windows_assignments ORDER BY identity LIMIT 101")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CustomerWindowsAssignment{}
	counts := map[string]uint64{}
	managers := map[string]string{}
	revisions := map[string]uint64{}
	n := 0
	for rows.Next() {
		var id string
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			return nil, e
		}
		n++
		if n > MaxCustomerWindowsAssignments {
			return nil, ErrCustomerAssignmentConflict
		}
		a, e := decodeCustomerWindowsAssignment(id, raw)
		if e != nil {
			return nil, e
		}
		if a.Manager == manager {
			out = append(out, a)
		}
		counts[a.CustomerID]++
		if a.CustomerRevision > revisions[a.CustomerID] {
			revisions[a.CustomerID] = a.CustomerRevision
		}
		if prior, ok := managers[a.CustomerID]; ok && prior != a.Manager {
			return nil, ErrCustomerAssignmentConflict
		}
		managers[a.CustomerID] = a.Manager
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	customers, e := q.QueryContext(ctx, "SELECT id,body FROM customers LIMIT 26")
	if e != nil {
		return nil, e
	}
	defer customers.Close()
	n = 0
	for customers.Next() {
		var id string
		var raw []byte
		if e = customers.Scan(&id, &raw); e != nil {
			return nil, e
		}
		n++
		if n > MaxCustomers {
			return nil, ErrCustomerAssignmentConflict
		}
		c, err := decodeCustomer(id, raw)
		if err != nil {
			return nil, err
		}
		if counts[id] != c.AssignmentCount || revisions[id] > c.Revision || counts[id] > 0 && managers[id] != c.Manager {
			return nil, ErrCustomerAssignmentConflict
		}
		delete(counts, id)
	}
	if e = customers.Err(); e != nil {
		return nil, e
	}
	if len(counts) != 0 {
		return nil, ErrCustomerAssignmentConflict
	}
	return out, nil
}

func (s *Store) CustomerWindowsAssignments(ctx context.Context, manager string) ([]CustomerWindowsAssignment, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := readCustomerWindowsAssignments(ctx, tx, manager)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return rows, nil
}

// Caller holds the enrollment authority lease. A customer revision and the live
// session/authority guard are rechecked inside this write transaction. No
// replacement, deletion or implicit reassignment is performed.
func (s *Store) CreateCustomerWindowsAssignment(ctx context.Context, a CustomerWindowsAssignment, guard func() error) error {
	if !validCustomerWindowsAssignment(a) || guard == nil {
		return ErrCustomerAssignmentConflict
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	all, e := readCustomerWindowsAssignments(ctx, tx, a.Manager)
	if e != nil {
		return e
	}
	for _, old := range all {
		if old.Identity == a.Identity {
			return ErrCustomerAssignmentConflict
		}
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM customer_windows_assignments").Scan(&count); e != nil {
		return e
	}
	if count >= MaxCustomerWindowsAssignments {
		return ErrCustomerAssignmentConflict
	}
	var raw []byte
	e = tx.QueryRowContext(ctx, "SELECT body FROM customers WHERE id=?", a.CustomerID).Scan(&raw)
	if e != nil {
		return ErrCustomerAssignmentConflict
	}
	c, e := decodeCustomer(a.CustomerID, raw)
	if e != nil || c.Manager != a.Manager || c.Revision != a.CustomerRevision {
		return ErrCustomerAssignmentConflict
	}
	if e = guard(); e != nil {
		return e
	}
	raw, e = json.Marshal(a)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO customer_windows_assignments(identity,body) VALUES(?,?)", a.Identity, raw); e != nil {
		return e
	}
	if c.AssignmentCount >= MaxCustomerWindowsAssignments {
		return ErrCustomerAssignmentConflict
	}
	c.AssignmentCount++
	customerRaw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE customers SET body=? WHERE id=?", customerRaw, c.ID); e != nil {
		return e
	}
	if e = guard(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return tx.Commit()
}
