package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"

	"localrmm/internal/enrollmentcrypto"
)

// CustomerAuthorityLease holds the operator database's write exclusion for one
// exact customer revision. It is organizational authority only: it does not
// authorize a device, scope, certificate, action, or external data sharing.
// Callers must hold all preceding locks before acquiring this lease, in the
// order enrollment (if used), pending, profile, then operator. Database alias
// detection and the issuer/session guard are the caller's responsibilities.
// The guard must not reenter this store: Store owns a single SQL connection.
type CustomerAuthorityLease struct {
	mu       sync.Mutex
	conn     *sql.Conn
	ctx      context.Context
	customer Customer
	guard    func() error
}

// AcquireCustomerAuthority holds BEGIN IMMEDIATE until Release. The caller
// must defer Release, including on error, cancellation or uncertain outcomes
// of its enclosing transaction. A Check just before that transaction's COMMIT
// is required; the lease must remain held until that COMMIT or ROLLBACK finishes.
// It must never be used as a replacement for independent session/issuer checks.
func (s *Store) AcquireCustomerAuthority(ctx context.Context, manager, id string, revision uint64, guard func() error) (*CustomerAuthorityLease, error) {
	if s == nil || s.db == nil || ctx == nil || guard == nil || !enrollmentcrypto.ValidHash(manager) || !enrollmentcrypto.ValidID(id, "customer_") || revision == 0 || revision > MaxFleetGroupRevision {
		return nil, ErrCustomerInvalid
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	l := &CustomerAuthorityLease{conn: conn, ctx: ctx, guard: guard}
	began, retained := false, false
	defer func() {
		if !retained {
			if began {
				l.Release()
			} else {
				discardCustomerConn(conn)
			}
		}
	}()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	began = true
	customer, err := readCustomerForAuthority(ctx, conn, manager, id, revision)
	if err != nil {
		return nil, err
	}
	l.customer = customer
	if err = l.Check(); err != nil {
		return nil, err
	}
	retained = true
	return l, nil
}

func readCustomerForAuthority(ctx context.Context, conn *sql.Conn, manager, id string, revision uint64) (Customer, error) {
	rows, err := conn.QueryContext(ctx, "SELECT id,body FROM customers ORDER BY id LIMIT 26")
	if err != nil {
		return Customer{}, err
	}
	defer rows.Close()
	var selected Customer
	count := 0
	for rows.Next() {
		var key string
		var raw []byte
		if err = rows.Scan(&key, &raw); err != nil {
			return Customer{}, err
		}
		count++
		if count > MaxCustomers {
			return Customer{}, ErrCustomerInvalid
		}
		c, err := decodeCustomer(key, raw)
		if err != nil {
			return Customer{}, err
		}
		if key == id {
			selected = c
		}
	}
	if err = rows.Err(); err != nil {
		return Customer{}, err
	}
	if err = rows.Close(); err != nil {
		return Customer{}, err
	}
	if selected.ID == "" || selected.Manager != manager || selected.Revision != revision {
		return Customer{}, ErrCustomerConflict
	}
	return selected, nil
}

func (l *CustomerAuthorityLease) checkLocked() error {
	if l.conn == nil || l.ctx == nil || l.guard == nil {
		return ErrCustomerConflict
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	c, err := readCustomerForAuthority(l.ctx, l.conn, l.customer.Manager, l.customer.ID, l.customer.Revision)
	if err != nil {
		return err
	}
	if c != l.customer {
		return ErrCustomerConflict
	}
	if err = l.guard(); err != nil {
		return err
	}
	return l.ctx.Err()
}

// Check revalidates the held revision and the caller's live session/issuer
// guard. A successful Check is not permission to release before an outer commit.
func (l *CustomerAuthorityLease) Check() error {
	if l == nil {
		return ErrCustomerConflict
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked()
}

// Customer returns a value copy after a fresh Check. Its name is presentation
// data, not device identity or enrollment authority.
func (l *CustomerAuthorityLease) Customer() (Customer, error) {
	if l == nil {
		return Customer{}, ErrCustomerConflict
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(); err != nil {
		return Customer{}, err
	}
	return l.customer, nil
}

// Release ends the read-only transaction and is safe to call more than once.
func (l *CustomerAuthorityLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	conn := l.conn
	l.conn = nil
	if conn != nil {
		defer func() {
			if p := recover(); p != nil {
				discardCustomerConn(conn)
				panic(p)
			}
		}()
		_, err := conn.ExecContext(context.Background(), "ROLLBACK")
		if err != nil {
			// A connection with an uncertain transaction must not return to
			// the pool. The enclosing operation is reconciled independently.
			discardCustomerConn(conn)
			return
		}
		_ = conn.Close()
	}
}

func discardCustomerConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}
