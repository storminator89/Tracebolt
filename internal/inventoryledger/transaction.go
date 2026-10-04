package inventoryledger

import (
	"context"
	"database/sql"
	"errors"
)

var (
	ErrInvalid       = errors.New("inventory_ledger_invalid")
	ErrConflict      = errors.New("inventory_ledger_conflict")
	ErrQuota         = errors.New("inventory_ledger_quota")
	ErrStorage       = errors.New("inventory_ledger_storage")
	ErrIncomplete    = errors.New("inventory_ledger_incomplete")
	ErrNotFound      = errors.New("inventory_ledger_not_found")
	ErrExpired       = errors.New("inventory_ledger_expired")
	ErrCursor        = errors.New("inventory_ledger_cursor_invalid")
	ErrCursorExpired = errors.New("inventory_ledger_cursor_expired")
)

// Transaction is the SQL seam implemented by *sql.Conn and *sql.Tx. It MUST
// represent the already-open, caller-owned authority BEGIN IMMEDIATE transaction.
// Passing a pool or an autocommit connection violates the security contract.
// This interface is deliberately insufficient to commit or open a database.
type Transaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// AuthorityTransaction must perform authority validation, action, authority-state
// persistence and COMMIT atomically, returning nil ONLY after successful COMMIT.
// It must roll back on action failure. It must not cache authorization decisions.
type AuthorityTransaction func(context.Context, func(Transaction) error) error

// CommitResult suppresses every provisional result if the action, authority
// checks, persistence or COMMIT fails. The authority owner supplies the runner;
// this function cannot authenticate callers or prove a runner honors its contract.
func CommitResult[T any](ctx context.Context, run AuthorityTransaction, action func(Transaction) (T, error)) (T, error) {
	var zero T
	if ctx == nil || run == nil || action == nil {
		return zero, ErrInvalid
	}
	var out T
	err := run(ctx, func(tx Transaction) error {
		var err error
		out, err = action(tx)
		return err
	})
	if err != nil {
		return zero, err
	}
	return out, nil
}
