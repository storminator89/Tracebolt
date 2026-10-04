package enrollmentstore

import (
	"context"
	"errors"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrBusy means SQLite refused the initial BEGIN before this operation could
// read or mutate authority. It never represents an uncertain commit result.
var ErrBusy = errors.New("enrollment storage is temporarily busy")

func beginError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var databaseError *sqlite.Error
	if errors.As(err, &databaseError) && databaseError != nil {
		primary := databaseError.Code() & 0xff
		if primary == sqlite3.SQLITE_BUSY || primary == sqlite3.SQLITE_LOCKED {
			return ErrBusy
		}
	}
	return ErrStorage
}
