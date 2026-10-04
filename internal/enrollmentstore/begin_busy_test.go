package enrollmentstore

import (
	"context"
	"errors"
	"testing"
)

type falseBusyError struct{}

func (falseBusyError) Error() string { return "SQLITE_BUSY" }
func (falseBusyError) Code() int     { return 5 }

func TestInitialBusyClassificationNeverUsesTextOrArbitraryCodes(t *testing.T) {
	for _, err := range []error{nil, errors.New("SQLITE_BUSY (5)"), falseBusyError{}, ErrStorage, context.Canceled, context.DeadlineExceeded} {
		if got := beginError(context.Background(), err); !errors.Is(got, ErrStorage) {
			t.Fatal("non-driver error was classified as retryable busy")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(beginError(ctx, falseBusyError{}), context.Canceled) {
		t.Fatal("cancellation became busy")
	}
}

func TestRealInitialBusyLeavesAuthorityUnchangedAndCanRetry(t *testing.T) {
	f, s, path := fixtureStore(t)
	ctx := context.Background()
	original, err := s.CreateInvitation(ctx, f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	other := f.open(t, path)
	connection, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer connection.ExecContext(ctx, "ROLLBACK")
	// The unchanged five-second SQLite deadline produces a real driver BUSY.
	if _, err = other.Get(ctx, original.InvitationID); !errors.Is(err, ErrBusy) {
		t.Fatal("initial SQLite contention not precisely classified", err)
	}
	if _, err = connection.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	restored, err := other.Get(ctx, original.InvitationID)
	if err != nil || restored != original {
		t.Fatal("rejected transaction changed authority or failed after release")
	}
	// Failure after BEGIN/validation is still storage failure, never assumed safe
	// for replay merely because its message resembles a transient database error.
	if err = other.transact(ctx, func(*transaction) error { return ErrStorage }); !errors.Is(err, ErrStorage) || errors.Is(err, ErrBusy) {
		t.Fatal("post-BEGIN failure classified as busy")
	}
}
