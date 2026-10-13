package enrollmentclient

import (
	"bytes"
	"context"
	"io"
	sender "localrmm/internal/macosinventorysender"
	state "localrmm/internal/macosinventorystate"
	"time"
)

// ValidateMacOSInventoryServicePreflight checks a live local credential and the
// original existing sender state while holding the enrollment lock. Unlike the
// retained-state handoff validator, expired or locally revoked authority fails.
// It never renews, contacts a manager, restores state, collects, or initializes
// anything. Remote revocation is still checked by the actual reporting path.
func ValidateMacOSInventoryServicePreflight(ctx context.Context, path string) error {
	return validateMacOSInventoryServicePreflight(ctx, path, macOSInventoryPreflightDependencies{
		openEnrollment: openMacOSInventoryEnrollment,
		openStorage: func(path string, enable []byte) (io.Closer, []byte, error) {
			return sender.OpenExistingStorage(path, enable)
		},
		now: time.Now,
	})
}

type macOSInventoryPreflightDependencies struct {
	openEnrollment func(string) (*session, error)
	openStorage    func(string, []byte) (io.Closer, []byte, error)
	now            func() time.Time
}

func validateMacOSInventoryServicePreflight(ctx context.Context, path string, d macOSInventoryPreflightDependencies) (result error) {
	if ctx == nil || d.openEnrollment == nil || d.openStorage == nil || d.now == nil {
		return ErrState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s, e := d.openEnrollment(path)
	if e != nil {
		return e
	}
	defer func() {
		if e := closeMacOSInventoryEnrollment(s); e != nil {
			result = ErrState
		} else if result == nil && ctx.Err() != nil {
			result = ctx.Err()
		}
	}()
	active := &macOSInventoryActive{s: s, ctx: ctx}
	evidence, e := active.Check(d.now().UTC())
	if e != nil {
		return e
	}
	active.leaf = bytes.Clone(evidence.CurrentDER)
	c, _, enable, e := s.macOSInventoryOriginal()
	if e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	storage, raw, e := d.openStorage(c.StateDirectory, enable)
	if e != nil {
		return e
	}
	valid := state.ValidateCheckpoint(raw, enable) == nil
	closeErr := storage.Close()
	if !valid || closeErr != nil {
		return ErrState
	}
	// Storage validation cannot substitute for a final check of the original
	// artifacts, same current leaf, local revocation/clock floors and cancellation.
	if _, e = active.Check(d.now().UTC()); e != nil {
		return e
	}
	return ctx.Err()
}
