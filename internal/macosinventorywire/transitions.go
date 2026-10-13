package macosinventorywire

import (
	"bytes"
	"time"
)

// Disable binds the exact locally durable reservation floor into a terminal
// decision. It performs no write, cancellation, drain, erasure or acknowledgement.
func Disable(active Control, reservedFloor uint64, changedAt time.Time) (Control, error) {
	if ValidateControl(active) != nil || reservedFloor > MaxSequence || !validTime(changedAt) || changedAt.Before(active.ChangedAt) {
		return Control{}, ErrInvalid
	}
	if !active.Enabled {
		return Control{}, ErrDisabled
	}
	next := active
	next.Enabled = false
	next.ControlRevision = 2
	next.CaptureFloor = reservedFloor
	next.ChangedAt = changedAt
	return next, nil
}

// ValidateControlTransition checks an already-known control and known durable
// reservation/acceptance floor. A receiver may know a lower floor than the
// sender, but never a higher one. Exact retries are idempotent, including disable.
// After disable all reports and non-identical controls conflict permanently.
// Missing previous used state is NOT represented by a zero/fresh control here.
func ValidateControlTransition(previousRaw, nextRaw []byte, knownFloor uint64) (retry bool, err error) {
	previous, err := DecodeControl(previousRaw)
	if err != nil {
		return false, err
	}
	next, err := DecodeControl(nextRaw)
	if err != nil {
		return false, err
	}
	if knownFloor > MaxSequence {
		return false, ErrInvalid
	}
	if previous.Binding != next.Binding || previous.GrantID != next.GrantID || previous.GrantRevision != next.GrantRevision {
		return false, ErrConflict
	}
	if bytes.Equal(previousRaw, nextRaw) {
		if !next.Enabled && next.CaptureFloor < knownFloor {
			return false, ErrConflict
		}
		return true, nil
	}
	if !previous.Enabled {
		return false, ErrDisabled
	}
	if next.Enabled || next.ControlRevision != previous.ControlRevision+1 || next.CaptureFloor < knownFloor || next.ChangedAt.Before(previous.ChangedAt) {
		return false, ErrConflict
	}
	return false, nil
}

// ValidateReportTransition compares two canonical captures in the same active
// grant. Skipped sequences are allowed for reserved-but-lost/failed attempts;
// equal sequences require exact bytes and advancing captures need >= one minute.
// This is not a durable replay ledger: external used/floor checks must also reject
// sequences consumed after previousRaw, including attempts with no report.
func ValidateReportTransition(previousRaw, nextRaw []byte, active Control) (retry bool, err error) {
	previous, err := DecodeReport(previousRaw)
	if err != nil {
		return false, err
	}
	next, err := DecodeReport(nextRaw)
	if err != nil {
		return false, err
	}
	if err := ValidateReportBinding(previous, active); err != nil {
		return false, err
	}
	if err := ValidateReportBinding(next, active); err != nil {
		return false, err
	}
	if next.CaptureSequence < previous.CaptureSequence {
		return false, ErrConflict
	}
	if next.CaptureSequence == previous.CaptureSequence {
		if !bytes.Equal(previousRaw, nextRaw) {
			return false, ErrConflict
		}
		return true, nil
	}
	if next.CollectedAt.Before(previous.CollectedAt.Add(CaptureInterval)) {
		return false, ErrConflict
	}
	return false, nil
}
