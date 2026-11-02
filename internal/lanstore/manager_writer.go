package lanstore

import "errors"

var ErrManagerWriterBusy = errors.New("manager state directory already has an active cooperating writer")
var ErrManagerWriterUnavailable = errors.New("manager writer exclusion is unavailable for this filesystem or kernel")

// ManagerWriterLease excludes another cooperating manager using this exact
// protected directory. It does not fence external ledgers, standalone tools,
// older binaries, privileged writers or whole-volume replacement. It is not a
// complete backup fence, freshness proof or quarantine-release authority.
type ManagerWriterLease interface {
	Check() error
	Close() error
}
