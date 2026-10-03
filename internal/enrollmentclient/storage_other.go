//go:build !linux

package enrollmentclient

// Native enrollment requires the Linux descriptor, owner, and locking policy.
// Other platforms must not emulate it with weaker pathname-based operations.
type localStore struct{ storeRedaction }

func openStore(string) (*localStore, error)        { return nil, ErrState }
func (*localStore) Read(string) ([]byte, error)    { return nil, ErrState }
func (*localStore) Write(string, []byte) error     { return ErrState }
func (*localStore) TelemetryExists() (bool, error) { return false, ErrState }
func (*localStore) EnsureTelemetry() error         { return ErrState }
func (*localStore) Close() error                   { return nil }
