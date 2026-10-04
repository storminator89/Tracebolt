//go:build !linux

package systemstate

func newStorage(string) (storage, []byte, bool, error) {
	return nil, nil, false, ErrUnsupported
}

func newStorageMode(string, bool) (storage, []byte, bool, error) {
	return nil, nil, false, ErrUnsupported
}
