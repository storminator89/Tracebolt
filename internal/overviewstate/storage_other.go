//go:build !linux

package overviewstate

func newStorageMode(string, bool) (storage, []byte, bool, error) {
	return nil, nil, false, ErrUnsupported
}
