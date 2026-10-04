//go:build !linux

package inventorystate

func newStorageMode(string, bool) (storage, []byte, bool, error) {
	return nil, nil, false, ErrUnsupported
}
