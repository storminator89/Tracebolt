//go:build !linux

package lanclientstate

func newStorage(string) (storage, []byte, bool, error) {
	return nil, nil, false, ErrUnsupported
}
