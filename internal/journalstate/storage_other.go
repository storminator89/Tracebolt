//go:build !linux

package journalstate

import "context"

func newStorage(context.Context, string, bool) (storage, []byte, error) {
	return nil, nil, ErrUnsupported
}
