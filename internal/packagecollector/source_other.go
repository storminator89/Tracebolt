//go:build !linux

package packagecollector

import "localrmm/internal/linuxpackages"

func newSystemProvider() (sourceProvider, error) {
	return nil, sourceFailure(linuxpackages.ReasonNotSupported)
}
