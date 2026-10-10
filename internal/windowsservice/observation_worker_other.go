//go:build !windows

package windowsservice

import "context"

func ValidateObservationWorker(context.Context) (ObservationWorkerIdentity, error) {
	return ObservationWorkerIdentity{}, ErrUnsupported
}
