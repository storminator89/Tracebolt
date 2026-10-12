//go:build !windows

package windowspackage

import (
	"context"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowssoftwarejob"
)

func stagePreparedMSINative(context.Context, windowsservice.Receipt, []byte, job.Selection) (PreparedMSIReceipt, error) {
	return PreparedMSIReceipt{}, ErrUnsupported
}
func openPreparedMSINative(context.Context, PreparedMSIReceipt) (preparedMSIPin, error) {
	return nil, ErrUnsupported
}
func checkPreparedMSIAbsentNative(context.Context, windowsservice.Receipt) error {
	return ErrUnsupported
}
