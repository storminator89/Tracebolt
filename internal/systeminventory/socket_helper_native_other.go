//go:build !linux

package systeminventory

import (
	"context"
	"os"
	"time"
)

// CaptureSocketOwners is unsupported outside the separately gated Linux helper.
func CaptureSocketOwners(context.Context, string, time.Time, *os.File, func() error) ([]Socket, error) {
	return nil, SourceError{ReasonNotSupported}
}
