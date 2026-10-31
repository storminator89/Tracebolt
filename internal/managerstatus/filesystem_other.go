//go:build !linux

package managerstatus

import "context"

func newFilesystemProbe(string) (*FilesystemProbe, error) { return nil, ErrFilesystemProbe }
func (*FilesystemProbe) checkFilesystem(context.Context) ProbeResult {
	return ProbeResult{State: Unavailable}
}
