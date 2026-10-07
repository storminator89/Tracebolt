//go:build !linux

package actionhelper

import "context"

func newFullAdminBackend() Backend { return nil }
func InspectFullAdminService(context.Context, string) (ServiceInspection, error) {
	return ServiceInspection{}, ErrUnavailable
}
