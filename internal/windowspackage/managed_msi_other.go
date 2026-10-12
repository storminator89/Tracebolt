//go:build !windows

package windowspackage

import (
	"context"
	managed "localrmm/internal/windowsmanagedmsi"
)

func openManagedMSINative(context.Context, ManagedMSIReceipt) (managedMSIPin, error) {
	return nil, managed.ErrUnavailable
}
func NewManagedMSIPayload() managed.Payload          { return nil }
func CheckManagedMSIExclusive(context.Context) error { return managed.ErrUnavailable }
func CheckManagedMSIAbsent(context.Context) error    { return managed.ErrUnavailable }

func CheckCoordinatedMutationExclusive(context.Context) error { return managed.ErrUnavailable }

func CheckManagedMSIParticipantAbsent(context.Context) error { return managed.ErrUnavailable }

func CheckBackgroundMutationExclusive(context.Context) error { return managed.ErrUnavailable }
func CheckBackgroundUpdateFresh(context.Context) error       { return managed.ErrUnavailable }
