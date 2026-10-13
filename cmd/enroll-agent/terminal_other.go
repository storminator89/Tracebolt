//go:build !linux && !darwin

package main

import (
	"context"
	"localrmm/internal/enrollmentclient"
)

func readInvitation(context.Context, func() error) ([]byte, error) {
	return nil, enrollmentclient.ErrInput
}
