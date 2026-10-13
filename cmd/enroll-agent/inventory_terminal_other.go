//go:build !darwin

package main

import (
	"context"
	"localrmm/internal/enrollmentclient"
)

func readInventoryApproval(context.Context, func() error) ([]byte, error) {
	return nil, enrollmentclient.ErrInput
}
