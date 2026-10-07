//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func nativeOperation(context.Context, request, io.Writer, io.Writer) (any, error) {
	return nil, errors.New("native Windows lifecycle unavailable")
}
