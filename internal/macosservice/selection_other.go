//go:build !darwin

package macosservice

import (
	"context"
	"io"
)

// The internal preflight is never available off a native Mac.
func RunNativeSelectionChild(context.Context, []string, io.Writer, bool) int { return 2 }
