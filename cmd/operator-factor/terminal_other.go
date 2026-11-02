//go:build !linux

package main

import (
	"context"
	"os"
)

const platformSupported = false

func terminationSignals() []os.Signal                      { return []os.Signal{os.Interrupt} }
func readTerminal(context.Context, string) ([]byte, error) { return nil, errInput }
