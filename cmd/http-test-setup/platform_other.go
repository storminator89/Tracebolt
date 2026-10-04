//go:build !linux

package main

import (
	"context"
	"os"
)

func platformSignals() []os.Signal { return []os.Signal{os.Interrupt} }

func closeParent(int)                                              {}
func openProtectedParent() (int, error)                            { return -1, errSetup }
func outputAbsent(int) error                                       { return errSetup }
func publish(context.Context, int, []materialFile, int, int) error { return errSetup }
func readPassword(context.Context) ([]byte, error)                 { return nil, errSetup }
