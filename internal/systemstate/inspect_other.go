//go:build !linux

package systemstate

func InspectExisting(string, string) error { return ErrUnsupported }
