//go:build !linux && !windows

package lanclientstate

func InspectExisting(string, string) error { return ErrUnsupported }
