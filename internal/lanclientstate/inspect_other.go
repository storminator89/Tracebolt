//go:build !linux && !windows && !darwin

package lanclientstate

func InspectExisting(string, string) error { return ErrUnsupported }
