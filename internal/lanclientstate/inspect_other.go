//go:build !linux

package lanclientstate

func InspectExisting(string, string) error { return ErrUnsupported }
