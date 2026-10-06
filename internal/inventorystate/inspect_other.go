//go:build !linux

package inventorystate

func InspectExisting(string, string, string) error { return ErrUnsupported }
