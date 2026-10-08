//go:build !windows

package windowsnetwork

func queryNative(tableSpec, []byte) (uint32, error) { return 0, ErrUnsupported }
