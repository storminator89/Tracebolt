//go:build !linux

package cachedupdates

func newNativeSource() (nativeSource, error) { return nil, sourceFailure(ReasonNotSupported) }
