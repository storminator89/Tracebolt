//go:build !linux

package systeminventory

func newSystemProvider() (Provider, error) { return nil, SourceError{ReasonNotSupported} }
