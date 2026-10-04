//go:build !linux

package completeoverview

func newProvider() (Provider, error) { return nil, SourceError{ReasonNotSupported} }
