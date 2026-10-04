//go:build !linux

package journalview

func newSystemProvider() (Provider, error) { return nil, SourceError{ReasonNotSupported} }
