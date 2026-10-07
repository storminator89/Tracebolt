//go:build !windows

package windowsservice

import "context"

type unsupportedBackend struct{}

func nativeBackend() backend                                       { return unsupportedBackend{} }
func (unsupportedBackend) Layout() (Layout, error)                 { return Layout{}, ErrUnsupported }
func (unsupportedBackend) VerifyExecutable(Layout) (string, error) { return "", ErrUnsupported }
func (unsupportedBackend) Open(access) (service, error)            { return nil, ErrUnsupported }
func (unsupportedBackend) Create(Configuration) (service, error)   { return nil, ErrUnsupported }
func (unsupportedBackend) LookupSID() (string, error)              { return "", ErrUnsupported }
func ResolveLayout() (Layout, error)                               { return Layout{}, ErrUnsupported }
func LookupServiceSID() (string, error)                            { return "", ErrUnsupported }
func ValidateRuntimeIdentity() error                               { return ErrUnsupported }
func Run(context.Context, Worker) error                            { return ErrUnsupported }
