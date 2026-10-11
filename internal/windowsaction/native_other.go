//go:build !windows

package windowsaction

import "context"

func AuthorityPath() (string, error)    { return "", ErrUnavailable }
func serviceSID(string) (string, error) { return "", ErrUnavailable }
func ReviewExistingSetup(Policy) error  { return ErrUnavailable }
func verifyBrokerProcess(Policy) error  { return ErrUnavailable }
func nativeBackend() Backend            { return unsupportedBackend{} }

type unsupportedBackend struct{}

func (unsupportedBackend) Open(Target, string, string) (Service, error) { return nil, ErrUnavailable }
func Serve(context.Context, *Broker) error                              { return ErrUnavailable }
func callNative(context.Context, Request) (Response, error)             { return Response{}, ErrUnavailable }
func RunService() error                                                 { return ErrUnavailable }
