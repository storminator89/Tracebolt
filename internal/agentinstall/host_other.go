//go:build !linux

package agentinstall

import "context"

type LinuxBackend struct{}

func NewLinuxBackend() *LinuxBackend { return &LinuxBackend{} }
func (*LinuxBackend) Inspect(context.Context, Request) (HostFacts, error) {
	return HostFacts{}, ErrPreflight
}
func (*LinuxBackend) Begin(context.Context, Request, Plan) (Transaction, error) {
	return nil, ErrPreflight
}
