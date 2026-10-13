//go:build !darwin

package macosservice

import "context"

type nativeBackend struct{}

func NewNativeBackend() Backend { return nativeBackend{} }
func (nativeBackend) Inspect(context.Context, Request) ([]Check, error) {
	return []Check{{Code: "platform", Detail: "Local preflight requires a supported native macOS amd64 or arm64 process. Use --render-only only for an unchecked candidate."}}, ErrPreflight
}
