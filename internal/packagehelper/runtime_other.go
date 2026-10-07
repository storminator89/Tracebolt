//go:build !linux

package packagehelper

import (
	"context"
	"io"
)

const CaptureAbortExit = 42

func Initialize(context.Context) error { return ErrUnavailable }
func RunBroker(context.Context) error  { return ErrUnavailable }
func RunRunner(string) error           { return ErrUnavailable }
func RunGuard(string, io.Reader) int   { return 1 }

type Client struct{}

func NewClient() *Client { return &Client{} }
func (*Client) Capabilities(context.Context) (Capabilities, error) {
	return Capabilities{}, ErrUnavailable
}
func (*Client) Submit(context.Context, []byte) (Snapshot, error) { return Snapshot{}, ErrUnavailable }
func (*Client) Status(context.Context, string) (Snapshot, error) { return Snapshot{}, ErrUnavailable }
