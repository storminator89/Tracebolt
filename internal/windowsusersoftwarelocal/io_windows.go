//go:build windows

package windowsusersoftwarelocal

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
)

// Native pipe I/O is overlapped and cancellation is drained before any buffer,
// OVERLAPPED event or handle is released. We never abandon an in-flight write.
func overlapped(ctx context.Context, h windows.Handle, start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return 0, ErrUnavailable
	}
	defer windows.CloseHandle(event)
	o := windows.Overlapped{HEvent: event}
	var n uint32
	e = start(&o, &n)
	if !errors.Is(e, windows.ERROR_IO_PENDING) {
		return n, e
	}
	for {
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, ctx.Err()
		}
		status, e := windows.WaitForSingleObject(event, 25)
		if e != nil {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, ErrUnavailable
		}
		if status == windows.WAIT_OBJECT_0 {
			e = windows.GetOverlappedResult(h, &o, &n, false)
			return n, e
		}
		if status != uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, ErrUnavailable
		}
	}
}
func pipeRead(ctx context.Context, h windows.Handle, raw []byte) error {
	for len(raw) > 0 {
		n, e := overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.ReadFile(h, raw, n, o) })
		if e != nil || n == 0 || n > uint32(len(raw)) {
			return ErrUnavailable
		}
		raw = raw[n:]
	}
	return nil
}
func readFrame(ctx context.Context, h windows.Handle) ([]byte, error) {
	return readFrameMax(ctx, h, MaxMessageBytes)
}
func readFrameMax(ctx context.Context, h windows.Handle, maximum uint32) ([]byte, error) {
	var header [4]byte
	if e := pipeRead(ctx, h, header[:]); e != nil {
		return nil, e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > maximum {
		return nil, ErrInvalid
	}
	raw := make([]byte, n)
	if e := pipeRead(ctx, h, raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func writeFrame(ctx context.Context, h windows.Handle, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return ErrInvalid
	}
	frame := make([]byte, len(raw)+4)
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	for len(frame) > 0 {
		n, e := overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.WriteFile(h, frame, n, o) })
		if e != nil || n == 0 || n > uint32(len(frame)) {
			return ErrUnavailable
		}
		frame = frame[n:]
	}
	return nil
}
