//go:build windows

package windowsaction

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// One persistent first instance is reused. Concurrency is bounded to one, and
// all handles are non-inheritable. The only request goroutine is the isolated
// identification-token query; it never dispatches an action or network call.
// A submission response loss never triggers a retry.
func Serve(ctx context.Context, b *Broker) error { return serveReady(ctx, b, nil) }
func serveReady(ctx context.Context, b *Broker, ready chan<- struct{}) error {
	if ctx == nil || b == nil || verifyBrokerProcess(b.policy) != nil {
		return ErrBinding
	}
	sddl, e := pipeSDDL(b.policy.BrokerSID, b.policy.AgentSID)
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return ErrBinding
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd, InheritHandle: 0}
	h, e := windows.CreateNamedPipe(windows.StringToUTF16Ptr(PipeName), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, MaxMessageBytes+4, MaxMessageBytes+4, 5000, &sa)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(h)
	if ready != nil {
		close(ready)
	}
	for ctx.Err() == nil {
		_, e = overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.ConnectNamedPipe(h, o) })
		if e != nil && !errors.Is(e, windows.ERROR_PIPE_CONNECTED) {
			return e
		}
		conversationErr := func() error {
			defer windows.DisconnectNamedPipe(h)
			reqCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
			defer cancel()
			// ImpersonateNamedPipeClient identifies the last-read context. Read
			// only a size/deadline-bounded unauthenticated frame before admission;
			// no request is decoded, dispatched or persisted until proof succeeds.
			raw, e := readFrame(reqCtx, h)
			if e != nil {
				return e
			}
			peer, e := openObservationPeer(reqCtx, h, b.policy.AgentSID)
			if e != nil {
				return e
			}
			defer peer.close()
			if e = peer.check(); e != nil {
				return e
			}
			reqCtx = context.WithValue(reqCtx, peerCheckKey{}, func() error { return peer.check() })
			response := dispatch(reqCtx, b, raw)
			if peer.failedRevert {
				return errPeerRevert
			}
			if e = peer.check(); e != nil {
				return e
			}
			raw, e = json.Marshal(response)
			if e != nil {
				return e
			}
			return respondAwaitACK(reqCtx, raw, func(ctx context.Context, b []byte) error { return writeFrame(ctx, h, b) }, func(ctx context.Context) ([]byte, error) { return readFrame(ctx, h) })
		}()
		if errors.Is(conversationErr, errPeerRevert) {
			return errPeerRevert
		}
	}
	return ctx.Err()
}
func callNative(ctx context.Context, r Request) (Response, error) {
	raw, e := encodeRequest(r)
	if e != nil || ctx == nil {
		return Response{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	// IDENTIFICATION forbids the peer from using this client's token to perform
	// effects, even if another local process somehow owns the pipe name.
	value, e := connectBeforeWrite(ctx, func() (uintptr, error) {
		h, e := windows.CreateFile(windows.StringToUTF16Ptr(PipeName), pipeClientAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		return uintptr(h), e
	}, func(e error) bool { return errors.Is(e, windows.ERROR_PIPE_BUSY) }, waitContext)
	if e != nil {
		return Response{}, ErrUnavailable
	}
	h := windows.Handle(value)
	defer windows.CloseHandle(h)
	var pid uint32
	if windows.GetNamedPipeServerProcessId(h, &pid) != nil {
		return Response{}, ErrBinding
	}
	sid, e := serviceSID(BrokerName)
	if e != nil {
		return Response{}, e
	}
	peer, e := openBrokerPeer(h, pid, sid)
	if e != nil {
		return Response{}, e
	}
	defer peer.close()
	if e = peer.check(); e != nil {
		return Response{}, e
	}
	if e = writeFrame(ctx, h, raw); e != nil {
		return Response{}, ErrUnavailable
	}
	raw, e = readFrame(ctx, h)
	if e != nil || peer.check() != nil {
		return Response{}, ErrUnavailable
	}
	var out Response
	if DecodeCanonical(raw, &out, MaxMessageBytes) != nil || out.Version != IPCVersion {
		return Response{}, ErrInvalid
	}
	ack, _ := json.Marshal(consumedACK{IPCVersion, Digest(raw)})
	if e = writeFrame(ctx, h, ack); e != nil || peer.check() != nil {
		return Response{}, ErrUnavailable
	}
	return out, nil
}

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
	var header [4]byte
	if e := pipeRead(ctx, h, header[:]); e != nil {
		return nil, e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > MaxMessageBytes {
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
